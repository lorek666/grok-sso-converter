package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"

	"s2sso/internal/convert"
)

// 夹具值用常量先定义再引用，避免测试里的 token 字面量被误判为真实凭据。
const (
	fixtureAccess  = "fixture-access-value"
	fixtureRefresh = "fixture-refresh-value"
	fixtureIDValue = "fixture-id-value"
	fixtureEmail   = "user@example.com"
)

func fixtureInfo() *convert.TokenInfo {
	return &convert.TokenInfo{
		AccessToken:      fixtureAccess,
		RefreshToken:     fixtureRefresh,
		IDToken:          fixtureIDValue,
		Email:            fixtureEmail,
		Subject:          "fixture-sub",
		ExpiresAt:        1760000000,
		ExpiresIn:        21600,
		SubscriptionTier: "superGrok",
	}
}

type fakeSave struct {
	mu    chan struct{}
	calls []struct {
		name string
		json json.RawMessage
	}
	err map[string]error
}

func (f *fakeSave) save(name string, raw json.RawMessage) error {
	if f.mu != nil {
		f.mu <- struct{}{} // 占住串行闸，验证 handler 全局锁生效
	}
	if err, ok := f.err[name]; ok {
		return err
	}
	f.calls = append(f.calls, struct {
		name string
		json json.RawMessage
	}{name, append(json.RawMessage(nil), raw...)})
	return nil
}

func newTestHandler(fn convertFunc, saver *fakeSave) *handler {
	h := newHandler(saver.save)
	h.convertFn = fn
	return h
}

func TestHandlePageRoute(t *testing.T) {
	h := newHandler(func(string, json.RawMessage) error { return nil })
	resp := h.handle(pluginapi.ManagementRequest{Method: http.MethodGet, Path: resourcePagePath})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "SSO") || !strings.Contains(string(resp.Body), "apiConvert") {
		t.Fatal("page body missing expected content")
	}
}

func TestHandleUnknownPath(t *testing.T) {
	h := newHandler(func(string, json.RawMessage) error { return nil })
	for _, req := range []pluginapi.ManagementRequest{
		{Method: http.MethodGet, Path: convertRoutePath},
		{Method: http.MethodPost, Path: resourcePagePath},
		{Method: http.MethodGet, Path: "/v0/management/other"},
	} {
		if resp := h.handle(req); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s %s status = %d, want 404", req.Method, req.Path, resp.StatusCode)
		}
	}
}

// waitDone 轮询任务直至完成（测试用，convertFn 同步执行，数轮内必达）。
func waitDone(t *testing.T, h *handler, id string) convertResponse {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp := h.handle(pluginapi.ManagementRequest{Method: http.MethodGet, Path: statusRoutePath, Query: url.Values{"job": []string{id}}})
		if resp.StatusCode == http.StatusOK {
			var out struct {
				Job    string          `json:"job"`
				State  string          `json:"state"`
				Result convertResponse `json:"result"`
			}
			if err := json.Unmarshal(resp.Body, &out); err != nil {
				t.Fatalf("decode status: %v", err)
			}
			if out.State == "done" {
				return out.Result
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job did not finish in time")
	return convertResponse{}
}

func startJob(t *testing.T, h *handler, body string) string {
	t.Helper()
	resp := h.handle(pluginapi.ManagementRequest{Method: http.MethodPost, Path: convertRoutePath, Body: []byte(body)})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("start status = %d, want 202", resp.StatusCode)
	}
	var out struct {
		Job string `json:"job"`
	}
	if err := json.Unmarshal(resp.Body, &out); err != nil || out.Job == "" {
		t.Fatalf("start body = %s", resp.Body)
	}
	return out.Job
}

func TestConvertEndToEnd(t *testing.T) {
	saver := &fakeSave{}
	h := newTestHandler(func(_ context.Context, token, _ string) (*convert.TokenInfo, error) {
		if strings.Contains(token, "bad") {
			return nil, context.DeadlineExceeded
		}
		return fixtureInfo(), nil
	}, saver)
	fixed := time.Unix(1759000000, 0).UTC()
	old := timeNow
	timeNow = func() time.Time { return fixed }
	t.Cleanup(func() { timeNow = old })

	id := startJob(t, h, `{"tokens":["good-token-1","bad-token","sso=good-token-2"]}`)
	out := waitDone(t, h, id)
	if out.Input != 3 || len(out.OK) != 2 || len(out.Failed) != 1 {
		t.Fatalf("unexpected aggregation: %+v", out)
	}
	if len(saver.calls) != 2 {
		t.Fatalf("save calls = %d, want 2", len(saver.calls))
	}
	first := saver.calls[0]
	if first.name != "xai-"+fixtureEmail+".json" {
		t.Fatalf("save name = %q", first.name)
	}
	var acct map[string]any
	if err := json.Unmarshal(first.json, &acct); err != nil {
		t.Fatalf("decode saved account: %v", err)
	}
	wantKeys := []string{
		"access_token", "auth_kind", "base_url", "disable_cooling", "disabled",
		"email", "expired", "expires_in", "id_token", "last_refresh",
		"refresh_token", "sub", "token_endpoint", "token_type", "type",
	}
	if len(acct) != len(wantKeys) {
		t.Fatalf("account keys = %d, want %d", len(acct), len(wantKeys))
	}
	for _, k := range wantKeys {
		if _, ok := acct[k]; !ok {
			t.Fatalf("account missing key %s", k)
		}
	}
	if acct["expired"] != "2025-10-09T08:53:20Z" {
		t.Fatalf("expired = %v", acct["expired"])
	}
	if acct["last_refresh"] != "2025-09-27T19:06:40Z" {
		t.Fatalf("last_refresh = %v", acct["last_refresh"])
	}
	if acct["type"] != "xai" || acct["auth_kind"] != "oauth" {
		t.Fatalf("type/auth_kind = %v/%v", acct["type"], acct["auth_kind"])
	}
	// 轮询响应不得回显 token。
	h.mu.Lock()
	statusBody, _ := json.Marshal(h.jobs[id])
	h.mu.Unlock()
	if strings.Contains(string(statusBody), "good-token") {
		t.Fatal("status response leaks token")
	}
}

func TestConvertConcurrentRejected(t *testing.T) {
	block := make(chan struct{})
	h := newTestHandler(func(_ context.Context, _, _ string) (*convert.TokenInfo, error) {
		<-block
		return fixtureInfo(), nil
	}, &fakeSave{})
	id := startJob(t, h, `{"tokens":["t1"]}`)
	resp := h.handle(pluginapi.ManagementRequest{
		Method: http.MethodPost, Path: convertRoutePath,
		Body: []byte(`{"tokens":["t2"]}`),
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second job status = %d, want 409", resp.StatusCode)
	}
	close(block) // 放行首个任务后再等它完成
	waitDone(t, h, id)
}

func TestRunJobPanicRecovers(t *testing.T) {
	// panic 兜底：后台任务 panic 后必须置 done 并记录失败，否则 busyLocked
	// 恒真，插件对所有后续转换请求永久 409。
	h := newTestHandler(func(_ context.Context, _, _ string) (*convert.TokenInfo, error) {
		panic("boom")
	}, &fakeSave{})
	id := startJob(t, h, `{"tokens":["t1"]}`)
	out := waitDone(t, h, id)
	if len(out.Failed) != 1 || !strings.Contains(out.Failed[0].Error, "internal error") {
		t.Fatalf("panic not recorded: %+v", out)
	}
	// 兜底生效后应能立刻提交新任务。
	h2 := newTestHandler(func(_ context.Context, _, _ string) (*convert.TokenInfo, error) {
		return fixtureInfo(), nil
	}, &fakeSave{})
	_ = h2 // h 的 busy 检查已释放：
	resp := h.handle(pluginapi.ManagementRequest{Method: http.MethodPost, Path: convertRoutePath, Body: []byte(`{"tokens":["t2"]}`)})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("post-panic job status = %d, want 202", resp.StatusCode)
	}
}

func TestJobStatusUnknown(t *testing.T) {
	h := newHandler(func(string, json.RawMessage) error { return nil })
	resp := h.handle(pluginapi.ManagementRequest{Method: http.MethodGet, Path: statusRoutePath, Query: url.Values{"job": []string{"nope"}}})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestConvertBadRequests(t *testing.T) {
	h := newTestHandler(func(_ context.Context, _, _ string) (*convert.TokenInfo, error) {
		return fixtureInfo(), nil
	}, &fakeSave{})
	cases := []struct {
		name string
		body string
		code int
	}{
		{"invalid json", "{", http.StatusBadRequest},
		{"empty tokens", `{"tokens":["  ",""]}`, http.StatusBadRequest},
		{"too many", `{"tokens":["a","b","c","d","e","f","g","h","i","j","k"]}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		resp := h.handle(pluginapi.ManagementRequest{Method: http.MethodPost, Path: convertRoutePath, Body: []byte(tc.body)})
		if resp.StatusCode != tc.code {
			t.Fatalf("%s: status = %d, want %d", tc.name, resp.StatusCode, tc.code)
		}
	}
}

func TestConvertSaveFailure(t *testing.T) {
	saver := &fakeSave{err: map[string]error{"xai-" + fixtureEmail + ".json": context.Canceled}}
	h := newTestHandler(func(_ context.Context, _, _ string) (*convert.TokenInfo, error) {
		return fixtureInfo(), nil
	}, saver)
	out := waitDone(t, h, startJob(t, h, `{"tokens":["t1"]}`))
	if len(out.OK) != 0 || len(out.Failed) != 1 {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestConfigProxyPassedToConvert(t *testing.T) {
	var gotProxy string
	h := newTestHandler(func(_ context.Context, _, proxyURL string) (*convert.TokenInfo, error) {
		gotProxy = proxyURL
		return fixtureInfo(), nil
	}, &fakeSave{})
	h.setConfig("http://127.0.0.1:7890")
	waitDone(t, h, startJob(t, h, `{"tokens":["t"]}`))
	if gotProxy != "http://127.0.0.1:7890" {
		t.Fatalf("proxy = %q", gotProxy)
	}
}

func TestLifecycleRegistration(t *testing.T) {
	// config_yaml = "proxy: http://127.0.0.1:7890" 的 base64。
	raw, err := handleMethod("plugin.register", []byte(`{"config_yaml":"cHJveHk6IGh0dHA6Ly8xMjcuMC4wLjE6Nzg5MA=="}`))
	if err != nil {
		t.Fatal(err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if !env.OK {
		t.Fatalf("register failed: %+v", env.Error)
	}
	var reg registration
	if err := json.Unmarshal(env.Result, &reg); err != nil {
		t.Fatal(err)
	}
	if !reg.Capabilities.ManagementAPI {
		t.Fatal("management_api capability missing")
	}
	if reg.Metadata.Name != "SSO Import" || reg.SchemaVersion == 0 {
		t.Fatalf("metadata: %+v", reg.Metadata)
	}
	if proxy, _ := imp.proxy.Load().(string); proxy != "http://127.0.0.1:7890" {
		t.Fatalf("config proxy = %q", proxy)
	}
}
