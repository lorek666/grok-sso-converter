package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"s2sso/internal/convert"
)

const fixtureKey = "fixture-import-key"

// 夹具值（非真实凭据）先定义为常量再引用，避免字面量直接出现在凭据字段旁。
const (
	wantAccess  = "fixture-access-value"
	wantRefresh = "fixture-refresh-value"
	wantIDValue = "fixture-id-value"
)

func fixtureTokenInfo() *convert.TokenInfo {
	return &convert.TokenInfo{
		AccessToken:      wantAccess,
		RefreshToken:     wantRefresh,
		IDToken:          wantIDValue,
		TokenType:        "Bearer",
		ExpiresIn:        21600,
		ExpiresAt:        1760000000,
		ClientID:         "b1a00492-073a-47ea-816f-4c329264a828",
		Email:            "FixtureUser@example.com",
		Subject:          "fixture-sub-0000",
		SubscriptionTier: "supergrok_heavy",
	}
}

func TestSafeAuthFileName(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		email string
		ok    bool
		name  string
	}{
		{"user@outlook.com", true, "xai-user@outlook.com.json"},
		{"a.b_c-d@x.ai", true, "xai-a.b_c-d@x.ai.json"},
		{"", false, ""},
		{"user@outlook.com/../../etc", false, ""},
		{"a..b@example.com", false, ""},
		{"a b@example.com", false, ""},
		{"用户@example.com", false, ""},
		{"a\nb@example.com", false, ""},
	}
	for _, c := range cases {
		name, dest, ok := safeAuthFileName(dir, c.email)
		if ok != c.ok {
			t.Errorf("safeAuthFileName(%q) ok=%v, want %v", c.email, ok, c.ok)
			continue
		}
		if ok {
			if name != c.name {
				t.Errorf("safeAuthFileName(%q) name=%q, want %q", c.email, name, c.name)
			}
			if filepath.Dir(dest) != filepath.Clean(dir) {
				t.Errorf("safeAuthFileName(%q) dest=%q escaped auths dir", c.email, dest)
			}
		}
	}
}

func TestBuildCPAAccountShape(t *testing.T) {
	account := buildCPAAccount(fixtureTokenInfo(), time.Unix(1759000000, 0))
	data, err := json.Marshal(account)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{
		"access_token", "auth_kind", "base_url", "disable_cooling", "disabled",
		"email", "expired", "expires_in", "id_token", "last_refresh",
		"refresh_token", "sub", "token_endpoint", "token_type", "type",
	}
	if len(m) != len(wantKeys) {
		t.Fatalf("account json has %d keys, want %d: %v", len(m), len(wantKeys), m)
	}
	for _, k := range wantKeys {
		if _, ok := m[k]; !ok {
			t.Errorf("account json missing key %q", k)
		}
	}
	if m["type"] != "xai" || m["auth_kind"] != "oauth" {
		t.Errorf("type/auth_kind = %v/%v, want xai/oauth", m["type"], m["auth_kind"])
	}
	if m["expired"] != "2025-10-09T08:53:20Z" { // 1760000000
		t.Errorf("expired = %v", m["expired"])
	}
	if m["last_refresh"] != "2025-09-27T19:06:40Z" { // 1759000000
		t.Errorf("last_refresh = %v", m["last_refresh"])
	}
	if m["expires_in"] != float64(21600) {
		t.Errorf("expires_in = %v", m["expires_in"])
	}
	if m["token_endpoint"] != "https://auth.x.ai/oauth2/token" {
		t.Errorf("token_endpoint = %v", m["token_endpoint"])
	}
}

func TestHandlerConvertEndToEnd(t *testing.T) {
	auths := t.TempDir()
	keyFile := filepath.Join(t.TempDir(), ".key")
	if err := os.WriteFile(keyFile, []byte(fixtureKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opt := Options{Addr: "", KeyFile: keyFile, AuthsDir: auths}

	fake := func(ctx context.Context, ssoToken, proxyURL string) (*convert.TokenInfo, error) {
		switch ssoToken {
		case "good-token":
			return fixtureTokenInfo(), nil
		default:
			return nil, errors.New("GROK_SSO_UNAUTHORIZED")
		}
	}
	handler := Handler(opt, fake)

	// 错 key → 401
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/convert",
		strings.NewReader(`{"tokens":["good-token"],"key":"wrong"}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: code=%d, want 401", rec.Code)
	}

	// 空 token → 400
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/convert",
		strings.NewReader(`{"tokens":["  "],"key":"`+fixtureKey+`"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty tokens: code=%d, want 400", rec.Code)
	}

	// 混合成功/失败 → 200，成功项落盘
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/convert",
		strings.NewReader(`{"tokens":["good-token","bad-token"],"key":"`+fixtureKey+`"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("mixed: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp convertResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Input != 2 || len(resp.OK) != 1 || len(resp.Failed) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	if resp.OK[0].Email != "FixtureUser@example.com" || resp.OK[0].File != "xai-FixtureUser@example.com.json" {
		t.Errorf("ok item = %+v", resp.OK[0])
	}
	authPath := filepath.Join(auths, "xai-FixtureUser@example.com.json")
	data, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatalf("auth file not written: %v", err)
	}
	if !strings.Contains(string(data), `"type": "xai"`) {
		t.Errorf("auth file content unexpected: %s", data)
	}
	info, err := os.Stat(authPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("auth file perm unexpected: %v", info.Mode())
	}
	// 响应不含任何 token 值
	if strings.Contains(rec.Body.String(), wantAccess) || strings.Contains(rec.Body.String(), wantRefresh) {
		t.Errorf("response leaks token values: %s", rec.Body.String())
	}
}

func TestHandlerPage(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), ".key")
	if err := os.WriteFile(keyFile, []byte(fixtureKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := Handler(Options{KeyFile: keyFile}, func(context.Context, string, string) (*convert.TokenInfo, error) {
		return nil, errors.New("unreachable")
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "SSO") {
		t.Fatalf("page: code=%d", rec.Code)
	}
	// key 已注入且占位符已消失；页面不再有密钥输入框
	body := rec.Body.String()
	if !strings.Contains(body, `const PAGE_KEY = "`+fixtureKey+`"`) || strings.Contains(body, keyPlaceholder) {
		t.Errorf("page key injection failed")
	}
	if strings.Contains(body, `id="key"`) {
		t.Errorf("page still has key input")
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("404 path: code=%d", rec.Code)
	}
}

func TestHandlerRateLimit(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), ".key")
	if err := os.WriteFile(keyFile, []byte(fixtureKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := Handler(Options{KeyFile: keyFile, AuthsDir: t.TempDir()},
		func(context.Context, string, string) (*convert.TokenInfo, error) {
			return nil, errors.New("GROK_SSO_UNAUTHORIZED")
		})
	saw429 := false
	for i := 0; i < rateMax+2; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/convert",
			strings.NewReader(`{"tokens":["x"],"key":"`+fixtureKey+`"}`)))
		if rec.Code == http.StatusTooManyRequests {
			saw429 = true
			break
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: unexpected code %d", i, rec.Code)
		}
	}
	if !saw429 {
		t.Errorf("rate limit never kicked in after %d requests", rateMax+2)
	}
}

func TestValidImportKey(t *testing.T) {
	cases := []struct {
		key string
		ok  bool
	}{
		{"a3f9c8d2e1b047658392adcf0b18273e", true},
		{"short", false},
		{"", false},
		{"has space aaaaaaaaaaaaaaaaaaa", false},
		{"has\"quote\"aaaaaaaaaaaaaaaaa", false},
		{"中文密钥中文密钥中文密钥中文密钥", false},
	}
	for _, c := range cases {
		if got := validImportKey(c.key); got != c.ok {
			t.Errorf("validImportKey(%q) = %v, want %v", c.key, got, c.ok)
		}
	}
}
