package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"

	"s2sso/internal/convert"
	"s2sso/internal/cpaformat"
)

//go:embed page.html
var pageHTML []byte

// timeNow 便于测试注入固定时间。
var timeNow = time.Now

const (
	maxTokens   = 10
	maxBodyByte = 1 << 20
)

// saveFunc 把凭证 JSON 交给宿主落盘（生产实现走 host.auth.save 回调；测试
// 注入假实现）。
type saveFunc func(name string, raw json.RawMessage) error

// convertFunc 与 web 工具一致，可注入便于测试。
type convertFunc func(ctx context.Context, ssoToken, proxyURL string) (*convert.TokenInfo, error)

// handler 持有插件运行态。转换全局串行（指纹客户端并发易触发 CF 边缘质
// 询）；转换最坏数分钟/账号，超过常见网关 read timeout，因此 POST 立即
// 返回任务号，结果由 status 轮询，长任务不挂在单次 HTTP 连接上。管理路
// 由本身已有管理密钥鉴权，无需再叠加限速。
type handler struct {
	proxy     atomic.Value // string；register/reconfigure 写入
	convertFn convertFunc
	saveFn    saveFunc
	mu        sync.Mutex // 串行执行转换任务并保护 jobs 表
	jobs      map[string]*job
	jobOrder  []string // 按创建序淘汰
}

// job 是一次批量转换的后台任务。
type job struct {
	id      string
	state   string // "running" | "done"
	resp    convertResponse
	created time.Time
	doneAt  time.Time // 完成时间；淘汰按它起算（created 起算会被最坏 1h 的任务自身顶穿）
}

const (
	jobMaxKept    = 32
	jobMaxAge     = time.Hour
	convertBudget = 6 * time.Minute // 单 token 转换预算（含重试）
)

func newHandler(save saveFunc) *handler {
	h := &handler{saveFn: save, convertFn: convert.Convert, jobs: map[string]*job{}}
	h.proxy.Store("")
	return h
}

func (h *handler) setConfig(proxy string) { h.proxy.Store(proxy) }

func (h *handler) handle(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	switch {
	case req.Method == http.MethodGet && req.Path == resourcePagePath:
		return pluginapi.ManagementResponse{
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
			Body:       pageHTML,
		}
	case req.Method == http.MethodPost && req.Path == convertRoutePath:
		return h.startConvert(req)
	case req.Method == http.MethodGet && req.Path == statusRoutePath:
		return h.jobStatus(req)
	default:
		return pluginapi.ManagementResponse{
			StatusCode: http.StatusNotFound,
			Headers:    http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
			Body:       []byte(`{"error":"not found"}`),
		}
	}
}

type okItem struct {
	Email   string `json:"email"`
	Tier    string `json:"tier"`
	Expired string `json:"expired"`
	File    string `json:"file"`
}

type failItem struct {
	Email string `json:"email,omitempty"`
	Error string `json:"error"`
}

type convertResponse struct {
	Input  int        `json:"input"`
	OK     []okItem   `json:"ok"`
	Failed []failItem `json:"failed"`
}

// startConvert 校验请求后立即返回任务号；转换在后台串行执行。
func (h *handler) startConvert(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	bad := func(code int, msg string) pluginapi.ManagementResponse {
		return pluginapi.ManagementResponse{
			StatusCode: code,
			Headers:    http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
			Body:       []byte(`{"error":` + mustJSON(msg) + `}`),
		}
	}
	if len(req.Body) > maxBodyByte {
		return bad(http.StatusRequestEntityTooLarge, "request body too large")
	}
	var input struct {
		Tokens []string `json:"tokens"`
	}
	if err := json.Unmarshal(req.Body, &input); err != nil {
		return bad(http.StatusBadRequest, "invalid request body")
	}
	var tokens []string
	for _, t := range input.Tokens {
		if t = strings.TrimSpace(t); t != "" {
			tokens = append(tokens, t)
		}
	}
	if len(tokens) == 0 {
		return bad(http.StatusBadRequest, "no tokens")
	}
	if len(tokens) > maxTokens {
		return bad(http.StatusBadRequest, fmt.Sprintf("too many tokens (max %d)", maxTokens))
	}

	h.mu.Lock()
	if h.busyLocked() {
		h.mu.Unlock()
		return bad(http.StatusConflict, "a conversion job is already running, retry shortly")
	}
	id := newJobID()
	j := &job{id: id, state: "running", created: timeNow()}
	h.jobs[id] = j
	h.jobOrder = append(h.jobOrder, id)
	h.evictLocked()
	convertFn, saveFn := h.convertFn, h.saveFn
	proxy, _ := h.proxy.Load().(string)
	h.mu.Unlock()

	go h.runJob(j, tokens, proxy, convertFn, saveFn)

	body, _ := json.Marshal(map[string]string{"job": id})
	return pluginapi.ManagementResponse{
		StatusCode: http.StatusAccepted,
		Headers:    http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Body:       body,
	}
}

// busyLocked 报告是否已有任务在跑（调用方需持锁）。
func (h *handler) busyLocked() bool {
	for _, id := range h.jobOrder {
		if h.jobs[id] != nil && h.jobs[id].state == "running" {
			return true
		}
	}
	return false
}

// evictLocked 淘汰过期与超额的已完成任务（调用方需持锁）。过期按 doneAt
// 起算：最坏任务时长（10×convertBudget）可达 1h，若按 created 起算会被
// 自身顶穿，导致刚完成的任务被立刻淘汰、轮询方拿到 404。
func (h *handler) evictLocked() {
	now := timeNow()
	for len(h.jobOrder) > 0 {
		id := h.jobOrder[0]
		j := h.jobs[id]
		if j == nil {
			h.jobOrder = h.jobOrder[1:]
			continue
		}
		if j.state == "running" {
			break
		}
		expired := !j.doneAt.IsZero() && now.Sub(j.doneAt) > jobMaxAge
		if expired || len(h.jobOrder) > jobMaxKept {
			delete(h.jobs, id)
			h.jobOrder = h.jobOrder[1:]
			continue
		}
		break
	}
}

func (h *handler) jobStatus(req pluginapi.ManagementRequest) pluginapi.ManagementResponse {
	notFound := pluginapi.ManagementResponse{
		StatusCode: http.StatusNotFound,
		Headers:    http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Body:       []byte(`{"error":"unknown job"}`),
	}
	id := strings.TrimSpace(req.Query.Get("job"))
	if id == "" {
		return notFound
	}
	// 快照必须在锁内取：j.state/j.resp 由后台 runJob 在锁内写入，锁外读
	// 会与其构成数据竞争（race detector 实锤），且可能拿到撕裂的中间态。
	h.mu.Lock()
	j := h.jobs[id]
	var id_, state string
	var resp convertResponse
	if j != nil {
		id_, state, resp = j.id, j.state, j.resp
	}
	h.mu.Unlock()
	if j == nil {
		return notFound
	}
	body, err := json.Marshal(map[string]any{"job": id_, "state": state, "result": resp})
	if err != nil {
		return notFound
	}
	return pluginapi.ManagementResponse{
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		Body:       body,
	}
}

// runJob 是后台任务体：逐 token 转换 → 组装凭证 → 宿主落盘 → 聚合结果。
// panic 兜底：转换或宿主回调若 panic，置 done 并记录失败——否则 job 永远
// 卡在 running，busyLocked 恒真，插件从此对所有转换请求 409。
func (h *handler) runJob(j *job, tokens []string, proxy string, convertFn convertFunc, saveFn saveFunc) {
	resp := convertResponse{Input: len(tokens)}
	now := timeNow()
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("sso-import plugin: job %s panic: %v", j.id, r)
				resp.Failed = append(resp.Failed, failItem{Error: fmt.Sprintf("internal error: %v", r)})
			}
		}()
		for i, token := range tokens {
			ctx, cancel := context.WithTimeout(context.Background(), convertBudget)
			info, err := convertFn(ctx, token, proxy)
			cancel()
			if err != nil {
				resp.Failed = append(resp.Failed, failItem{Error: fmt.Sprintf("第 %d 个：%s", i+1, convert.DescribeError(err))})
				continue
			}
			name, ok := cpaformat.AuthFileName(info.Email)
			if !ok {
				resp.Failed = append(resp.Failed, failItem{Email: truncate(info.Email, 40), Error: "unsafe email segment"})
				continue
			}
			account := cpaformat.Build(info, now)
			data, err := json.MarshalIndent(account, "", "  ")
			if err != nil {
				resp.Failed = append(resp.Failed, failItem{Error: "marshal account failed"})
				continue
			}
			data = append(data, '\n')
			if err := saveFn(name, data); err != nil {
				log.Printf("sso-import plugin: save %s failed: %v", name, err)
				resp.Failed = append(resp.Failed, failItem{Email: info.Email, Error: "save auth file failed: " + truncate(err.Error(), 120)})
				continue
			}
			log.Printf("sso-import plugin: imported %s tier=%s expired=%s", info.Email, info.SubscriptionTier, account.Expired)
			resp.OK = append(resp.OK, okItem{Email: info.Email, Tier: info.SubscriptionTier, Expired: account.Expired, File: name})
		}
	}()
	h.mu.Lock()
	j.resp = resp
	j.state = "done"
	j.doneAt = timeNow()
	h.mu.Unlock()
}

var jobCounter atomic.Uint64

func newJobID() string {
	return fmt.Sprintf("j%d-%d", timeNow().UnixNano(), jobCounter.Add(1))
}

// hostAuthSave 走宿主官方通道写凭证 JSON 并更新运行时凭证记录（落盘即热
// 加载，无需重启）。
func hostAuthSave(name string, raw json.RawMessage) error {
	_, err := callHost(pluginabi.MethodHostAuthSave, pluginapi.HostAuthSaveRequest{
		Name: name,
		JSON: raw,
	})
	return err
}

func mustJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
