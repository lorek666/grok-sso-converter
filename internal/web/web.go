// Package web 提供 s2sso serve：贴 sso cookie 一键转 CLIProxyAPI xai 账号
// 的极简 Web 工具。
//
// GET  /            内嵌单页
// POST /api/convert {tokens:[...], key} → 进程内调 convert.Convert（指纹
// 流程），组装 xai-<email>.json 原子写入 CPA auths 目录（CPA 监听目录热
// 加载，无需重启）。
//
// 只应绑定 127.0.0.1（公网经 nginx /sso-import/ 反代）；key 从文件读取、
// 支持随时轮换；sso token 不落日志、不回显、不落盘；写文件名经白名单
// 校验且结果路径必须仍在 auths 目录内。
package web

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"s2sso/internal/convert"
	"s2sso/internal/cpaformat"
)

//go:embed page.html
var pageHTML []byte

const (
	maxTokens   = 10
	maxBodyByte = 1 << 20
	// 页面免输入：GET / 时服务端把密钥注入页面（hex 字符集，无需 JS 转义）。
	// POST 鉴权保留，可挡住不解析页面的盲打扫描器。
	keyPlaceholder = "__IMPORT_KEY_PLACEHOLDER__"
	// 转换接口每 IP 限速：转换串行且每 token 最坏数分钟，正常用远达不到。
	rateMax    = 5
	rateWindow = time.Minute
)

// Options 是 Serve 的配置。
type Options struct {
	Addr     string // 监听地址，应保持 127.0.0.1:8318
	KeyFile  string // 访问密钥文件（600，openssl rand -hex 24 生成）
	AuthsDir string // CPA auths 目录（docker volume 宿主机路径）
	Proxy    string // 可选出站代理（透传给 convert）
}

// cpaAccount、buildCPAAccount、文件名白名单均已抽到 internal/cpaformat
// （与 CPA 插件共用）；此处保留同名薄包装，测试与调用点不变。
type cpaAccount = cpaformat.Account

func buildCPAAccount(info *convert.TokenInfo, now time.Time) cpaAccount {
	return cpaformat.Build(info, now)
}

// safeAuthFileName 把 email 映射为 ('xai-<email>.json', 目标绝对路径)。
// 白名单校验在 cpaformat.SafeEmailSegment；最终路径必须仍位于 authsDir 内
// （防御深度，web 版直写 auths 目录特有）。
func safeAuthFileName(authsDir, email string) (name, dest string, ok bool) {
	if !cpaformat.SafeEmailSegment(email) {
		return "", "", false
	}
	name = "xai-" + email + ".json"
	dest = filepath.Join(authsDir, name)
	if filepath.Dir(dest) != filepath.Clean(authsDir) {
		return "", "", false
	}
	return name, dest, true
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

// server 的转换函数可注入，便于测试（生产为 convert.Convert）。
type convertFunc func(ctx context.Context, ssoToken, proxyURL string) (*convert.TokenInfo, error)

type server struct {
	opt       Options
	convertFn convertFunc
	mu        sync.Mutex // 转换全局串行（指纹客户端并发易触发 CF 边缘质询）
	rl        *ipLimiter
}

// ipLimiter 是极简固定窗口限速器（内存态，重启清零即够用）。
type ipLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newIPLimiter() *ipLimiter {
	return &ipLimiter{hits: make(map[string][]time.Time)}
}

func (l *ipLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	fresh := l.hits[ip][:0]
	for _, t := range l.hits[ip] {
		if now.Sub(t) < rateWindow {
			fresh = append(fresh, t)
		}
	}
	if len(fresh) >= rateMax {
		l.hits[ip] = fresh
		return false
	}
	l.hits[ip] = append(fresh, now)
	if len(l.hits) > 10000 { // 防内存膨胀：超量清表（重启级精度即可）
		l.hits = make(map[string][]time.Time)
	}
	return true
}

func clientIP(r *http.Request) string {
	// 服务只绑 127.0.0.1，唯一入口是 nginx；X-Real-IP 由 nginx 覆盖式设置，
	// 客户端伪造的值不会透传。
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *server) handleConvert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.rl.allow(clientIP(r), time.Now()) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests, retry in a minute"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyByte)
	var req struct {
		Tokens []string `json:"tokens"`
		Key    string   `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	expected, err := loadKey(s.opt.KeyFile)
	if err != nil || expected == "" || subtle.ConstantTimeCompare(
		[]byte(req.Key), []byte(expected)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid key"})
		return
	}
	var tokens []string
	for _, t := range req.Tokens {
		if t = strings.TrimSpace(t); t != "" {
			tokens = append(tokens, t)
		}
	}
	if len(tokens) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no tokens"})
		return
	}
	if len(tokens) > maxTokens {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("too many tokens (max %d)", maxTokens)})
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	resp := convertResponse{Input: len(tokens)}
	for i, token := range tokens {
		info, err := s.convertFn(r.Context(), token, s.opt.Proxy)
		if err != nil {
			resp.Failed = append(resp.Failed, failItem{Error: fmt.Sprintf("第 %d 个：%s", i+1, convert.DescribeError(err))})
			continue
		}
		name, dest, ok := safeAuthFileName(s.opt.AuthsDir, info.Email)
		if !ok {
			resp.Failed = append(resp.Failed, failItem{Email: truncate(info.Email, 40), Error: "unsafe email segment"})
			continue
		}
		account := buildCPAAccount(info, now)
		data, err := json.MarshalIndent(account, "", "  ")
		if err != nil {
			resp.Failed = append(resp.Failed, failItem{Error: "marshal account failed"})
			continue
		}
		data = append(data, '\n')
		tmp := dest + ".tmp"
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			resp.Failed = append(resp.Failed, failItem{Email: info.Email, Error: "write auth file failed"})
			continue
		}
		if err := os.Rename(tmp, dest); err != nil { // 原子替换，watcher 不会读到半个文件
			os.Remove(tmp)
			resp.Failed = append(resp.Failed, failItem{Email: info.Email, Error: "rename auth file failed"})
			continue
		}
		log.Printf("sso-import: imported %s tier=%s expired=%s", info.Email, info.SubscriptionTier, account.Expired)
		resp.OK = append(resp.OK, okItem{Email: info.Email, Tier: info.SubscriptionTier, Expired: account.Expired, File: name})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handlePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	key, err := loadKey(s.opt.KeyFile)
	if err != nil || !validImportKey(key) {
		http.Error(w, "import key not configured on server", http.StatusInternalServerError)
		return
	}
	// key 经 validImportKey 限定为 [0-9A-Za-z_.-]，注入 JS 字符串字面量无需转义
	body := strings.ReplaceAll(string(pageHTML), keyPlaceholder, key)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(body))
}

func loadKey(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// validImportKey 限定密钥字符集与长度：既是注入安全前提，也挡住误配置。
func validImportKey(key string) bool {
	if len(key) < 16 || len(key) > 128 {
		return false
	}
	for _, r := range key {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r == '_' || r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, obj any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(obj)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Handler 返回可测试的 http.Handler（mux: / 与 /api/convert）。
func Handler(opt Options, convertFn convertFunc) http.Handler {
	if convertFn == nil {
		convertFn = convert.Convert
	}
	s := &server{opt: opt, convertFn: convertFn, rl: newIPLimiter()}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/convert", s.handleConvert)
	mux.HandleFunc("/", s.handlePage)
	return mux
}

// Serve 启动 HTTP 服务（阻塞）。应绑定 127.0.0.1，公网访问走 nginx 反代。
func Serve(ctx context.Context, opt Options) error {
	if opt.Addr == "" {
		opt.Addr = "127.0.0.1:8318"
	}
	key, err := loadKey(opt.KeyFile)
	if err != nil || !validImportKey(key) {
		return fmt.Errorf("key file %s 不可读或格式不符（openssl rand -hex 24 生成，权限 600，字符集 [0-9A-Za-z_.-]，长度 16-128）", opt.KeyFile)
	}
	if st, err := os.Stat(opt.AuthsDir); err != nil || !st.IsDir() {
		return fmt.Errorf("auths 目录不可用: %s", opt.AuthsDir)
	}
	srv := &http.Server{
		Addr:              opt.Addr,
		Handler:           Handler(opt, nil),
		ReadHeaderTimeout: 30 * time.Second,
		// 不设 WriteTimeout：单次转换最坏约 4-5 分钟/账号，长响应不能被掐。
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	log.Printf("sso-import listening on http://%s (auths=%s)", opt.Addr, opt.AuthsDir)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	// ErrServerClosed 是 ctx 触发的正常停机（SIGINT/SIGTERM），不是失败。
	return nil
}
