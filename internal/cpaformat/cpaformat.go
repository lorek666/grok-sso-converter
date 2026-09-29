// Package cpaformat 生成 CLIProxyAPI xai 凭证文件的序列化形状与文件名，
// 供 web 工具（s2sso serve）与 CPA 插件（plugin/ssoimport）共用，避免两
// 份实现漂移。
//
// Account 对齐 CLIProxyAPI internal/auth/xai 的 TokenData/TokenStorage 序列
// 化形状（types.go 的 json tag + token.go SaveTokenToFile 写死的字段）。
package cpaformat

import (
	"strings"
	"time"

	"s2sso/internal/convert"
)

const (
	// DefaultAPIBaseURL 与 discovery 的 token endpoint，对齐
	// CLIProxyAPI internal/auth/xai。CPA 运行时对 grok 模型自动改用
	// cli-chat-proxy，此值仅作为账号文件的初始 base_url。
	BaseURL       = "https://api.x.ai/v1"
	TokenEndpoint = "https://auth.x.ai/oauth2/token"
	ExpiresIn     = 21600
)

// Account 是写进 CPA auths 目录的单个 xai 凭证文件形状（15 键）。
type Account struct {
	AccessToken    string `json:"access_token"`
	AuthKind       string `json:"auth_kind"`
	BaseURL        string `json:"base_url"`
	DisableCooling bool   `json:"disable_cooling"`
	Disabled       bool   `json:"disabled"`
	Email          string `json:"email"`
	Expired        string `json:"expired"`
	ExpiresIn      int64  `json:"expires_in"`
	IDToken        string `json:"id_token"`
	LastRefresh    string `json:"last_refresh"`
	RefreshToken   string `json:"refresh_token"`
	Sub            string `json:"sub"`
	TokenEndpoint  string `json:"token_endpoint"`
	TokenType      string `json:"token_type"`
	Type           string `json:"type"`
}

// Build 由转换结果组装凭证文件内容。
func Build(info *convert.TokenInfo, now time.Time) Account {
	expiresIn := info.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = ExpiresIn
	}
	return Account{
		AccessToken:    info.AccessToken,
		AuthKind:       "oauth",
		BaseURL:        BaseURL,
		DisableCooling: true,
		Disabled:       false,
		Email:          info.Email,
		Expired:        time.Unix(info.ExpiresAt, 0).UTC().Format(time.RFC3339),
		ExpiresIn:      expiresIn,
		IDToken:        info.IDToken,
		LastRefresh:    now.UTC().Format(time.RFC3339),
		RefreshToken:   info.RefreshToken,
		Sub:            info.Subject,
		TokenEndpoint:  TokenEndpoint,
		TokenType:      "Bearer",
		Type:           "xai",
	}
}

// SafeEmailSegment 校验 email 只含白名单字符且无路径穿越片段。白名单
// 字符集与 CLIProxyAPI sanitizeFileSegment 对齐；显式拒绝路径分隔符与
// ".."。宿主侧 host.auth.save 以文件名落盘，此处校验是注入防御的第一层。
func SafeEmailSegment(email string) bool {
	if email == "" || strings.Contains(email, "..") || strings.ContainsAny(email, `/\`) {
		return false
	}
	for _, r := range email {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '@' || r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// AuthFileName 返回凭证文件名（'xai-<email>.json'）；email 不安全时 ok 为
// false。
func AuthFileName(email string) (string, bool) {
	if !SafeEmailSegment(email) {
		return "", false
	}
	return "xai-" + email + ".json", true
}
