// Package xai 在本工具中是从 sub2api fork（main 分支 7256c01be 起）抽取的
// SSO→OAuth 转换子集。fork 里的完整 xai 包还依赖 redis / redissession 等服务端
// 组件，这里只保留 sso_device.go / subscription_tier.go（裁剪版）所需的最小
// 常量与类型，语义与 fork 保持一致，便于日后 diff 对齐。
package xai

import (
	"os"
	"strings"
)

const (
	OAuthIssuer       = "https://auth.x.ai"
	DefaultClientID   = "b1a00492-073a-47ea-816f-4c329264a828"
	DefaultBaseURL    = "https://api.x.ai/v1"
	DefaultCLIBaseURL = "https://cli-chat-proxy.grok.com/v1"

	EnvClientID = "XAI_CLIENT_ID"
	// EnvAllowUnsafeURLOverrides 与 fork 同名：仅本地调试（例如指向 mock
	// 上游）时开启，生产保持关闭，SSO 流程只会访问 x.ai 域。
	EnvAllowUnsafeURLOverrides = "XAI_ALLOW_UNSAFE_URL_OVERRIDES"
)

// TokenResponse represents xAI OAuth token responses.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// EffectiveClientID 允许用环境变量覆盖 client_id；留空回默认值。
func EffectiveClientID() string {
	return envOrDefault(EnvClientID, DefaultClientID)
}

func AllowUnsafeURLOverrides() bool {
	return envBool(EnvAllowUnsafeURLOverrides)
}
