package convert

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"s2sso/internal/xai"

	"github.com/stretchr/testify/require"
)

// 测试夹具 token：值无意义，仅断言往返一致（非真实凭据）。
const (
	fixtureAccess  = "fixture-access"
	fixtureRefresh = "fixture-refresh"
	fixtureIDTok   = "fixture-id"
)

// fixtureJWT 构造无签名的 JWT（仅测 claims 解析，值均为夹具）。
func fixtureJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	body := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + body + ".fixture-signature"
}

func fixtureTokenResponse() *xai.TokenResponse {
	return &xai.TokenResponse{
		AccessToken:  fixtureAccess,
		RefreshToken: fixtureRefresh,
		IDToken:      fixtureIDTok,
		TokenType:    "Bearer",
	}
}

func TestTokenInfoUsesDeviceFlowClientID(t *testing.T) {
	// 回归锁：device flow 硬编码 DefaultClientID，credentials 的 client_id
	// 不允许跟随 XAI_CLIENT_ID 环境变量漂移，否则 refresh 会用错 client。
	t.Setenv(xai.EnvClientID, "some-other-client-id")
	info := tokenInfoFromResponse(&xai.TokenResponse{
		AccessToken: fixtureAccess,
		IDToken:     fixtureJWT(t, map[string]any{"email": "user@example.cc", "sub": "sub-1", "team_id": "team-1"}),
		ExpiresIn:   3600,
	})
	require.Equal(t, xai.DefaultClientID, info.ClientID)
	require.NotEqual(t, "some-other-client-id", info.ClientID)
}

func TestTokenInfoClaimsAndTier(t *testing.T) {
	info := tokenInfoFromResponse(&xai.TokenResponse{
		AccessToken:  fixtureJWT(t, map[string]any{"tier": float64(5)}),
		RefreshToken: fixtureRefresh,
		IDToken:      fixtureJWT(t, map[string]any{"email": "user@example.cc", "sub": "sub-1", "team_id": "team-1"}),
		ExpiresIn:    0, // 走默认 TTL 分支
	})
	require.Equal(t, "user@example.cc", info.Email)
	require.Equal(t, "sub-1", info.Subject)
	require.Equal(t, "team-1", info.TeamID)
	require.Equal(t, "supergrok_heavy", info.SubscriptionTier)
	require.Equal(t, int64(grokDefaultAccessTokenTTL.Seconds()), info.ExpiresIn)
	require.NotZero(t, info.ExpiresAt)
}

func TestBuildAccountCredentialsKeySet(t *testing.T) {
	info := &TokenInfo{
		AccessToken:      fixtureAccess,
		RefreshToken:     fixtureRefresh,
		IDToken:          fixtureIDTok,
		TokenType:        "Bearer",
		ExpiresAt:        1760000000,
		ClientID:         xai.DefaultClientID,
		Scope:            "openid",
		Email:            "user@example.cc",
		Subject:          "sub-1",
		TeamID:           "team-1",
		SubscriptionTier: "supergrok",
	}
	creds := BuildAccountCredentials(info)
	for _, key := range []string{
		"access_token", "expires_at", "refresh_token", "token_type", "id_token",
		"client_id", "scope", "email", "sub", "team_id", "subscription_tier", "base_url",
	} {
		require.Contains(t, creds, key)
	}
	require.Equal(t, xai.DefaultCLIBaseURL, creds["base_url"])
	require.True(t, strings.HasPrefix(creds["expires_at"].(string), "20"), "expires_at 应为 RFC3339")
}
