// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Package convert 串联「SSO cookie → Build OAuth token → 账号凭据」，
// 派生自 Wei-Shaw/sub2api（LGPL-3.0）的
// repository.grok_oauth_client.go（3 次重试）与
// service.grok_oauth_service.go 的 tokenInfoFromResponse /
// BuildAccountCredentials 组装语义。
// Copyright (C) Wei-Shaw/sub2api contributors.
package convert

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"s2sso/internal/fpclient"
	"s2sso/internal/xai"
)

const grokDefaultAccessTokenTTL = 6 * time.Hour

// TokenInfo 对齐 fork 的 service.GrokTokenInfo（导入 sub2api 所需字段）。
type TokenInfo struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	IDToken          string `json:"id_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int64  `json:"expires_in"`
	ExpiresAt        int64  `json:"expires_at"`
	ClientID         string `json:"client_id,omitempty"`
	Scope            string `json:"scope,omitempty"`
	Email            string `json:"email,omitempty"`
	Subject          string `json:"sub,omitempty"`
	TeamID           string `json:"team_id,omitempty"`
	SubscriptionTier string `json:"subscription_tier,omitempty"`
}

// Convert 把 Web SSO cookie 换成 Build OAuth token。CF 对浏览器指纹仍有
// 概率性边缘质询（EOF/超时），流程无客户端侧状态，整体重启安全： transport
// 类错误重试至多 3 次；业务类错误（cookie 无效/授权拒绝/上游 4xx/5xx）直接返回。
func Convert(ctx context.Context, ssoToken, proxyURL string) (*TokenInfo, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, lastErr
			case <-time.After(500 * time.Millisecond):
			}
		}
		client, err := fpclient.NewSSOOAuthHTTPClient(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("create SSO fingerprint client: %w", err)
		}
		requestCtx, cancel := context.WithTimeout(ctx, xai.SSOConversionTimeout)
		tokenResp, rawErr := xai.ConvertSSOToBuild(requestCtx, ssoToken, &xai.SSODeviceOptions{HTTPClient: client})
		cancel()
		if rawErr == nil {
			info := tokenInfoFromResponse(tokenResp)
			if strings.TrimSpace(info.AccessToken) == "" {
				return nil, errors.New("grok oauth token response missing access_token")
			}
			return info, nil
		}
		lastErr = rawErr
		if !isRetryableSSOTransportError(rawErr) {
			return nil, lastErr
		}
	}
	return nil, lastErr
}

func isRetryableSSOTransportError(err error) bool {
	if errors.Is(err, xai.ErrSSOUnauthorized) || errors.Is(err, xai.ErrSSOAuthorizationDenied) {
		return false
	}
	var statusErr xai.SSOHTTPError
	if errors.As(err, &statusErr) {
		return false
	}
	return true
}

func tokenInfoFromResponse(tokenResp *xai.TokenResponse) *TokenInfo {
	now := time.Now()
	expiresIn := tokenResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = int64(grokDefaultAccessTokenTTL.Seconds())
	}
	info := &TokenInfo{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		TokenType:    tokenResp.TokenType,
		ExpiresIn:    expiresIn,
		ExpiresAt:    now.Add(time.Duration(expiresIn) * time.Second).Unix(),
		// device flow 硬编码 DefaultClientID（见 sso_device.go），credentials 必须
		// 存同一个值，否则后续 refresh 会用错 client_id——fork 的 ValidateSSOToken
		// 同样显式传 xai.DefaultClientID 而非 EffectiveClientID()。
		ClientID: strings.TrimSpace(xai.DefaultClientID),
		Scope:    tokenResp.Scope,
	}
	if info.TokenType == "" {
		info.TokenType = "Bearer"
	}
	applyGrokTokenClaims(info, tokenResp.IDToken, false)
	applyGrokTokenClaims(info, tokenResp.AccessToken, true)
	return info
}

func applyGrokTokenClaims(info *TokenInfo, token string, includeTier bool) {
	if info == nil || strings.TrimSpace(token) == "" {
		return
	}
	claims := xai.DecodeJWTClaims(token)
	if claims == nil {
		return
	}
	if info.Email == "" {
		info.Email = xai.JWTClaimString(claims, "email")
	}
	if info.Subject == "" {
		info.Subject = xai.JWTClaimString(claims, "sub")
	}
	if info.TeamID == "" {
		info.TeamID = xai.JWTClaimString(claims, "team_id")
	}
	if includeTier {
		if tier := xai.SubscriptionTierFromJWT(token); tier != "" {
			info.SubscriptionTier = tier
		}
	}
}

// BuildAccountCredentials 与 fork service.BuildAccountCredentials 字段一一对齐：
// sub2api 调度器/刷新器按这些键读取（refresh_token、client_id、base_url 等）。
func BuildAccountCredentials(info *TokenInfo) map[string]any {
	if info == nil {
		return nil
	}
	expiresAt := time.Unix(info.ExpiresAt, 0).UTC().Format(time.RFC3339)
	creds := map[string]any{
		"access_token": info.AccessToken,
		"expires_at":   expiresAt,
	}
	if info.RefreshToken != "" {
		creds["refresh_token"] = info.RefreshToken
	}
	if info.TokenType != "" {
		creds["token_type"] = info.TokenType
	}
	if info.IDToken != "" {
		creds["id_token"] = info.IDToken
	}
	if info.ClientID != "" {
		creds["client_id"] = info.ClientID
	}
	if info.Scope != "" {
		creds["scope"] = info.Scope
	}
	if info.Email != "" {
		creds["email"] = info.Email
	}
	if info.Subject != "" {
		creds["sub"] = info.Subject
	}
	if info.TeamID != "" {
		creds["team_id"] = info.TeamID
	}
	if info.SubscriptionTier != "" {
		creds["subscription_tier"] = info.SubscriptionTier
	}
	creds["base_url"] = xai.DefaultCLIBaseURL
	return creds
}

// DescribeError 把底层错误翻译成 CLI 可读文案（对齐 fork 的错误码语义）。
func DescribeError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, xai.ErrSSOUnauthorized) {
		return "GROK_SSO_UNAUTHORIZED: SSO cookie 无效或已过期，请重新从 grok.com 取 sso cookie"
	}
	if errors.Is(err, xai.ErrSSOAuthorizationDenied) {
		return "GROK_SSO_AUTHORIZATION_DENIED: xAI 设备授权被拒绝或已过期"
	}
	var statusErr xai.SSOHTTPError
	if errors.As(err, &statusErr) {
		if statusErr.Status == http.StatusForbidden {
			return fmt.Sprintf("GROK_SSO_UPSTREAM_FAILED(403): %v", err)
		}
		return fmt.Sprintf("GROK_SSO_UPSTREAM_FAILED(%d): %v", statusErr.Status, err)
	}
	return err.Error()
}
