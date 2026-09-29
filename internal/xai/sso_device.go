// SPDX-License-Identifier: LGPL-3.0-or-later
//
// 本文件逐字取自 Wei-Shaw/sub2api（LGPL-3.0）的
// backend/internal/pkg/xai/sso_device.go，仅调整包路径。
// Copyright (C) Wei-Shaw/sub2api contributors.

package xai

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	SSOBuildScope        = "openid profile email offline_access grok-cli:access api:access conversations:read conversations:write"
	SSOAccountsURL       = "https://accounts.x.ai/"
	SSODeviceURL         = OAuthIssuer + "/oauth2/device/code"
	SSOVerifyURL         = OAuthIssuer + "/oauth2/device/verify"
	SSOApproveURL        = OAuthIssuer + "/oauth2/device/approve"
	SSOTokenURL          = OAuthIssuer + "/oauth2/token"
	SSOConversionTimeout = 90 * time.Second

	ssoMaxAuthBody     = 2 << 20
	ssoMaxTokenLength  = 16 << 10
	ssoDefaultUA       = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	ssoDefaultTokenTTL = 6 * time.Hour
)

var (
	ErrSSOUnauthorized        = errors.New("xai sso unauthorized")
	ErrSSOAuthorizationDenied = errors.New("xai device authorization denied")
)

type SSOHTTPError struct {
	Status int
	Body   string
}

func (e SSOHTTPError) Error() string {
	msg := fmt.Sprintf("xAI OAuth HTTP %d", e.Status)
	snippet := strings.Join(strings.Fields(e.Body), " ")
	if snippet != "" {
		if len(snippet) > 400 {
			snippet = snippet[:400]
		}
		msg += " body=" + snippet
	}
	return msg
}

type SSODeviceHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type SSODeviceOptions struct {
	HTTPClient SSODeviceHTTPClient
	UserAgent  string
	Sleep      func(context.Context, time.Duration) error
}

type ssoDeviceFlow struct {
	client    SSODeviceHTTPClient
	userAgent string
	cookieJar http.CookieJar
	sleep     func(context.Context, time.Duration) error
}

func ConvertSSOToBuild(ctx context.Context, ssoToken string, opts *SSODeviceOptions) (*TokenResponse, error) {
	ssoToken = NormalizeSSOToken(ssoToken)
	if ssoToken == "" {
		return nil, ErrSSOUnauthorized
	}
	if opts == nil {
		opts = &SSODeviceOptions{}
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: SSOConversionTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	userAgent := strings.TrimSpace(opts.UserAgent)
	if userAgent == "" {
		userAgent = ssoDefaultUA
	}
	sleep := opts.Sleep
	if sleep == nil {
		sleep = sleepContext
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	seedSSOCookies(jar, ssoToken)

	flow := &ssoDeviceFlow{
		client:    client,
		userAgent: userAgent,
		cookieJar: jar,
		sleep:     sleep,
	}
	return flow.convert(ctx)
}

func (f *ssoDeviceFlow) convert(ctx context.Context) (*TokenResponse, error) {
	status, finalURL, probeBody, err := f.do(ctx, http.MethodGet, SSOAccountsURL, nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized || strings.Contains(finalURL, "sign-in") || strings.Contains(finalURL, "sign-up") {
		return nil, ErrSSOUnauthorized
	}
	if status < 200 || status >= 400 {
		return nil, fmt.Errorf("validate Grok Web SSO: %w", SSOHTTPError{Status: status, Body: string(probeBody)})
	}

	status, _, body, err := f.do(ctx, http.MethodPost, SSODeviceURL, url.Values{
		"client_id": {DefaultClientID},
		"scope":     {SSOBuildScope},
	})
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("start xAI device flow: %w", SSOHTTPError{Status: status, Body: string(body)})
	}
	var device struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		Interval                int    `json:"interval"`
		ExpiresIn               int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &device); err != nil {
		return nil, fmt.Errorf("parse xAI device flow response: %w", err)
	}
	if device.DeviceCode == "" || device.UserCode == "" || !safeXAIAuthURL(device.VerificationURIComplete) {
		return nil, errors.New("xAI device flow response is incomplete")
	}
	if device.Interval <= 0 {
		device.Interval = 5
	}
	if device.ExpiresIn <= 0 {
		device.ExpiresIn = 1800
	}

	status, _, verifyBody, err := f.do(ctx, http.MethodGet, device.VerificationURIComplete, nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 400 {
		return nil, fmt.Errorf("open xAI device verification page: %w", SSOHTTPError{Status: status, Body: string(verifyBody)})
	}

	status, finalURL, verifyBody, err = f.do(ctx, http.MethodPost, SSOVerifyURL, url.Values{"user_code": {device.UserCode}})
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 400 {
		return nil, fmt.Errorf("verify xAI device code: %w", SSOHTTPError{Status: status, Body: string(verifyBody)})
	}
	if !strings.Contains(finalURL, "consent") {
		return nil, errors.New("xAI device verification did not reach consent page")
	}

	// xAI 的 approve 端点要求 consent 页下发的 consent_token（ES256 JWT，绑定
	// device_code、约 30 分钟有效），并按跨站表单导航校验 Origin/Referer/
	// Sec-Fetch 头——缺 consent_token 或浏览器头任一，CF WAF 都会直接 403
	// "Request could not be verified"。consent 页在 accounts.x.ai，approve 提交
	// 到 auth.x.ai，因此 Origin 指向 accounts 域、Sec-Fetch-Site 为 cross-site。
	consentToken := extractConsentFormToken(string(verifyBody))
	if consentToken == "" {
		return nil, errors.New("xAI consent page did not provide consent_token")
	}

	approveExtra := http.Header{}
	approveExtra.Set("Origin", "https://accounts.x.ai")
	approveExtra.Set("Referer", finalURL)
	approveExtra.Set("Sec-Fetch-Dest", "document")
	approveExtra.Set("Sec-Fetch-Mode", "navigate")
	approveExtra.Set("Sec-Fetch-Site", "cross-site")
	approveExtra.Set("Sec-Fetch-User", "?1")
	approveExtra.Set("Upgrade-Insecure-Requests", "1")
	status, finalURL, approveBody, err := f.doWithHeaders(ctx, http.MethodPost, SSOApproveURL, url.Values{
		"user_code":      {device.UserCode},
		"action":         {"allow"},
		"principal_type": {"User"},
		"principal_id":   {""},
		"consent_token":  {consentToken},
	}, approveExtra)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 400 {
		return nil, fmt.Errorf("approve xAI device code: %w", SSOHTTPError{Status: status, Body: string(approveBody)})
	}
	if !strings.Contains(finalURL, "done") {
		return nil, errors.New("xAI device approval did not reach done page")
	}

	return f.pollToken(ctx, device.DeviceCode, time.Duration(device.Interval)*time.Second, time.Duration(device.ExpiresIn)*time.Second)
}

func (f *ssoDeviceFlow) pollToken(ctx context.Context, deviceCode string, interval, expiresIn time.Duration) (*TokenResponse, error) {
	if interval < time.Second {
		interval = time.Second
	}
	deadline := time.Now().Add(minDuration(expiresIn, 75*time.Second))
	for time.Now().Before(deadline) {
		if err := f.sleep(ctx, interval); err != nil {
			return nil, err
		}
		status, _, body, err := f.do(ctx, http.MethodPost, SSOTokenURL, url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"client_id":   {DefaultClientID},
			"device_code": {deviceCode},
		})
		if err != nil {
			return nil, err
		}
		var payload struct {
			AccessToken      string `json:"access_token"`
			RefreshToken     string `json:"refresh_token"`
			IDToken          string `json:"id_token"`
			TokenType        string `json:"token_type"`
			ExpiresIn        int64  `json:"expires_in"`
			Scope            string `json:"scope"`
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("parse xAI token response: %w", err)
		}
		if status >= 200 && status < 300 && payload.AccessToken != "" {
			if payload.ExpiresIn <= 0 {
				payload.ExpiresIn = int64(ssoDefaultTokenTTL.Seconds())
			}
			if payload.TokenType == "" {
				payload.TokenType = "Bearer"
			}
			return &TokenResponse{
				AccessToken:  payload.AccessToken,
				RefreshToken: payload.RefreshToken,
				IDToken:      payload.IDToken,
				TokenType:    payload.TokenType,
				ExpiresIn:    payload.ExpiresIn,
				Scope:        payload.Scope,
			}, nil
		}
		switch payload.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "access_denied", "expired_token":
			return nil, ErrSSOAuthorizationDenied
		default:
			if status >= 400 {
				return nil, fmt.Errorf("xAI token polling failed (%s): %w", firstNonEmpty(payload.ErrorDescription, payload.Error), SSOHTTPError{Status: status})
			}
			return nil, fmt.Errorf("xAI token polling failed: %s", firstNonEmpty(payload.ErrorDescription, payload.Error, strconv.Itoa(status)))
		}
	}
	return nil, errors.New("xAI device flow token polling timed out")
}

func (f *ssoDeviceFlow) do(ctx context.Context, method, endpoint string, form url.Values) (int, string, []byte, error) {
	return f.doWithHeaders(ctx, method, endpoint, form, nil)
}

func (f *ssoDeviceFlow) doWithHeaders(ctx context.Context, method, endpoint string, form url.Values, extra http.Header) (int, string, []byte, error) {
	if !safeXAIAuthURL(endpoint) {
		return 0, "", nil, errors.New("xAI OAuth URL is not trusted")
	}
	currentURL := endpoint
	currentMethod := method
	currentForm := form
	for redirects := 0; redirects <= 8; redirects++ {
		var body io.Reader
		if currentForm != nil {
			body = strings.NewReader(currentForm.Encode())
		}
		request, err := http.NewRequestWithContext(ctx, currentMethod, currentURL, body)
		if err != nil {
			return 0, currentURL, nil, err
		}
		request.Header.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.8")
		request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
		request.Header.Set("User-Agent", f.userAgent)
		for key, values := range extra {
			// Origin 只在首个请求（approve 表单 POST）携带：浏览器对重定向后
			// 的 GET 导航不发 Origin；Sec-Fetch-*/Referer/Upgrade-Insecure-
			// Requests 属导航语义，浏览器会在后续跳转 GET 上继续携带。
			if redirects > 0 && strings.EqualFold(key, "Origin") {
				continue
			}
			for _, value := range values {
				request.Header.Set(key, value)
			}
		}
		if cookie := f.cookieHeader(request.URL); cookie != "" {
			request.Header.Set("Cookie", cookie)
		}
		if currentForm != nil {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}

		response, err := f.client.Do(request)
		if err != nil {
			return 0, currentURL, nil, err
		}
		f.captureCookies(request.URL, response)
		data, readErr := io.ReadAll(io.LimitReader(response.Body, ssoMaxAuthBody+1))
		_ = response.Body.Close()
		if readErr != nil {
			return response.StatusCode, currentURL, nil, readErr
		}
		if len(data) > ssoMaxAuthBody {
			return response.StatusCode, currentURL, nil, errors.New("xAI OAuth response exceeds 2 MiB")
		}
		if response.StatusCode < 300 || response.StatusCode > 399 {
			return response.StatusCode, currentURL, data, nil
		}

		location := strings.TrimSpace(response.Header.Get("Location"))
		if location == "" {
			return response.StatusCode, currentURL, data, errors.New("xAI OAuth redirect missing Location")
		}
		base, _ := url.Parse(currentURL)
		next, err := url.Parse(location)
		if err != nil {
			return response.StatusCode, currentURL, data, err
		}
		currentURL = base.ResolveReference(next).String()
		if !safeXAIAuthURL(currentURL) {
			return response.StatusCode, currentURL, data, errors.New("xAI OAuth redirected to untrusted host")
		}
		if response.StatusCode == http.StatusSeeOther || ((response.StatusCode == http.StatusMovedPermanently || response.StatusCode == http.StatusFound) && currentMethod != http.MethodGet && currentMethod != http.MethodHead) {
			currentMethod = http.MethodGet
			currentForm = nil
		}
	}
	return 0, currentURL, nil, errors.New("xAI OAuth redirected too many times")
}

func seedSSOCookies(jar http.CookieJar, token string) {
	if jar == nil {
		return
	}
	for _, rawURL := range []string{SSOAccountsURL, OAuthIssuer + "/"} {
		target, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		jar.SetCookies(target, []*http.Cookie{
			{Name: "sso", Value: token, Path: "/", Secure: true, HttpOnly: true},
			{Name: "sso-rw", Value: token, Path: "/", Secure: true, HttpOnly: true},
		})
	}
}

func (f *ssoDeviceFlow) captureCookies(requestURL *url.URL, response *http.Response) {
	if f == nil || f.cookieJar == nil || requestURL == nil || response == nil {
		return
	}
	cookies := make([]*http.Cookie, 0)
	for _, cookie := range response.Cookies() {
		name := strings.TrimSpace(cookie.Name)
		value := strings.TrimSpace(cookie.Value)
		if name == "" || len(name) > 128 || len(value) > 16384 || strings.ContainsAny(name+value, "\r\n\x00") {
			continue
		}
		cookie.Name = name
		cookie.Value = value
		cookies = append(cookies, cookie)
	}
	f.cookieJar.SetCookies(requestURL, cookies)
}

func (f *ssoDeviceFlow) cookieHeader(requestURL *url.URL) string {
	if f == nil || f.cookieJar == nil || requestURL == nil {
		return ""
	}
	cookies := f.cookieJar.Cookies(requestURL)
	sort.Slice(cookies, func(i, j int) bool { return cookies[i].Name < cookies[j].Name })
	parts := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		parts = append(parts, cookie.Name+"="+cookie.Value)
	}
	return strings.Join(parts, "; ")
}

func safeXAIAuthURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.Hostname() == "" {
		return false
	}
	if AllowUnsafeURLOverrides() {
		return parsed.Scheme != "" && parsed.Host != ""
	}
	if parsed.Scheme != "https" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "x.ai" || strings.HasSuffix(host, ".x.ai")
}

func NormalizeSSOToken(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(value), "cookie:") {
		value = strings.TrimSpace(value[len("cookie:"):])
	}
	for _, part := range strings.Split(value, ";") {
		name, token, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "sso", "sso-rw":
			return sanitizeSSOToken(token)
		}
	}
	if token, _, found := strings.Cut(value, ";"); found {
		value = strings.TrimSpace(token)
	}
	return sanitizeSSOToken(value)
}

func sanitizeSSOToken(value string) string {
	value = strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(strings.TrimSpace(value))
	if len(value) > ssoMaxTokenLength {
		return ""
	}
	return value
}

func DecodeJWTClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	return claims
}

func JWTClaimString(claims map[string]any, key string) string {
	value, _ := claims[key].(string)
	return strings.TrimSpace(value)
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if a < b {
		return a
	}
	return b
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// extractConsentFormToken pulls the consent_token hidden input out of the
// consent page HTML. The value is a signed JWT whose expiry is bounded
// (~30 minutes), so a stale page would fail approve anyway.
func extractConsentFormToken(pageHTML string) string {
	const marker = `name="consent_token" value="`
	idx := strings.Index(pageHTML, marker)
	if idx < 0 {
		return ""
	}
	rest := pageHTML[idx+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	token := strings.TrimSpace(rest[:end])
	if token == "" || len(token) > ssoMaxTokenLength {
		return ""
	}
	return token
}
