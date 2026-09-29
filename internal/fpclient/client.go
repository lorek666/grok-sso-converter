// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Package fpclient 提供 SSO→OAuth 转换专用的浏览器指纹 HTTP client。
// 拷贝自 Wei-Shaw/sub2api（LGPL-3.0）的
// backend/internal/repository/grok_oauth_fingerprint_client.go，
// 仅调整包名与 xai import 路径。
// Copyright (C) Wei-Shaw/sub2api contributors.
package fpclient

import (
	stdhttp "net/http"

	"s2sso/internal/xai"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

// SSO→OAuth 转换（accounts.x.ai）跑在 Cloudflare bot 防护之后：非浏览器指纹的
// 客户端在边缘就被回裸 403，SSO cookie 根本没被评估。2026-09-28 服务器实测
// （每个 profile 4 轮完整流程）：
//   - Go/curl 原生指纹：403
//   - utls 仅模拟 TLS 层 + x/net/http2：EOF/403/307 间歇抖动（H2 指纹仍是 Go 的）
//   - tls-client Chrome_124：4/4 被 CF 403
//   - tls-client Chrome_131：约 6 成被边缘 EOF
//   - tls-client Chrome_116_PSK：稳定通过，与 curl-impersonate chrome116 实测一致
//
// 因此固定 Chrome_116_PSK。浏览器 UA 由 xai.sso_device.go 的 ssoDefaultUA
// （Chrome/131）在请求时设置；cookie 由 sso_device 流程手动管理（显式 Cookie
// header + 自行捕获 Set-Cookie），client 不配置 jar 避免双重管理。
func NewSSOOAuthHTTPClient(proxyURL string) (xai.SSODeviceHTTPClient, error) {
	options := []tls_client.HttpClientOption{
		tls_client.WithClientProfile(profiles.Chrome_116_PSK),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithTimeoutSeconds(int(xai.SSOConversionTimeout.Seconds())),
	}
	if proxyURL != "" {
		options = append(options, tls_client.WithProxyUrl(proxyURL))
	}
	inner, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		return nil, err
	}
	return &ssoFingerprintClient{inner: inner}, nil
}

// ssoFingerprintClient 把 tls-client 的 fhttp 类型 Do 适配成
// xai.SSODeviceHTTPClient 要求的标准库签名。仅搬运 SSO 流程用到的字段。
type ssoFingerprintClient struct {
	inner tls_client.HttpClient
}

func (c *ssoFingerprintClient) Do(req *stdhttp.Request) (*stdhttp.Response, error) {
	freq, err := fhttp.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), req.Body)
	if err != nil {
		return nil, err
	}
	freq.Host = req.Host
	// fhttp 对 io.Reader 包装类型推断不出长度（这里 body 已被 stdlib 包成
	// NopCloser），不回填会退化为 chunked 传输——真实浏览器表单 POST 带
	// Content-Length，这是指纹偏差点。
	freq.ContentLength = req.ContentLength
	for key, values := range req.Header {
		for _, value := range values {
			freq.Header.Add(key, value)
		}
	}
	fresp, err := c.inner.Do(freq)
	if err != nil {
		return nil, err
	}
	return &stdhttp.Response{
		Status:        fresp.Status,
		StatusCode:    fresp.StatusCode,
		Proto:         fresp.Proto,
		ProtoMajor:    fresp.ProtoMajor,
		ProtoMinor:    fresp.ProtoMinor,
		Header:        stdhttp.Header(fresp.Header),
		Body:          fresp.Body,
		ContentLength: fresp.ContentLength,
		Request:       req,
	}, nil
}
