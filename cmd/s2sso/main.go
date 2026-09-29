// Command s2sso 把 grok.com 的 SSO cookie 转换为 xAI OAuth token，
// 并提供可选的独立 Web 工具（serve）。
//
// 用法:
//
//	s2sso convert -sso-file ./sso.txt [-proxy http://host:port]
//	s2sso serve   [-addr 127.0.0.1:8318] [-key-file ./sso-import.key] \
//	              [-auths-dir ./auths] [-proxy ...]
//
// 凭据只从文件/环境变量读取，不回显。
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"s2sso/internal/convert"
	"s2sso/internal/web"
)

const usage = `s2sso — Grok SSO → xAI OAuth 转换器

用法:
  s2sso convert [选项]     转换 SSO cookie → OAuth token（输出完整 JSON）
  s2sso serve   [选项]     独立 Web 工具（贴 sso 一键写入 CPA auths 目录）

公共选项:
  -sso string          单个 SSO cookie
  -sso-file string     SSO cookie 文件（每行一个，# 开头为注释）
  -proxy string        出站代理（指纹客户端经它访问 accounts.x.ai）
  环境变量 S2_SSO 等价于 -sso。

convert 输出 TokenInfo JSON（access_token / refresh_token / id_token /
email / sub / expires_at / subscription_tier 等），可直接交给其他系统。

serve 选项:
  -addr string       监听地址（默认 127.0.0.1:8318，公网走 nginx 反代）
  -key-file string   访问密钥文件（默认 ./sso-import.key，600，openssl rand -hex 24）
  -auths-dir string  CPA auths 目录（默认 ./auths，或指向 docker volume 宿主机路径）
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	var (
		ssoFlag, ssoFile, proxy      string
		serveAddr, keyFile, authsDir string
	)
	fs.StringVar(&ssoFlag, "sso", "", "单个 SSO cookie")
	fs.StringVar(&ssoFile, "sso-file", "", "SSO cookie 文件（每行一个）")
	fs.StringVar(&proxy, "proxy", "", "出站代理")
	fs.StringVar(&serveAddr, "addr", "127.0.0.1:8318", "serve 监听地址")
	fs.StringVar(&keyFile, "key-file", "sso-import.key", "serve 访问密钥文件")
	fs.StringVar(&authsDir, "auths-dir", "auths", "serve：CPA auths 目录")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "convert":
		tokens := collectSSOTokens(ssoFlag, ssoFile)
		if len(tokens) == 0 {
			fmt.Fprintln(os.Stderr, "错误: 未提供 SSO cookie（-sso / -sso-file / S2_SSO）")
			os.Exit(2)
		}
		failures := 0
		for i, sso := range tokens {
			info, err := convert.Convert(ctx, sso, proxy)
			if err != nil {
				failures++
				fmt.Fprintf(os.Stderr, "[%d/%d] 转换失败: %s\n", i+1, len(tokens), convert.DescribeError(err))
				continue
			}
			encoded, _ := json.MarshalIndent(info, "", "  ")
			fmt.Printf("[%d/%d] %s\n%s\n", i+1, len(tokens), describeInfo(info), encoded)
		}
		if failures > 0 {
			os.Exit(1)
		}
	case "serve":
		exitOnErr(web.Serve(ctx, web.Options{
			Addr:     serveAddr,
			KeyFile:  keyFile,
			AuthsDir: authsDir,
			Proxy:    proxy,
		}))
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func collectSSOTokens(ssoFlag, ssoFile string) []string {
	if ssoFile != "" {
		file, err := os.Open(ssoFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 打不开 sso 文件: %v\n", err)
			os.Exit(2)
		}
		defer file.Close()
		var tokens []string
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 64*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				tokens = append(tokens, line)
			}
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "错误: 读取 sso 文件失败: %v\n", err)
			os.Exit(2)
		}
		return tokens
	}
	if ssoFlag != "" {
		return []string{ssoFlag}
	}
	if env := strings.TrimSpace(os.Getenv("S2_SSO")); env != "" {
		return []string{env}
	}
	return nil
}

func describeInfo(info *convert.TokenInfo) string {
	return fmt.Sprintf("email=%s tier=%s expires_at=%s refresh_token=有(%d字符)",
		info.Email, info.SubscriptionTier,
		time.Unix(info.ExpiresAt, 0).Format("2006-01-02 15:04:05 UTC"),
		len(info.RefreshToken))
}

func exitOnErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}
