# s2sso — Grok SSO → xAI OAuth 转换器（CLI + CLIProxyAPI 插件）

把 grok.com 的 **SSO cookie** 转换成 **xAI OAuth token**（refresh_token），
并以 CLIProxyAPI（CPA）插件的形式提供"网页贴 sso 一键导入凭证"。

多数自制脚本用 Go/Python 原生 TLS 指纹请求 accounts.x.ai，被 Cloudflare
边缘直接 403（cookie 根本没被评估）。本工具用 Chrome_116_PSK 浏览器指纹 +
consent_token 流程完成转换，实测可通过。

> 本项目与 xAI / Grok 无关联。使用本项目产生的账号行为受 xAI 服务条款
> 约束，使用者自行承担合规责任。

## 提供什么

| 形态 | 入口 | 适用 |
|---|---|---|
| CLI | `s2sso convert` | 手动批量转换，输出 TokenInfo JSON |
| **CPA 插件** | 贴 sso 的网页，挂 CLIProxyAPI 管理面板菜单 | 在用 CPA/CPAMP 的部署（推荐） |
| 独立 Web | `s2sso serve` | 不用 CPA 面板、想单独部署一个贴 sso 页面 |

## 安装与 CLI 用法

```bash
go build -o s2sso ./cmd/s2sso

# 转换（输出含 refresh_token 的完整 JSON）
./s2sso convert -sso 'sso=xxxx'                # 单个
./s2sso convert -sso-file ./sso.txt            # 每行一个
./s2sso convert -sso-file ./sso.txt -proxy http://127.0.0.1:7890
```

- SSO 也可用环境变量 `S2_SSO`；凭据走 600 权限文件，不回显。

## CPA 插件（plugin/ssoimport）

CPA v8.0.0+ 内置插件系统（C ABI 动态库 + JSON 信封，v8 默认 Linux 构建
即支持，可用管理 API 响应头 `X-CPA-SUPPORT-PLUGIN: 1` 检测）。本插件把
"贴 sso 一键进 CPA"做成 CPA 进程内能力：

- **入口**：`GET /v0/resource/plugins/sso-import/import` 资源页（带菜单，
  会出现在 CPAMC/CPAMP 系管理面板的「插件管理」里）。
- **接口**：`POST /v0/management/plugins/sso-import/convert`（管理密钥鉴权）
  + `GET .../status?job=`。转换**异步任务化**（POST 秒回 job id，页面轮询），
  不受网关 read timeout 影响；同一时间只跑一个任务（并发提交 409）。
- **落盘**：`host.auth.save` 宿主回调写 `xai-<email>.json` 并更新运行时
  凭证记录（热加载，无需重启）。
- **管理密钥自动带出**：页面 JS 兼容管理中心 localStorage 的两代混淆
  （v1：`salt|host|ua`；CPAMP 的 v2：`salt|v2|host`），同源部署免输入；
  解不出（未勾记住密码等）降级为输入框，sessionStorage 会话内记住。
- 指纹请求不走宿主 HTTP 桥（无 utls 指纹过不了 CF），在插件内自起
  Chrome_116_PSK 客户端；出站代理可配 `plugins.configs.sso-import.proxy`。

### 构建（Linux amd64 为例）

```bash
CGO_ENABLED=1 go build -trimpath -buildmode=c-shared \
  -o sso-import.so ./plugin/ssoimport
```

mac 上交叉编译 linux/amd64 可用 docker（把源码挂进 golang 容器）：

```bash
docker run --rm -v "$PWD":/src -w /src -e CGO_ENABLED=1 \
  golang:1.26 go build -trimpath -buildmode=c-shared \
  -o sso-import.so ./plugin/ssoimport
```

### 安装

1. 放入 CPA 插件目录（`plugins/linux/amd64/sso-import.so`；docker 部署即
   plugins volume 的 `linux/amd64/` 子目录）。
2. `config.yaml` 开插件并加配置：

```yaml
plugins:
  enabled: true
  configs:
    sso-import:
      enabled: true
      priority: 1
      # proxy: "http://127.0.0.1:7890"   # 可选：指纹客户端出站代理
```

3. 重启 CPA，确认日志出现 `plugin registered plugin_id=sso-import`，
   浏览器打开资源页即可。

## 独立 Web 工具（s2sso serve，备选）

`internal/web`：单页 + `POST /api/convert`，进程内转换后原子写入指定
auths 目录（CPA 监听目录热加载）。适合不用管理面板的部署：

```bash
openssl rand -hex 24 > sso-import.key && chmod 600 sso-import.key
./s2sso serve -key-file ./sso-import.key -auths-dir /path/to/cpa/auths
# 监听 127.0.0.1:8318，公网请经 nginx 反代；sso-import/sso-import.service
# 是 systemd 单元示例
```

key 文件每请求重读、支持轮换；每 IP 5 次/分钟限速；GET 页面时服务端把
key 注入页面（零输入）。**该形态需要 key 文件**；CPA 插件形态完全不需要
（鉴权复用 CPA 管理密钥）。

公开部署注意：长批次（10 个 token 最坏约 45-60 分钟）会被 nginx 默认
`proxy_read_timeout`(60s) 掐断——反代请配置足够大的 read timeout，或直接
使用 CPA 插件形态（异步轮询，不受影响）。限速按 `X-Real-IP` 区分 IP，
反代必须**覆盖式**设置该头（`proxy_set_header X-Real-IP $remote_addr`），
否则客户端可伪造头绕过限速。

## 附带脚本

- `scripts/sso-to-cpa.sh` — sso cookie 一键转 CPA 账号（CLI 通道，不经
  插件）：调本工具 convert → 组装 `xai-<email>.json` → install 进 auths
  目录。`S2SSO` / `AUTHS` 环境变量可覆盖二进制与目标目录。

## 已知行为

- xAI 的 refresh_token 每次刷新轮换（旧 token 实测有宽限期）。同一账号
  凭证若在多处使用，可能出现 `invalid_grant`——届时其他持有方会相继失效。
- 转换含指纹流程与上游交互，单账号最坏需数分钟；批量转换时长线性增长。

## License

LGPL-3.0-or-later（见 LICENSE 与 NOTICE）。`internal/xai`、
`internal/fpclient`、`internal/convert` 派生自
[Wei-Shaw/sub2api](https://github.com/Wei-Shaw/sub2api)（LGPL-3.0）；
CPA 插件依赖 [router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)
（MIT，仅 import 其 SDK 包）。
