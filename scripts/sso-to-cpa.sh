#!/usr/bin/env bash
# sso cookie -> CLIProxyAPI(CPA) xai 账号 一键转换导入
# 用法:
#   ./sso-to-cpa.sh -f ./sso.txt          # 文件里每行一个 sso token
#   ./sso-to-cpa.sh '<sso-token>'         # 单个 token 直接传参
# 行为: 调 s2sso convert（Chrome_116_PSK 指纹过 accounts.x.ai CF）
#       -> 组装 xai-<email>.json -> install 进 CPA auths 目录（热加载）
# 可用环境变量覆盖: S2SSO（s2sso 二进制路径）、AUTHS（CPA auths 目录）
set -euo pipefail
export LC_ALL=C
S2SSO=${S2SSO:-s2sso}
AUTHS=${AUTHS:-./auths}
TMPD=$(mktemp -d /tmp/s2sso-cpa.XXXXXX)
chmod 700 "$TMPD"
trap 'rm -rf "$TMPD"' EXIT

command -v "$S2SSO" >/dev/null 2>&1 || [ -x "$S2SSO" ] || { echo "ERROR: s2sso not found ($S2SSO)" >&2; exit 1; }

SSO_FILE="$TMPD/sso.txt"
if [ "${1:-}" = "-f" ]; then
  [ $# -eq 2 ] && [ -f "$2" ] || { echo "usage: $0 -f <sso-file> | $0 <sso-token>" >&2; exit 1; }
  cp "$2" "$SSO_FILE"
else
  [ $# -eq 1 ] || { echo "usage: $0 -f <sso-file> | $0 <sso-token>" >&2; exit 1; }
  printf '%s\n' "$1" > "$SSO_FILE"
fi
chmod 600 "$SSO_FILE"

"$S2SSO" convert -sso-file "$SSO_FILE" > "$TMPD/convert.out" 2> "$TMPD/convert.err" || {
  echo "convert failed:" >&2; cat "$TMPD/convert.err" >&2; exit 1; }

python3 - "$TMPD" <<'PY'
import json, os, sys
from datetime import datetime, timezone

tmpd = sys.argv[1]
raw = open(os.path.join(tmpd, "convert.out"), encoding="utf-8", errors="replace").read()

# s2sso convert 输出形如: "[i/n] <摘要行>\n<MarshalIndent JSON>\n..."，逐段提取 JSON
decoder = json.JSONDecoder()
infos, i = [], 0
while i < len(raw):
    if raw[i] == "{":
        obj, end = decoder.raw_decode(raw, i)
        infos.append(obj)
        i = end
    else:
        i += 1
if not infos:
    sys.exit("no token JSON parsed from convert output")

rows = []
for idx, info in enumerate(infos):
    need = ("access_token", "refresh_token", "email", "sub", "id_token")
    missing = [k for k in need if not info.get(k)]
    if missing:
        sys.exit("token #%d missing keys: %s (convert partial?)" % (idx + 1, missing))
    exp = info.get("expires_at") or 0
    expired = datetime.fromtimestamp(exp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if exp else ""
    out = {
        "access_token": info["access_token"],
        "auth_kind": "oauth",
        "base_url": "https://api.x.ai/v1",  # CPA 运行时对 grok 模型自动改用 cli-chat-proxy
        "disable_cooling": True,
        "disabled": False,
        "email": info["email"],
        "expired": expired,  # CPA TokenData json tag 即 "expired"
        "expires_in": int(info.get("expires_in") or 21600),
        "id_token": info["id_token"],
        "last_refresh": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "refresh_token": info["refresh_token"],
        "sub": info["sub"],
        "token_endpoint": "https://auth.x.ai/oauth2/token",
        "token_type": info.get("token_type") or "Bearer",
        "type": "xai",
    }
    p = os.path.join(tmpd, "%d.json" % (idx + 1))  # 索引 int 定界，杜绝路径注入
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    rows.append((idx + 1, out["email"]))
    print("converted #%d: %s (tier=%s expired=%s)" % (
        idx + 1, out["email"], info.get("subscription_tier", "?"), expired or "?"))

with open(os.path.join(tmpd, "map.tsv"), "w") as m:
    for idx, email in rows:
        m.write("%d\t%s\n" % (idx, email))
PY

while IFS=$'\t' read -r idx email; do
  case "$email" in
    ''|*[!0-9A-Za-z@._-]*|*..*) echo "unsafe email segment: $email" >&2; exit 1;;
  esac
  install -m 600 "$TMPD/$idx.json" "$AUTHS/xai-$email.json"
  echo "installed: $AUTHS/xai-$email.json"
done < "$TMPD/map.tsv"
echo "done. CPA watches the auth dir and picks files up automatically (no restart)."
