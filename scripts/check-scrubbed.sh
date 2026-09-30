#!/usr/bin/env bash
# 凭证与敏感信息泄漏审计:扫描 git 跟踪文件与发布产物中的
# JWT、API Key、Cookie、授权参数与 Bearer 令牌痕迹。
#
# 范围与豁免:
#   - git 跟踪的全部文件,排除 *_test.go —— 测试固定值必须是
#     程序合成的(makeJWT 等);此脚本关注的是会被发布或会被
#     粘贴进 issue/日志的内容。
#   - dist/ 下的发布产物文本(若存在)。
#   - git-ignored 的嵌套参考仓库(docs/zcode2api 等)不在
#     git ls-files 中,天然不扫描。
#
# 命中任何模式即以非零退出;输出只含命中的文件名,不回显命中
# 内容,避免把疑似秘密再次打印到日志里。
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

patterns=(
    'eyJ[A-Za-z0-9_-]{20,}'                        # JWT 三段式 base64url 头
    'sk-[A-Za-z0-9]{16,}'                          # 以 sk- 起头的 API Key
    'Bearer [A-Za-z0-9._-]{25,}'                   # 完整 Bearer 令牌
    'Set-Cookie:[^$]+[A-Za-z0-9_=-]{8,}'           # 具体 Cookie 值
    '(access_token|refresh_token|client_secret)=[A-Za-z0-9_-]{12,}'
    '(code|state)=[A-Za-z0-9]{24,}'                # OAuth 授权参数的实际值
)

# 收集待扫描文件:跟踪文件(排除 *_test.go)+ dist 产物文本。
scan_targets=$(git ls-files | grep -v -E '(^|/)_test\.go$' || true)
if [ -d dist ]; then
    dist_targets=$(find dist -type f 2>/dev/null | grep -v -E '\.(so|dylib|dll|h)$' || true)
    # 二进制与生成的 C 头文件不扫;压缩包内容由源文件层面保证。
    scan_targets="$scan_targets
$dist_targets"
fi

# 将模式合成一条扩展 grep 表达式;命中即失败。
expr=$(IFS='|'; echo "${patterns[*]}")

failures=0
while IFS= read -r file; do
    [ -n "$file" ] || continue
    [ -f "$file" ] || continue
    if LC_ALL=C grep -E -q "$expr" "$file" 2>/dev/null; then
        echo "疑似敏感内容: $file"
        failures=$((failures + 1))
    fi
done <<< "$scan_targets"

if [ "$failures" -gt 0 ]; then
    echo "审计失败: $failures 个文件疑似携带令牌/Key/Cookie/授权参数。" >&2
    echo "请核对命中的文件;测试令牌若为程序合成,应改由代码生成而非粘贴字面量。" >&2
    exit 1
fi
echo "凭证泄漏审计通过:未发现令牌、Key、Cookie 或授权参数痕迹。"
