#!/usr/bin/env bash
# 构建目标平台的 CGO 共享库、最小安装压缩包与 SHA-256 校验和。
#
# 用法:
#   scripts/release.sh <版本号> [goos/goarch ...]
#
# 不指定平台时构建默认矩阵:
#   linux/amd64 linux/arm64 darwin/arm64 darwin/amd64 windows/amd64
#
# 交叉构建 CGO 需要对应目标的 C 交叉编译器,通过环境变量声明,
# 变量名形如 CC_<goos>_<goarch>:
#   CC_linux_arm64=aarch64-linux-gnu-gcc
#   CC_darwin_amd64="clang -arch x86_64"
#   CC_windows_amd64=x86_64-w64-mingw32-gcc
# 未声明的平台按本机编译器构建(仅当目标即本机平台时可行)。
#
# 输出: dist/release/
#   zcode-v<版本>-<goos>-<goarch>.tar.gz
#   SHA256SUMS
# 压缩包内含共享库、生成的 zcode.h、LICENSE 与中文安装说明 INSTALL.md。
set -euo pipefail

usage() {
    echo "usage: $0 <version> [goos/goarch ...]" >&2
    exit 2
}

[ $# -ge 1 ] || usage
version=$1
shift
case "$version" in
    ''|-[!]*) usage ;;
esac

root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/dist/release"
rm -rf "$out"
mkdir -p "$out"

default_platforms=(linux/amd64 linux/arm64 darwin/arm64 darwin/amd64 windows/amd64)
platforms=("$@")
[ ${#platforms[@]} -gt 0 ] || platforms=("${default_platforms[@]}")

# sha256 工具在 GNU coreutils 与 macOS 之间名称不同。
sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    else
        shasum -a 256 "$1"
    fi
}

# 构建单平台并打包。stage 目录即压缩包内的一层目录,
# 解包即是完整的最小安装内容。
build_platform() {
    goos=$1
    goarch=$2
    case "$goos" in
        linux) ext=so ;;
        darwin) ext=dylib ;;
        windows) ext=dll ;;
        *) echo "unsupported goos: $goos" >&2; return 1 ;;
    esac

    cc_var="CC_${goos}_${goarch}"
    cc=${!cc_var:-}

    stage="$out/zcode-v$version-$goos-$goarch"
    mkdir -p "$stage"
    echo "==> building zcode-v$version $goos/$goarch"
    (
        cd "$root"
        export CGO_ENABLED=1 GOOS="$goos" GOARCH="$goarch"
        [ -n "$cc" ] && export CC="$cc"
        go build -trimpath -buildmode=c-shared \
            -ldflags "-s -w -X main.pluginVersion=$version" \
            -o "$stage/zcode.$ext" .
    )
    # go build -buildmode=c-shared 会把 C 头文件生成在输出文件旁。
    [ -f "$stage/zcode.h" ] || { echo "missing generated zcode.h" >&2; return 1; }
    cp "$root/LICENSE" "$stage/LICENSE"
    cp "$root/docs/install.md" "$stage/INSTALL.md"

    archive_base="zcode-v$version-$goos-$goarch"
    # 统一使用 tar.gz:Windows 10+ 自带 bsdtar 可直接解包,
    # 也避免交叉平台 CI 环境对 zip 工具的依赖。
    tar -czf "$out/$archive_base.tar.gz" -C "$out" "$archive_base"
    rm -rf "$stage"
}

for target in "${platforms[@]}"; do
    case "$target" in
        */*) ;;
        *) echo "bad platform '$target', expected goos/goarch" >&2; exit 2 ;;
    esac
    build_platform "${target%/*}" "${target#*/}"
done

# 校验和只覆盖压缩包本身;每行是文件名而非路径,便于发布页直接下载校验。
: > "$out/SHA256SUMS"
for archive in "$out"/zcode-v*-*; do
    (cd "$out" && sha256_file "$(basename "$archive")") >> "$out/SHA256SUMS"
done

# 自检:重新验证一遍刚生成的校验和,失败即中止发布。
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$out" && sha256sum -c SHA256SUMS >/dev/null)
else
    (cd "$out" && shasum -a 256 -c SHA256SUMS >/dev/null)
fi
echo "==> release artifacts in $out"
ls -l "$out"
