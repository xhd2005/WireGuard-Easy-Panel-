#!/usr/bin/env bash
# 跨架构纯静态编译与打包脚本 (linux/amd64 & linux/arm64)
# 生成的归档位于 dist/，包含 sha256 校验和文件 checksums.txt
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"

VERSION="${VERSION:-$(git -C "$ROOT_DIR" describe --tags --always 2>/dev/null || echo "1.0.0")}"
COMMIT="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo "dev")"
BUILD_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

mkdir -p "$DIST_DIR"
rm -rf "${DIST_DIR:?}"/*

echo "=========================================================="
echo "🚀 开始构建 WireGuard Web Panel"
echo "   版本:   v$VERSION"
echo "   提交:   $COMMIT"
echo "   时间:   $BUILD_TIME"
echo "=========================================================="

ARCHS=("amd64" "arm64")

for arch in "${ARCHS[@]}"; do
    echo "--> 正在编译 linux/${arch}..."
    bin_name="wg-panel-linux-${arch}"
    bin_path="$DIST_DIR/$bin_name"

    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath \
        -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILD_TIME}" \
        -o "$bin_path" "$ROOT_DIR/panel"

    # 打包为 GitHub Release 结构
    tar_name="wg-panel-v${VERSION}-linux-${arch}.tar.gz"
    echo "--> 打包归档 ${tar_name}..."
    
    TMP_STAGE="$(mktemp -d)"
    cp "$bin_path" "$TMP_STAGE/wg-panel"
    cp "$ROOT_DIR/deploy/wg-panel.service" "$TMP_STAGE/"
    cp "$ROOT_DIR/LICENSE" "$TMP_STAGE/" 2>/dev/null || true
    
    tar -czf "$DIST_DIR/$tar_name" -C "$TMP_STAGE" .
    rm -rf "$TMP_STAGE"
done

echo "--> 计算 SHA256 校验和..."
(
    cd "$DIST_DIR"
    sha256sum wg-panel-*.tar.gz > checksums.txt
)

echo "=========================================================="
echo "✅ 构建完成！构建产物列表："
ls -lh "$DIST_DIR"
echo "=========================================================="
