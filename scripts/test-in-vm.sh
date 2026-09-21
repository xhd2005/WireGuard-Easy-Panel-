#!/usr/bin/env bash
# 在目标 Linux 虚拟机上跑 Go 测试，不在本机或服务器安装任何东西。
#
# 为什么需要这个脚本：开发机是 Windows 且没有 Go 工具链；计划用 Docker 跑测试的
# 路线也走不通（目标机的 dockerd 因 spec 4.5 所述的 DNS 问题无法 pull 镜像）。
# 唯一不改动主机配置的可行办法，是把官方 Go 包解到 /tmp 用完删除。
#
# 用法：
#   WG_TEST_HOST=user@host scripts/test-in-vm.sh
# 需要目标机上 ~/.ssh/ 里已配好密钥（脚本不接收也不存储密码）。
set -euo pipefail

: "${WG_TEST_HOST:?用法: WG_TEST_HOST=user@host scripts/test-in-vm.sh}"
GO_VER="${GO_VER:-1.23.4}"
REMOTE="/tmp/wgpanel-test.$$"
LOCAL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# 优先使用国内与腾讯云可用镜像
GO_URLS=(
  "https://golang.google.cn/dl/go${GO_VER}.linux-amd64.tar.gz"
  "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz"
)

echo "==> 打包 panel/ 与 fixtures/"
tar czf - -C "$LOCAL_ROOT" panel fixtures | ssh "$WG_TEST_HOST" "mkdir -p $REMOTE && tar xzf - -C $REMOTE"

echo "==> 上传并准备 Go ${GO_VER} 到 $REMOTE/go（缓存于 /tmp/go-dist-${GO_VER}）"
{
  printf '%s\n' "set -uo pipefail"
  printf 'cd %s\n' "$REMOTE"
  printf 'CACHED_GO=/tmp/go-dist-%s\n' "$GO_VER"
  printf 'if [ ! -x "$CACHED_GO/bin/go" ]; then\n'
  printf '  mkdir -p /tmp/gotmp-$$\n'
  printf '  ok=0\n'
  for u in "${GO_URLS[@]}"; do
    printf '  [ $ok = 1 ] || { echo "   尝试 %s"; timeout 180 curl -fsSL -o /tmp/gotmp-$$/go.tgz "%s" && [ -s /tmp/gotmp-$$/go.tgz ] && ok=1; }\n' "$u" "$u"
  done
  printf '  [ $ok = 1 ] || { echo "❌ 所有 Go 下载源都失败；请在能联网的机器上备好 $CACHED_GO/bin/go 再重跑" ; exit 1; }\n'
  printf '  tar xzf /tmp/gotmp-$$/go.tgz -C /tmp/gotmp-$$\n'
  printf '  rm -rf "$CACHED_GO"\n'
  printf '  mv /tmp/gotmp-$$/go "$CACHED_GO"\n'
  printf '  rm -rf /tmp/gotmp-$$\n'
  printf 'fi\n'
  printf 'ln -sf "$CACHED_GO" go\n'
  printf 'go/bin/go version\n'
} | ssh "$WG_TEST_HOST" "bash -s"

echo "==> go vet + go test + build"
ssh "$WG_TEST_HOST" "cd $REMOTE/panel \
  && export HOME=$REMOTE GOCACHE=$REMOTE/.gocache GOPATH=$REMOTE/.gopath GOTOOLCHAIN=local CGO_ENABLED=0 GOPROXY=https://goproxy.cn,direct \
  && ../go/bin/go mod tidy \
  && ../go/bin/go vet ./... \
  && ../go/bin/go test ./... -count=1 -v \
  && ../go/bin/go test ./... -count=1 -cover \
  && ../go/bin/go build -v -o $REMOTE/wg-panel ."

echo "==> 同步 go.sum 回本地"
ssh "$WG_TEST_HOST" "cat $REMOTE/panel/go.sum" > "$LOCAL_ROOT/panel/go.sum"

echo "==> 清理远端临时目录"
ssh "$WG_TEST_HOST" "chmod -R u+w $REMOTE 2>/dev/null || true; rm -rf $REMOTE"
echo "✅ 完成"
