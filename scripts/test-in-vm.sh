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

# 依次尝试：腾讯云内网源 -> 谷歌中国镜像 -> 官方源。大陆机器上前两个才有实用速度。
GO_URLS=(
  "https://mirrors.tencentyun.com/go/go${GO_VER}.linux-amd64.tar.gz"
  "https://golang.google.cn/dl/go${GO_VER}.linux-amd64.tar.gz"
  "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz"
)

echo "==> 打包 panel/ 与 fixtures/"
tar czf - -C "$LOCAL_ROOT" panel fixtures | ssh "$WG_TEST_HOST" "mkdir -p $REMOTE && tar xzf - && cat > /dev/null"

echo "==> 上传并准备 Go ${GO_VER} 到 $REMOTE/go（若已存在则复用）"
{
  printf '%s\n' "set -uo pipefail"
  printf 'cd %s\n' "$REMOTE"
  printf 'if [ ! -x go/bin/go ]; then\n'
  printf '  mkdir -p gotmp\n'
  printf '  ok=0\n'
  for u in "${GO_URLS[@]}"; do
    printf '  [ $ok = 1 ] || { echo "   尝试 %s"; timeout 180 curl -fsSL -o gotmp/go.tgz "%s" && [ -s gotmp/go.tgz ] && ok=1; }\n' "$u" "$u"
  done
  printf '  [ $ok = 1 ] || { echo "❌ 所有 Go 下载源都失败；请在能联网的机器上备好 %s/go 再重跑" ; exit 1; }\n' "$REMOTE"
  printf '  tar xzf gotmp/go.tgz -C gotmp && mv gotmp/go go && rm -rf gotmp\n'
  printf 'fi\n'
  printf 'go/bin/go version\n'
} | ssh "$WG_TEST_HOST" "bash -s"

echo "==> go vet + go test"
ssh "$WG_TEST_HOST" "cd $REMOTE/panel \
  && export HOME=$REMOTE GOCACHE=$REMOTE/.gocache GOPATH=$REMOTE/.gopath GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-mod=mod \
  && ../go/bin/go vet ./... \
  && ../go/bin/go test ./... -count=1 -v \
  && ../go/bin/go test ./... -count=1 -cover"

echo "==> 清理远端临时目录"
ssh "$WG_TEST_HOST" "rm -rf $REMOTE"
echo "✅ 完成"
