#!/usr/bin/env bash
# 编译并将只读面板部署到目标服务器的 systemd 服务中。
# 不修改任何现有 WireGuard / Docker / 业务配置。
set -euo pipefail

: "${WG_TEST_HOST:?用法: WG_TEST_HOST=user@host scripts/deploy-in-vm.sh}"
LOCAL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REMOTE="/tmp/wgpanel-deploy.$$"

echo "==> 1. 上传代码与构建文件到 $REMOTE"
tar czf - -C "$LOCAL_ROOT" panel fixtures deploy | ssh "$WG_TEST_HOST" "mkdir -p $REMOTE && tar xzf - -C $REMOTE"

echo "==> 2. 在远端编译并安全安装服务"
ssh "$WG_TEST_HOST" "bash -s -- '$REMOTE'" << 'REMOTE_EOF'
set -euo pipefail
REMOTE="$1"

GO_BIN="/tmp/go-dist-1.23.4/bin/go"
if [ ! -x "$GO_BIN" ]; then
  echo "❌ 未找到预热好的 Go 1.23.4 编译器，请先运行测试脚本下载"
  exit 1
fi

cd "$REMOTE/panel"
export HOME="$REMOTE" GOCACHE="$REMOTE/.gocache" GOPATH="$REMOTE/.gopath" GOTOOLCHAIN=local CGO_ENABLED=0 GOPROXY=https://goproxy.cn,direct

echo "==> 编译静态二进制..."
"$GO_BIN" build -v -ldflags="-s -w" -o "$REMOTE/wg-panel" .

echo "==> 安装二进制到 /usr/local/bin/wg-panel..."
sudo systemctl stop wg-panel.service 2>/dev/null || true
sudo install -m 755 -o root -g root "$REMOTE/wg-panel" /usr/local/bin/wg-panel

echo "==> 初始化受保护目录（0700 root:root）..."
sudo mkdir -p /etc/wg-panel /var/lib/wg-panel /var/backups/wg-panel
sudo chmod 700 /etc/wg-panel /var/lib/wg-panel /var/backups/wg-panel

echo "==> 安装 systemd 单元..."
sudo cp "$REMOTE/deploy/wg-panel.service" /etc/systemd/system/wg-panel.service
sudo chmod 644 /etc/systemd/system/wg-panel.service
sudo systemctl daemon-reload
sudo systemctl enable --now wg-panel.service

echo "==> 验证服务是否成功运行..."
sleep 1
sudo systemctl status wg-panel.service --no-pager

echo "==> 清理部署构建临时目录..."
chmod -R u+w "$REMOTE" 2>/dev/null || true
rm -rf "$REMOTE"
REMOTE_EOF

echo "==> 3. 提取服务初始日志与密码..."
ssh "$WG_TEST_HOST" "sudo journalctl -u wg-panel.service -n 25 --no-pager"

echo "==> 4. 本地回环接口连通性验证..."
ssh "$WG_TEST_HOST" "curl -sI http://127.0.0.1:8734/ | head -n 5"
echo "✅ 部署完成！"
