#!/usr/bin/env bash
# ==============================================================================
# WireGuard Web Panel 一键安装与管理脚本
# 项目地址: https://github.com/xaxanb/wg
# 适用系统: Ubuntu 20.04+, Debian 11+, CentOS 8+, Alma/Rocky 8+, Fedora
# ==============================================================================
set -euo pipefail

GITHUB_REPO="xaxanb/wg"
INSTALL_DIR="/usr/local/bin"
SERVICE_NAME="wg-panel"
SYSTEMD_DIR="/etc/systemd/system"
CONF_DIR="/etc/wg-panel"
STATE_DIR="/var/lib/wg-panel"
BACKUP_DIR="/var/backups/wg-panel"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }

check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        error "此脚本必须以 root 权限运行，请使用 'sudo bash $0'"
    fi
}

detect_arch() {
    local raw_arch
    raw_arch="$(uname -m)"
    case "$raw_arch" in
        x86_64|amd64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *) error "不受支持的硬件架构: $raw_arch (仅支持 amd64 / arm64)" ;;
    esac
}

check_wireguard_prerequisite() {
    info "检查 WireGuard 底层环境..."
    if ! command -v wg &>/dev/null || [[ ! -e "/etc/wireguard/wg0.conf" ]]; then
        warn "未检测到已初始化的 WireGuard 服务端 (/etc/wireguard/wg0.conf)。"
        echo -e "正在启动 WireGuard 底层配置程序...\n"
        
        # 若当前目录有 wg.sh 则直接使用，否则通过 curl 获取
        if [[ -f "./wg.sh" ]]; then
            bash ./wg.sh "$@"
        else
            TMP_WG="$(mktemp)"
            curl -fsSL "https://raw.githubusercontent.com/${GITHUB_REPO}/main/wg.sh" -o "$TMP_WG"
            bash "$TMP_WG" "$@"
            rm -f "$TMP_WG"
        fi
    else
        success "已检测到正在运行的 WireGuard 服务 (/etc/wireguard/wg0.conf)"
    fi
}

install_panel_binary() {
    local arch="$1"
    info "安装 wg-panel 控制台程序 [架构: $arch]..."

    mkdir -p "$INSTALL_DIR"

    # 优先检测本地是否有刚构建出的二进制
    if [[ -f "./dist/wg-panel-linux-${arch}" ]]; then
        info "使用本地构建产物: ./dist/wg-panel-linux-${arch}"
        install -m 755 -o root -g root "./dist/wg-panel-linux-${arch}" "$INSTALL_DIR/$SERVICE_NAME"
        return
    elif [[ -f "./panel/wg-panel" ]]; then
        info "使用本地编译二进制: ./panel/wg-panel"
        install -m 755 -o root -g root "./panel/wg-panel" "$INSTALL_DIR/$SERVICE_NAME"
        return
    fi

    # 从 GitHub Releases 获取最新发布包
    local release_url
    release_url="https://github.com/${GITHUB_REPO}/releases/latest/download/wg-panel-linux-${arch}.tar.gz"
    info "正在从 GitHub 下载最新版本: $release_url"

    local tmp_dir
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "$tmp_dir"' RETURN

    if curl -fsSL "$release_url" -o "$tmp_dir/wg-panel.tar.gz"; then
        tar -xzf "$tmp_dir/wg-panel.tar.gz" -C "$tmp_dir"
        install -m 755 -o root -g root "$tmp_dir/wg-panel" "$INSTALL_DIR/$SERVICE_NAME"
    else
        warn "从 GitHub Releases 下载失败，尝试现场编译 (需主机已装有 Go)..."
        if command -v go &>/dev/null; then
            (cd "./panel" && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$INSTALL_DIR/$SERVICE_NAME" .)
        else
            error "无法下载预编译二进制包，且未安装 Go 编译器。请在 Releases 页面手动下载并将二进制放置于 $INSTALL_DIR/$SERVICE_NAME。"
        fi
    fi
}

setup_service() {
    info "配置 systemd 服务沙箱..."

    mkdir -p "$CONF_DIR" "$STATE_DIR" "$BACKUP_DIR"
    chmod 700 "$CONF_DIR" "$STATE_DIR" "$BACKUP_DIR"

    local service_file="$SYSTEMD_DIR/${SERVICE_NAME}.service"
    cat << 'EOF' > "$service_file"
[Unit]
Description=WireGuard Web Management Panel
After=network.target wg-quick@wg0.service

[Service]
Type=simple
ExecStart=/usr/local/bin/wg-panel --listen 0.0.0.0:8734 --allow-insecure
Restart=on-failure
RestartSec=3
User=root
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/etc/wireguard /var/lib/wg-panel /etc/wg-panel /var/backups/wg-panel

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "$service_file"
    systemctl daemon-reload
    systemctl enable --now "${SERVICE_NAME}.service"

    # 若 ufw 处于 active 状态，仅放行 wg0 虚拟内网接口访问面板（保持外网公网阻断）
    if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
        ufw allow in on wg0 to any port 8734 proto tcp &>/dev/null || true
    fi

    success "wg-panel 服务已启动并配置开机自启！"
}

show_completion_banner() {
    local server_ip
    server_ip="$(curl -fsSL https://api.ipify.org 2>/dev/null || ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7}' || echo "你的服务器公网IP")"

    # 从日志中提取首次启动的随机管理员密码
    local init_pass="已保留既有密码"
    if journalctl -u "${SERVICE_NAME}.service" -n 50 --no-pager | grep -q "密  码:"; then
        init_pass="$(journalctl -u "${SERVICE_NAME}.service" -n 50 --no-pager | grep -oP '(?<=密  码: )\S+' | tail -1)"
    fi

    echo -e "\n${GREEN}======================================================================${NC}"
    echo -e "${GREEN}🎉 WireGuard Web 控制面板安装部署成功！${NC}"
    echo -e "${GREEN}======================================================================${NC}\n"
    echo -e "管理员用户名:  ${CYAN}admin${NC}"
    echo -e "初始登录密码:  ${YELLOW}${init_pass}${NC} (首次登录强制改密)\n"
    
    echo -e "${BLUE}▶ 方式一：连上 WireGuard 后直接打开（最方便、绝对安全）${NC}"
    echo -e "   浏览器访问:  ${GREEN}http://10.7.0.1:8734${NC}\n"

    echo -e "${BLUE}▶ 方式二：本地终端通过 SSH 端口转发访问（无需连 VPN）${NC}"
    echo -e "   1. 本地执行: ${YELLOW}ssh -L 8734:127.0.0.1:8734 root@${server_ip}${NC}"
    echo -e "   2. 浏览器打: ${GREEN}http://127.0.0.1:8734${NC}\n"

    echo -e "${YELLOW}⚠️ 安全提示：${NC}"
    echo -e "   1. 外部公网访问本端口已被自动屏蔽（云服务器安全组与主机防火墙均默认拦截）。"
    echo -e "   2. 若无法连接 VPN，请在腾讯云/阿里云控制台确认已放行 WireGuard UDP 监听端口。"
    echo -e "${GREEN}======================================================================${NC}\n"
}

uninstall_all() {
    check_root
    warn "正在卸载 WireGuard Web Panel..."
    systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}.service" 2>/dev/null || true
    rm -f "$SYSTEMD_DIR/${SERVICE_NAME}.service"
    systemctl daemon-reload
    rm -f "$INSTALL_DIR/$SERVICE_NAME"
    rm -rf "$CONF_DIR" "$STATE_DIR"
    success "wg-panel 已成功卸载！（WireGuard 底层隧道与 /etc/wireguard 配置已保留）"
    exit 0
}

main() {
    if [[ "${1:-}" == "--uninstall" || "${1:-}" == "uninstall" ]]; then
        uninstall_all
    fi

    check_root
    local arch
    arch="$(detect_arch)"
    check_wireguard_prerequisite "$@"
    install_panel_binary "$arch"
    setup_service
    show_completion_banner
}

main "$@"
