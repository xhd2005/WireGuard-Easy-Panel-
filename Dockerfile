# ==============================================================================
# WireGuard Easy Panel - Multi-stage Dockerfile
# ==============================================================================

# 构建阶段：纯静态编译 Go 二进制
FROM golang:1.23-alpine AS builder

WORKDIR /src
RUN apk add --no-cache git ca-certificates

# 缓存依赖层
COPY panel/go.mod panel/go.sum ./panel/
WORKDIR /src/panel
RUN go mod download

# 编译应用
COPY panel/ /src/panel/
RUN CGO_ENABLED=0 GOOS=linux go build -v -ldflags="-s -w" -o /bin/wg-panel .

# 生产运行阶段：轻量 Alpine 运行时，含 WireGuard 内核控制工具与防火墙
FROM alpine:3.20

LABEL maintainer="xhd2005"
LABEL description="WireGuard Easy Panel - Web 管理面板与组网工作站"

RUN apk add --no-cache \
    wireguard-tools \
    iptables \
    ip6tables \
    iproute2 \
    bash \
    curl \
    ca-certificates \
    tzdata

# 安装二进制
COPY --from=builder /bin/wg-panel /usr/local/bin/wg-panel

# 创建运行目录
RUN mkdir -p /etc/wireguard /etc/wg-panel /var/lib/wg-panel /var/backups/wg-panel

# 暴露 Web 端口与常用 WireGuard UDP 端口
EXPOSE 8734
EXPOSE 51820/udp 53/udp 123/udp 443/udp 8443/udp 1194/udp

# 环境变量：标记容器运行时（触发 apply 降级为直接内核/命令行热重载）
ENV WG_PANEL_RUNTIME=docker
ENV WG_PANEL_LISTEN=0.0.0.0:8734

VOLUME ["/etc/wireguard", "/etc/wg-panel", "/var/lib/wg-panel", "/var/backups/wg-panel"]

ENTRYPOINT ["/usr/local/bin/wg-panel", "--listen", "0.0.0.0:8734", "--allow-insecure"]
