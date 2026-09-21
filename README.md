<div align="center">

# 🛡️ WireGuard Easy Panel (wg-panel)

**高颜值、轻量级、企业级安全且具备零停机热重载的 WireGuard Web 管理控制台与自动化组网系统**

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat-square&logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Linux%20(amd64%20%7C%20arm64)-blue?style=flat-square&logo=linux)](https://github.com/xhd2005/WireGuard-Easy-Panel-)
[![Zero CDN](https://img.shields.io/badge/Dependencies-Zero%20External%20CDN-success?style=flat-square)](#-零外部-cdn-依赖)
[![Status](https://img.shields.io/badge/Production-Ready-brightgreen?style=flat-square)](#)

[English](#english-overview) · [中文文档](#-功能特性) · [快速开始](#-快速开始-一行命令部署) · [底层调优原理](#-核心技术内幕网络调优与架构原理) · [安全设计](#-安全模型与权限隔离)

</div>

---

## 🌟 功能特性

- 🖥️ **现代化暗色控制台 (Dark Glass Slate)**：
  - 沉浸式玻璃质感设计，深度适配桌面端与移动端浏览器（小屏幕自动流式切换为卡片流）。
  - **100% 纯内联原生矢量图标与内嵌样式**，无任何 Google Fonts、Bootstrap 或 unpkg/cdnjs 外部网络依赖，局域网与离线断网环境 0ms 闪烁顺畅秒开。
- ⚡ **零停机热重载 (Zero-Downtime Hot Reload)**：
  - 增删客户端、更换密钥或启停对端时，底层采用 `wg syncconf` 精确增量热重载，**存量连接零中断、不丢包、不重启网络接口**。
- 🔀 **智能内网分流 / 全局代理一键切换 (Split vs Full Tunnel)**：
  - 支持一键切换客户端配置文件为 **分流模式**（仅组网内网走隧道，日常上网直通本地千兆宽带，不挤占云主机小带宽）或 **全局代理模式**（全部流量走隧道出口）。
- 🛑 **Peer 一键停用 / 恢复 (Disable & Enable)**：
  - 无需删除客户端即可瞬间静默阻断某个设备的网络访问，保留原 IP 绝不发生地址冲突，随时一键满血恢复。
- 🔍 **实时检索与状态过滤**：
  - 毫秒级模糊搜索（支持客户端名称、虚拟 IP、公钥前缀匹配），支持“全部 / 在线 / 离线 / 禁用”状态快速过滤。
- 💾 **全自动配置备份与一键秒级回滚**：
  - 任何变更前自动在 `/var/backups/wg-panel` 保存历史快照（最多保留 20 份），支持控制台查看历史版本并一键安全回滚，自带防语法破坏与路径穿越校验。
- 📊 **主机系统资源与健康监控**：
  - 纯 Go 原生采集 Linux `/proc` 数据，实时呈现 CPU 使用率、1/5/15min 负载、内存/磁盘占用百分比进度条与系统开机时长。
- 📱 **多端全平台一键导入**：
  - 针对手机端提供高清二维码即时扫码导入，针对电脑端提供标准 `.conf` 一键下载与代码复制；支持打包下载全部客户端配置 (`export.zip`)。
- 🔒 **严格的安全边界与私钥保护**：
  - 客户端私钥仅在内存生成供展示或下载，**服务端磁盘绝不存储任何客户端明文私钥**；systemd 严格开启 `ProtectSystem=strict` 与 `ProtectHome=yes` 沙箱隔离。
  - 密码使用工业级 Argon2id 算法加随机 Salt 散列存储；非 GET 请求强制校验 CSRF Token；防暴力破解指数退避。

---

## 📐 系统架构与数据流向

```
                         [ 浏览器 Web 管理端 ]
                                  │ (HTTP / JSON / HTML)
                                  ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        wg-panel 进程 (Go 1.23)                         │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                      Web 路由层 (ServeMux)                     │   │
│   │   /api/auth  /api/clients  /api/backups  /api/system  /        │   │
│   └───────────────────────────────┬────────────────────────────────┘   │
│                                   │                                    │
│       ┌───────────────┬───────────┴───┬──────────────┬─────────────┐   │
│       ▼               ▼               ▼              ▼             ▼   │
│  [ auth ]       [ keygen ]     [ clientconf ]   [ system ]    [ apply ]│
│  Argon2id      Curve25519       分流/全局路由   /proc 监控    flock锁  │
│  会话安全      密钥对生成       配置与QR生成    系统健康      原子写入 │
│                                       │                      备份管理  │
│                                       ▼                         │      │
│                                [ wgconf 引擎 ]                  │      │
│                                原样写回 / 注释扩展              │      │
│                                (DNS/分流/禁用标记)              │      │
└───────────────────────────────────────┬─────────────────────────┴──────┘
                                        │ 读写 /etc/wireguard/wg0.conf
                                        ▼
                  ┌────────────────────────────────────────┐
                  │          内核态与系统网络层            │
                  │  - WireGuard 内核模块 (wg0 网卡)       │
                  │  - wg syncconf 热生效 (无丢包无重启)   │
                  │  - mangle 表 TCPMSS Clamping 规则      │
                  │  - Host 防火墙 (ufw / iptables / etc)  │
                  └────────────────────────────────────────┘
```

---

## 🚀 快速开始 (一行命令部署)

### 系统环境要求
- **操作系统**：Ubuntu 20.04+, Debian 11+, CentOS 8/9, Rocky/AlmaLinux 8/9, Fedora
- **架构支持**：`x86_64 (amd64)` / `aarch64 (arm64)`
- **权限**：具有 `root` 权限

### 1. 一键全自动安装

只需在服务器终端运行一行命令（若服务器未安装 WireGuard，脚本会自动引导安装底层环境）：

```bash
curl -fsSL https://raw.githubusercontent.com/xhd2005/WireGuard-Easy-Panel-/main/install.sh | sudo bash
```

安装完成后，终端会直接打印出：
- 管理员默认账号：`admin`
- 首次自动生成的随机强密码（首次登录后强制修改）
- 访问地址与 SSH 转发命令

---

### 2. 安全访问面板

出于安全考虑（面板拥有最高 `root` 系统网络权限），**外部公网默认无法直接访问面板端口**。你可以通过以下两种最推荐的方式访问：

#### 🌟 方式 A：连上 WireGuard 后直接打开（最方便、极力推荐）
只要你的手机或电脑连上了 WireGuard 隧道（分配为 `10.7.0.x`），在浏览器直接输入服务端的虚拟内网 IP 即可直达控制台：

👉 **`http://10.7.0.1:8734`**

> **为什么推荐这种方式？**
> 该端口仅对 WireGuard 虚拟网卡内网放行，公网黑客完全扫描不到该端口的存在，既不用敲任何 SSH 命令，又具备金融级的专网加密安全性！

#### 🔑 方式 B：本地终端通过 SSH 端口转发访问（适合首次配置）
在你的本地电脑终端（Windows PowerShell / macOS Terminal / Linux）执行：

```bash
ssh -L 8734:127.0.0.1:8734 root@你的服务器公网IP
```

保持该终端窗口运行，在本地浏览器直接打开：

👉 **`http://127.0.0.1:8734`**

---

### 3. 日常服务管理

```bash
# 查看面板服务运行状态
systemctl status wg-panel.service

# 重启面板
sudo systemctl restart wg-panel.service

# 查看面板运行与审计日志
sudo journalctl -u wg-panel.service -f

# 完整卸载面板 (保留 WireGuard 底层隧道与节点配置)
sudo bash install.sh --uninstall
```

---

## 💻 客户端使用与“分流/全局”配置指南

### 客户端下载官方推荐
- **Windows**: [WireGuard for Windows 官方下载](https://www.wireguard.com/install/)
- **macOS**: App Store 搜索 `WireGuard`
- **iOS**: App Store 搜索 `WireGuard`
- **Android**: Google Play 或 F-Droid 搜索 `WireGuard`

### 为什么强烈建议开启「内网分流模式」？

在使用个人云服务器搭建 WireGuard 组网时，很多用户会遇到 **“一连上 VPN 电脑上网就变卡”** 的问题。这是因为默认的全局代理配置把整台电脑的所有流量（微信、看 4K 视频、Steam 下载等）全部塞进了云主机的公网带宽中。而普通云服务器的带宽往往只有 **3Mbps ~ 5Mbps**，相当于把原本几百兆的家庭光纤强制降级为小水管。

在面板点击客户端的 **「配置/扫码」** 时，你可以自由选择两种模式：

| 模式 | 配置中的 `AllowedIPs` | 特点与适用场景 |
|---|---|---|
| **🔀 内网分流模式 (推荐)** | `10.7.0.0/24, fddd:2c4:2c4:2c4::/64` | **日常上网丝滑不卡顿**。只有访问远程服务器、公司/家庭私有局域网时走加密隧道；刷网页看视频依然走你本地原本的高速千兆宽带。 |
| **🌐 全局代理模式** | `0.0.0.0/0, ::/0` | **整机全部流量走服务器中转**。适合在公共非信任 Wi-Fi（如咖啡厅、酒店）保护隐私，或需要借用服务器公网 IP 进行特定网络访问的场景。 |

---

## 🔬 核心技术内幕：网络调优与架构原理

### 1. TCPMSS Clamping 与解决 PMTUD 黑洞

#### 痛点根因
标准以太网的 MTU 为 1500 字节。WireGuard 会给每一个原始数据包封装外层 UDP、IP 报头以及加密认证标签（开销通常为 60~80 字节）。因此 WireGuard 网卡 (`wg0`) 的内部 MTU 通常被设定为 1420（甚至跨洋丢包严重时建议降为 1280）。

在传统的路径 MTU 发现 (PMTUD) 机制中，路由器遇到超过 MTU 的数据包本应返回 ICMP `Need Fragmentation` (Type 3, Code 4) 差错报文。然而在现代互联网中，**大量运营商防火墙和云安全网关会粗暴过滤丢弃所有 ICMP 差错报文**，导致发送端永远不知道数据包过大被丢弃，这就是著名的 **PMTUD 黑洞**。
> **典型症状**：`ping` 和 SSH 终端打字完全正常（小包通），但一旦打开大型网页、执行 `git clone` 或拉取镜像时连接就会永久无响应卡死。

#### 本系统的破解方案
本系统在 Linux 系统的 `mangle` 表中为 WireGuard 子网量身定制了 TCPMSS Clamping 规则：

```bash
iptables -t mangle -A FORWARD -s 10.7.0.0/24 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t mangle -A FORWARD -d 10.7.0.0/24 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

- **为何放在 mangle 表**：Linux netfilter 钩子顺序为 `raw` -> `mangle` -> `filter`。若放在普通 `filter` 表，包一旦命中头部的 `ACCEPT` 就会离开链，末尾的规则永远轮不到执行；而在 `mangle` 表中，TCP 握手 SYN 阶段的最大分段大小在路由决定前被就地协商压制，杜绝分片。
- **无需重新分发**：该规则完全在服务端自动生效，存量客户端完全无感，彻底终结大包卡死问题。

---

### 2. 为什么 BBR 无法直接加速 WireGuard UDP 隧道？

很多网传教程声称“开启 BBR 就能让 WireGuard 翻倍提速”，这是一个典型的认知误区：
- **BBR (Bottleneck Bandwidth and RTT)** 是基于 **TCP 协议**的拥塞控制算法（通过调节 TCP 拥塞窗口 `cwnd` 来寻找带宽与延迟的最优平衡点）。
- **WireGuard 传输层是纯粹的 UDP 协议**。Linux 内核根本不对 UDP 流量跑 BBR 拥塞控制。
- 开启 BBR 真正改善的是服务器本机的 TCP 服务（如 SSH 连接、面板本身的 HTTP/HTTPS），对 WireGuard 封装发出的 UDP 数据包吞吐量毫无直接加速作用。
- 本系统去除了原脚本中无效的 `default_qdisc=fq` 与 `bbr` 误导性标记，直面底层网卡队列与软中断预算优化。

---

### 3. Linux 软中断与网络缓冲队列调优

为了让低配轻量云服务器在高突发网络流量下不发生丢包卡顿，本系统落地了内核软中断余量参数：

```ini
net.core.netdev_max_backlog = 16384  # 网卡设备输入队列深度（内核默认仅 1000）
net.core.netdev_budget = 600         # 单次软中断轮询 NAPI 批处理数据包上限（内核默认 300）
net.core.rmem_max = 16777216         # UDP Socket 接收缓冲区上限 16MB
net.core.wmem_max = 16777216         # UDP Socket 发送缓冲区上限 16MB
```

- **吸收突发流量**：在没有硬件 GSO 卸载能力的虚拟化网卡中，数据包必须逐个经由软中断处理，将 `netdev_budget` 从 300 提升至 600，能显著降低高并发时 `time_squeeze`（软中断时间片耗尽被迫让出 CPU）导致的延迟抖动。

---

### 4. 端口选择的技术权衡与避坑法则

| 端口选择 | 优势分析 | 致命陷阱与避坑法则 |
|---|---|---|
| **UDP 51820 (官方默认)** | 最标准，绝不与系统服务冲突 | 部分严苛公网 Wi-Fi 或企业级防火墙可能会阻断非标准大端口 UDP。 |
| **UDP 53 (DNS端口)** | 绝大部分公网放行 | **致命陷阱**：在 Linux 上若让 WireGuard 监听 `0.0.0.0:53`，会霸占通配地址导致本地 `systemd-resolved` 无法绑定 `127.0.0.53:53`，直接导致 **Docker daemon 拉取镜像时报 `lookup registry-1.docker.io on 127.0.0.53:53: i/o timeout` 瘫痪**！本系统已内置检测并向管理员警示。 |
| **UDP 443 (HTTPS/QUIC)** | 几乎 100% 放行 | 若服务器本机安装了 Nginx / OpenResty 并开启了 HTTP/3 (QUIC)，会发生 UDP 端口冲突导致服务起不来。 |
| **UDP 8443 / 3478 (推荐)** | 高度抗封锁且不易冲突 | 非常适合作为常规替代端口，避开常用端口争抢。 |

---

## 🔐 安全模型与权限隔离

```
┌──────────────────────────────────────────────────────────┐
│                   systemd 沙箱防御体系                   │
│                                                          │
│  [ ProtectSystem=strict ]  --> 整个根文件系统完全设为只读 │
│  [ ProtectHome=yes ]       --> 完全隔绝 /home 目录访问   │
│  [ NoNewPrivileges=yes ]   --> 禁止任何 SUID 越权提升   │
│  [ ReadWritePaths ]        --> 仅严格开放 4 个受控目录:  │
│                                ├── /etc/wireguard        │
│                                ├── /etc/wg-panel         │
│                                ├── /var/lib/wg-panel     │
│                                └── /var/backups/wg-panel │
└──────────────────────────────────────────────────────────┘
```

1. **原样写回机制 (Round-trip Fidelity)**：
   解析器使用行切片维护源文件的结构与外部注释，增删 Peer 时仅修改目标标记行，绝不重写或美化配置文件，百分之百兼容 `wg.sh` 脚本及管理员手动维护。
2. **并发文件排他锁 (`flock`)**：
   所有读写流程强制在 `/etc/wireguard/wg0.conf.lock` 独占锁下串行执行，杜绝多管理员或脚本并发修改导致配置破坏。
3. **敏感信息绝不落盘与脱敏输出**：
   - 客户端私钥仅在创建或重置瞬间通过一次性内存返回，服务端磁盘不存客户端明文私钥。
   - `GET /api/clients` 列表接口严格脱敏，绝不返回 `PrivateKey` 或 `PresharedKey`。
   - 杜绝直接暴露 `wg show dump` 原文（其第二列包含明文服务端私钥，本系统内置严格过滤器强制丢弃敏感列）。

---

## 📡 RESTful API 概览

所有非 GET 请求均需携带 `X-Requested-With: wg-panel` 防跨站请求伪造头。

| 方法 | 路径 | 认证 | 描述 |
|---|---|---|---|
| `POST` | `/api/login` | 公开 | 用户认证，写入 HttpOnly、SameSite=Strict Cookie |
| `POST` | `/api/logout` | 公开 | 销毁 Session 并清除 Cookie |
| `GET` | `/api/session` | 公开 | 查询当前登录会话状态与改密要求 |
| `PUT` | `/api/password` | 必须 | 修改管理员密码（解除强制改密限制） |
| `GET` | `/api/server` | 必须 | 获取服务端配置参数（端口、端点、网段、防火墙类型） |
| `PUT` | `/api/server/endpoint` | 必须 | 安全变更监听端口、公网端点与 MTU，触发热重载与批量重生成 |
| `GET` | `/api/clients` | 必须 | 获取所有客户端列表（名称、虚拟 IP、状态、分流模式） |
| `POST` | `/api/clients` | 必须 | 创建新客户端（自动分配最小空闲 IP、生成 Curve25519 密钥对） |
| `DELETE` | `/api/clients/{name}` | 必须 | 删除指定客户端并热同步注销 |
| `PUT` | `/api/clients/{name}/disable`| 必须 | 停用客户端（内核热切断通信，保留配置与 IP） |
| `PUT` | `/api/clients/{name}/enable` | 必须 | 重新启用客户端 |
| `POST` | `/api/clients/{name}/rotate-key`| 必须 | 一键轮换私钥与 PSK（旧设备立刻掉线） |
| `GET` | `/api/clients/{name}/config` | 必须 | 获取客户端 `.conf`（支持 `?mode=split` 内网分流参数） |
| `GET` | `/api/clients/{name}/qr.png` | 必须 | 获取客户端配置二维码 PNG（支持 `?mode=split`） |
| `GET` | `/api/clients/export.zip` | 必须 | 打包下载全部客户端配置压缩包 |
| `GET` | `/api/status` | 必须 | 实时读取内核 `wg show`（流量、对端、握手时间） |
| `GET` | `/api/system/stats` | 必须 | 获取服务器 CPU、内存、负载、磁盘及运行时间 |
| `GET` | `/api/backups` | 必须 | 获取历史配置快照列表 |
| `POST` | `/api/backups` | 必须 | 手动创建即时配置快照备份 |
| `POST` | `/api/backups/{file}/restore`| 必须 | 一键回滚到指定历史备份并热重载 |
| `GET` | `/api/version` | 公开 | 获取当前构建版本号与 Git Commit |

---

## 🛠️ 本地开发与手动构建

```bash
# 1. 克隆代码仓库
git clone https://github.com/xhd2005/WireGuard-Easy-Panel-.git
cd WireGuard-Easy-Panel-

# 2. 本地直接运行单元测试 (全量覆盖)
cd panel && go test ./... -v

# 3. 本地编译当前平台二进制
go build -ldflags="-s -w" -o wg-panel .

# 4. 执行全架构静态交叉编译打包
bash scripts/build.sh
```

---

## 📄 开源许可证 (License)

本项目采用 [MIT 许可证](LICENSE)。欢迎自由分发、修改与商用。
底层的 `wg.sh` 脚本演进自开源社区优秀的 shell 实现，致谢所有社区贡献者。

---

<div id="english-overview"></div>

## 🌐 English Overview

**WireGuard Easy Panel (wg-panel)** is a lightweight, secure, and modern WireGuard management dashboard written in pure Go. It features:
- **Zero-Downtime Hot Reload**: Manages peer addition, deletion, and key rotation via `wg syncconf` without dropping existing connections.
- **Split-Tunneling Support**: Seamlessly toggle between full-tunnel (`0.0.0.0/0`) and split-tunnel (mesh virtual subnet only) client profiles.
- **Zero External CDN Dependencies**: The web UI is completely self-contained with inline SVG graphics, ensuring blazing-fast loads even in offline environments.
- **Network Optimization**: Built-in TCPMSS Clamping to resolve PMTUD blackhole issues across lossy or PPPoE networks.
- **Strict Sandbox**: Operates under systemd sandboxing with read-only root filesystems and restricted directory permissions.
- **Single-Binary Delivery**: Self-contained web assets embedded via Go `embed.FS`.

### Quick Install
```bash
curl -fsSL https://raw.githubusercontent.com/xhd2005/WireGuard-Easy-Panel-/main/install.sh | sudo bash
```
Once installed, connect via SSH port forwarding (`ssh -L 8734:127.0.0.1:8734 root@<server_ip>`) or access via WireGuard tunnel (`http://10.7.0.1:8734`).
