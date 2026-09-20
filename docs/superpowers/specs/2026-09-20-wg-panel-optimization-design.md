# WireGuard 组网工具优化 + Go Web 管理面板 — 设计规格

日期：2026-09-20
状态：v3，待评审
交付物：修复并瘦身后的 `wg.sh` 安装器 + 全新的 `wg-panel` Go 单二进制管理面板

v3 的变化：2026-09-20 用只读命令实地核查了目标服务器，**v2 中有六处判断被真机推翻**（机型、DNS 地址、端口推荐、面板默认端口、防火墙写入方数量），并已用实测数据替换推测。核查快照见 4.6，逐条对应关系见第 17 节。

v2 相对 v1 的变化：目标部署环境明确为腾讯云大陆节点，据此删除 `wg.sh` 的 DNS 改配置逻辑（连带消除 v1 的 B1/B2/B3/B4/B9 五条）、新增性能优化与部署运维两节、修正端口流程在 firewalld 系统上的错误、补齐 v1 自检发现的五处空白。

---

## 1. 背景与现状

仓库当前只有一个 1730 行的 bash 脚本 `wg.sh`，是 [ngosang/wireguard-install](https://github.com/ngosang/wireguard-install) 的二改汉化版。能力覆盖：安装/卸载 WireGuard、增删客户端、列出客户端、显示 QR 码，支持交互式与 `--auto` 命令行两种模式。

`wg.sh` 生成的 `wg0.conf` 用注释标记标识 peer 边界：

```
# BEGIN_PEER <name>
[Peer]
PublicKey = ...
PresharedKey = ...
AllowedIPs = 10.7.0.<n>/32[, fddd:2c4:2c4:2c4::<n>/128]
# END_PEER <name>
```

服务器对外地址存在 `# ENDPOINT <ip>` 注释行（`wg.sh:899`）。这两个约定是面板与脚本互操作的基础，属于不可变更的协议。

## 2. 已确认的决策

| 决策点 | 结论 | 理由 |
|---|---|---|
| 优化范围 | 修 bug + 安全性、代码结构、功能增强；不引入 CI/shellcheck 门禁等工程质量专项 | 用户选择 |
| 分发形式 | 单文件约束解除，但 `wg.sh` 自身仍保持自包含单文件 | `curl -o wg.sh && bash wg.sh` 是"基础功能必须可用"的底线 |
| 面板技术栈 | Go 单二进制 + `go:embed` 嵌入式前端（Vue 3 + Vite + TS） | 无运行时依赖，`systemctl` 即部署 |
| 面板鉴权 | 默认只监听 `127.0.0.1:8734`，账号密码登录 | 零公网暴露，经 SSH 端口转发访问。原定的 `8080` 在目标机上已被 `docker-proxy` 占用，见 4.6 |
| 职责边界 | 面板只管客户端（peer）与对外地址；WG 本体的安装/卸载仍由 `wg.sh` 负责 | 不让 Go 重写 sysctl/防火墙/rc.local 这类危险操作 |
| 架构路线 | 方案 A：面板直接读写 `wg0.conf`，`wg syncconf` 热生效，`flock` 串行化 | 见第 6 节 |
| **部署环境** | 腾讯云 **CVM**（非轻量应用服务器），广州大陆节点，4 核 / 3 GB / Ubuntu 22.04.4 | 2026-09-20 实机核查修正，v2 误记为轻量 |
| **DNS 逻辑** | **整段删除** `wg.sh:14-40`，解析不可用时只报错不自动改配置 | 见 3.D1 |
| **监听端口策略** | `wg.sh` 保持 `51820` 默认不变；**撤销"推荐 443"**，改为"选空闲端口并强制 `ss` 实测" | 目标机上 UDP 443 已被 openresty 的 QUIC 占满，见 4.5 |
| **MTU 默认值** | 保持 `1420`（与现状一致），`1280` 作为面板可选项而非默认 | 改 MTU 需两端同时改并重新分发，不能静默变更 |
| **验收环境** | 就在这台现网机上做，用户已知悉并接受影响 6 个运行中容器与在用隧道的风险 | 用户决定；无备用测试机 |

## 3. `wg.sh` 缺陷清单与修复

### D1（最严重）删除整段 DNS 改配置逻辑

`wg.sh:14-40` 做的事：`systemctl stop systemd-resolved` → 清空 `/etc/systemd/resolved.conf`（`wg.sh:8`，位于脚本顶层且无条件执行，每次运行都清空）→ 把它 `mv` 成 `.bak`（`wg.sh:17`/`wg.sh:30`）→ 写入新 DNS → `ln -sf` 改 `/etc/resolv.conf` 指向。

这段代码有五个独立缺陷，且**在目标部署环境上是主动有害的**：

| 缺陷 | 事实 |
|---|---|
| 销毁原配置且备份无效 | 先清空再 `mv`，`.bak` 存的是空文件，"备份成功"提示为假 |
| 绕过全部安全校验 | 该块在脚本顶层执行，而 `check_root`/`check_os`/`check_container` 直到 `wg.sh:1728` 的 `wgsetup "$@"` 才运行 —— 容器、不支持的系统、权限不足场景下，DNS 已被改坏才报错退出 |
| 写入的配置语法无效 | `DNS=1.1.1.1  #国外DNS`（`wg.sh:22`/`wg.sh:35`），`resolved.conf` 不支持行内注释，`#国外DNS` 会被当作地址解析 |
| 幂等判据依赖 CWD | `./wg.txt`（`wg.sh:9-13`）相对于执行目录，换目录运行即判定为未配置并重复改系统 DNS |
| 写入后从未生效 | 停掉 `systemd-resolved` 后全程无 `restart`/`resolvectl reconfigure`，新配置是死的。真正起作用的是那条 symlink，它掩盖了这一点 |

**在目标服务器上已经真实造成损害**（2026-09-20 实测，见 4.6）：`/etc/systemd/resolved.conf` 与 `/etc/systemd/resolved.conf.bak` **都是 0 字节**，时间戳正好落在 `wg.sh` 执行当天 —— 原配置已永久丢失，"备份"是个空文件。机器现在还能解析，纯属侥幸：DNS 走的是 DHCP 下发的**每链路**地址（`resolvectl dns` 显示 `eth0: 183.60.83.19 183.60.82.98`，腾讯云广州的实际内网 DNS，**不是** v2 推测的 `100.100.2.136`）。另外 `grep -c DNS= resolved.conf` 返回 `0` —— 那段 append 最终什么都没留下，B9"写了但从未生效"有实机证据。

还有第二重危害：`wg.sh:16` 用 `ping -c1 www.google.com` 判定"能否上外网"，大陆节点这个探测大概率超时，于是脚本**必然**走"上不了外网"分支去配 `223.5.5.5`（阿里 DNS）。实机核查证实了这个推断 —— 导出配置 `/home/ubuntu/233.conf` 里正是 `DNS = 223.5.5.5`。一个为通用 VPS 写的启发式，在目标环境上系统性走错。

**处置**：删除 `wg.sh:3-41` 整块与 `wg.txt` 机制。改为在需要网络下载包之前做一次轻量解析自检（`getent hosts <镜像源域名>`），失败则**报错并打印修复建议**，绝不自动改系统配置。

#### ⚠️ 删除时必须保住的连带项（实机核查发现，v2 完全未考虑）

该块里的 `wg.sh:28` / `wg.sh:40` 两行 `iptables -I INPUT -p UDP --dport 53 -j ACCEPT` 名义上是"放行 DNS 解析"，但**目标机上的 WireGuard 正跑在 UDP 53**，所以这两行客观上同时充当了 VPN 隧道的 INPUT 放行规则 —— `iptables -S INPUT` 里能看到它被插了两次（脚本跑过两遍的痕迹）。

如果按字面理解"这段是 DNS 逻辑、整块删掉"，**目标机的隧道会当场断掉**，因为 `-P INPUT DROP` 之后就没有任何规则放行 53 了。

因此 D1 的处置必须附一条硬约束：

1. 删除前，先确认 `wg-iptables.service` 的 `ExecStart` 里 `-I INPUT -p udp --dport $port -j ACCEPT` 覆盖的就是**当前实际 `ListenPort`**（而不是安装时记忆的值），并 `systemctl restart wg-iptables.service` 后**立即** `iptables -S INPUT` 复核规则已就位
2. 复核通过才允许删除那两行；任何一步失败就中止删除，保持现网不动
3. 对应新增成功标准第 20 条

**代价**：某些 resolv.conf 不可写或 DNS 被污染的最小化系统会装机失败而非自动修好。这是有意识的取舍 —— 异常场景交给用户处理，不换取静默改写主机配置的能力。

### D2（正确性）`wg addconf` 只增不删

`update_wg_conf`（`wg.sh:1295-1297`）用 `wg addconf`。其语义是新增并覆盖同名 peer，**不会移除配置文件中已删除的 peer**，删除操作后内核态与文件态长期不一致。

**修复**：全部改为 `wg syncconf`。它会把内核中存在但配置里已不存在的 peer 删除，使增、删、改共用同一条生效路径。

### D3（健壮性，非行为修复）IP 分配解析

`select_client_ip`（`wg.sh:1065-1077`）用 `cut -d "." -f 4 | cut -d "/" -f 1` 从 `AllowedIPs` 抽末段，可读性差且依赖"IPv6 恰好写在同一行"的结构。

**实测修正**：阶段 1 改动前后在真实 Linux bash 下对三份配置跑过对比 —— 单 peer、密集+IPv6（`.2 .3 .5` → 应为 4）、以及一份故意在注释里写假 `AllowedIPs = 10.7.0.9/32` 的 trap 配置 —— **新旧算法结果完全一致（3 / 4 / 3）**。原因是它从 `.2` 线性找第一个空位，注释里的假值只要不落在候选位上就不影响结果。

所以这项**不是修 bug，是消除脆弱结构**：旧写法目前正确，但正确性依赖输入恰好长成 `wg.sh` 生成的形状。改用 `grep -oE 'AllowedIPs = 10\.7\.0\.[0-9]{1,3}/32'` 精确锚定 + 显式 `2..254` 边界后，正确性不再依赖形状巧合。

> 本条原先写成"未过滤 `::` 之外的输入、边界脆弱"，属于**读代码时的过度断言**，实测未复现任何错误行为。保留改动，但定性从"缺陷"下调为"健壮性"。

### D4（遗留）防火墙规则与 `rc.local` 的状态错乱

三个独立问题：

- `create_firewall_rules`（`wg.sh:912-969`）把 `--dport $port` 规则写进 `/etc/systemd/system/wg-iptables.service`。换端口或重复安装时文件被整体重写，但内核态仍是旧规则，直到 restart。
- **`update_rclocal`（`wg.sh:1190`）无条件往 `/etc/rc.local` 写 `systemctl restart wg-iptables.service`，不看防火墙分支。** 该 unit 只在 iptables 分支创建（`wg.sh:951-967`），firewalld 机器上根本不存在 —— 于是每次开机静默重启一个不存在的 service。
- `remove_firewall_rules`（`wg.sh:974`）用**当前** `ListenPort` 移除规则，所以换过端口再卸载，旧端口的 permanent 放行规则永久残留。

**修复**：`update_rclocal` 仅在 iptables 分支执行；卸载时取**全部曾用端口**逐个移除（数据来自 `wg-panel` 的审计记录，见 12.3），拿不到则提示人工检查，不静默跳过。

### D5（健壮性）缺少严格模式

脚本无 `set -euo pipefail`。

**修复**：`wgsetup()` 顶部加 `set -uo pipefail`。**不使用 `set -e`** —— installer 中大量命令允许失败（可选包安装、探测命令），全局 `-e` 会造成误退出。对关键写操作逐个显式判断返回值。D1 删掉后需回归确认脚本顶层只剩 `show_header` 一类无副作用输出。

### 已知不改：客户端 `Address = 10.7.0.n/24`

`wg.sh:1129` 生成的客户端掩码为 `/24`，与服务器端 peer 的 `/32` 语义不一致，会让 wg-quick 在客户端侧为整段 `/24` 建经隧道路由。这是上游 ngosang 行为，实际无功能危害（`AllowedIPs` 本就是 `0.0.0.0/0`），改动会让新旧客户端配置风格分裂。**保持不变**，面板生成配置时沿用 `/24`。

## 4. 目标部署环境约束（腾讯云 CVM · 广州 · 现网）

本节内容全部是 `wg.sh` 无法自动完成的，必须在 README 与面板 UI 中显式呈现。

### 4.1 带宽上限由云侧决定，不由配置决定

腾讯云服务器出口带宽是套餐/计费模式定的硬上限，任何主机内核参数都无法突破。

推论：第 5 节的目标是**稳定贴住上限 + 降低大丢包链路的重传代价 + 避免因表满/缓冲不足导致的突发性变慢**，不是提高吞吐上限。这个预期必须写进性能改动说明，否则用户会把"上限利用率从 40% 提到 95%"理解成"带宽翻倍"。

### 4.2 云侧还有一层防火墙，且 CVM 与轻量的形态不同

- **CVM** → 控制台里的**安全组**（默认拒绝入站，需显式加规则）
- **轻量应用服务器** → 实例的**防火墙规则列表**（形态不同，效果类似）

两者都在主机之外，`wg.sh` 完全碰不到。脚本执行成功、`wg-quick` 正常监听，客户端仍然连不上 —— 这是腾讯云 WG 部署排名第一的坑。实机佐证：目标机 `51820` 从外网探测不可达，而 `53` 可达（隧道在用），说明安全组按端口精细放行。

面板对策：检测 `wg0` 已起、`ListenPort` 正常、但**所有 peer 的 `latestHandshake` 均为从未握手**时，在页面顶部给出定向提示"请在控制台放行 UDP <当前端口>（CVM 是安全组，轻量是防火墙）"，而不是笼统报"连接失败"。

### 4.3 公网 IP 本机不可见（已实测）

`ip -brief addr` 显示目标机 `eth0` 只有 `10.2.0.15/22`，公网地址 `49.233.166.212` 不以任何形式出现在网卡上。从机器上 `curl https://ifconfig.me` **返回空**（探测不通）。

结论：面板的 `endpoint` 字段必须支持手工填写，不能只依赖探测。`# ENDPOINT 49.233.166.212` 这一行在现网配置里存在，说明当初就是人工确认填进去的。这是硬依赖，不是可选项。

### 4.4 IPv6 不可用（已实测）

`ip -6 addr show dev eth0 scope global` 返回空 —— 目标机**没有全局 IPv6**，只有链路本地 `fe80::`。`detect_ipv6`（`wg.sh:663-670`）会返回"不支持"，于是 `fddd:2c4:2c4:2c4::/64` 整段不生成。现网 `wg0.conf` 的 `Address = 10.7.0.1/24` 确实没有第二段，证实了这个分支。

这条决定了 fixture 与测试必须以"无 IPv6"为主场景，"含 IPv6"是另一份而不是默认 —— 见 13.1。

### 4.5 端口选择：撤销 v2 的"推荐 443"

大陆跨境链路的背景没变：到境外的国际出口晚高峰丢包常见 5–20%，实际吞吐能达标称三到四成即属正常；运营商与云侧对非 53/80/443 的 UDP 常做降优先级处理，所以**借用常见端口的思路本身仍然成立**。

但 v2 把"推荐 443"写进决策表是**错的**，实机核查直接推翻：目标机上 `ss -lunp 'sport = :443'` 显示 UDP 443 被 openresty 的 4 个 QUIC worker 全部占满（`1Panel-openresty` 在跑 HTTPS）。在这台机器上把 WG 改到 443 会当场起不来。

修正后的策略 —— **不给全局推荐值，改成强制实测**：

- 面板 `PUT /api/server/endpoint` 的预校验（第 8 节步骤 3）必须真的执行 `ss -lunp`，并把**占用者进程名**回显给用户（"443 已被 openresty 占用"比"端口无效"有用得多）
- README 的端口说明从"推荐 443"改为：常见可选端口 `53 / 123 / 443 / 8443 / 500`，但**必须逐个 `ss` 实测**，且提醒这些端口若被本机其他服务使用则不可用
- 现网事实供参考：目标机 WG 跑在 **UDP 53** 且工作正常（累计 2.69 GiB 下行、握手新鲜）。`ss -lunp 'sport = :53'` 显示只有 `0.0.0.0:53` 与 `[::]:53` 两个 socket、且**没有进程归属** —— 这正是 WireGuard 内核持有 socket 的特征，说明 53 确实是 WG 独占的。**但这不构成可移植的结论**：`127.0.0.53:53` 上未见 `systemd-resolved` 的 stub 监听，而 `resolved.conf` 是空文件、`DNSStubListener` 理论默认值应为 `yes` —— 也就是说"53 为什么是空的"这件事**没有查清**（可能是 1Panel、cloud-init 或某个 drop-in 改的）。换一台没跑过这套脚本的机器，53 完全可能正被 resolved 占着。所以端口仍然必须逐个实测

**换端口不能对抗协议特征识别**（这条不变）：WG 握手包首字节序列固定（`\x01\x00\x00\x00` + 时间戳），特征极强。若目标是抗 DPI，唯一出路是混淆传输层（AmneziaWG、udp2raw），超出本工具范围 —— 必须在 README 写明，避免用户以为换端口解决了问题。

### 4.6 目标服务器现状快照（2026-09-20 只读核查）

面板与 `wg.sh` 都将在下面这个真实环境上运行，而不是空白机器。这些事实直接决定了多处设计。

| 项 | 实测值 | 影响 |
|---|---|---|
| 机型 | `product_name=CVM`，4 核 / 3 GB / 40 GB 盘已用 80%，Ubuntu 22.04.4，内核 5.15 | 云侧是**安全组**；v2 误记为轻量 |
| WireGuard | `wg0` = `10.7.0.1/24`，`ListenPort = 53`，`# ENDPOINT 49.233.166.212`，仅 1 个 peer `233`（`10.7.0.2/32`），握手 42 秒前、累计 2.69 GiB 下行 | 隧道**正在被使用**，任何 restart 都会掉线 |
| 容器 | 6 个在跑：`hayden-frontend`/`hayden-backend`（博客，up 2 天）、`1Panel-mysql-qKVL`（up 3 个月）、`1Panel-redis-Kupr`、`1Panel-minio-nnF3`、`1Panel-openresty-Fp1w` | Docker 会与 WG 抢 iptables |
| 面板端口 | TCP `8080` 被 `docker-proxy` 绑在 `0.0.0.0`（后端容器发布出来的） | **面板默认端口必须换** → `127.0.0.1:8734`（实测空闲） |
| DNS | `resolved.conf` 与 `.bak` 均 0 字节；实际生效的是 DHCP 每链路 `183.60.83.19` / `183.60.82.98` | B1 损害已发生；见 3.D1 |
| iptables 后端 | `xtables-nft-multi`（iptables-nft） | 见下方"四个写入方" |
| 内核 conntrack | `nf_conntrack_max = 65536`，当前 200 表项 | 证实 5.4 的推测，提 4 倍有依据 |
| `rc.local` | 首行是 `#!bin/bash`（shebang 坏了），但 Debian 的 `rc-local.service` 用 `sh -c` source 执行故实际无害；`active (exited)` 自 **2025-11-27**，而 `wg.sh` 是 2026-09-19 跑的 | **开机重启 `wg-iptables` 这条路径从未被实际验证过** |
| 客户端私钥 | `/home/ubuntu/233.conf`，`0600 ubuntu:ubuntu`，内含明文 `PrivateKey` | 证实第 9 节的孤儿文件风险 |
| 遗留状态文件 | `/home/ubuntu/wg.txt` 存在 | B4 已发生 |

#### 主机防火墙不是"两个分支"，而是四个写入方

v2 的 `firewall` 包只打算处理 iptables / firewalld 两条分支。真机上同时存在四个互不知情的规则写入者：

1. **`wg-iptables.service`** —— 用 `iptables -I` 插到链头
2. **ufw** —— `Status: active`，`DEFAULT_INPUT_POLICY=DROP`，`DEFAULT_FORWARD_POLICY=DROP`，`INPUT` 链挂 `ufw-before-input` 等一串
3. **1Panel** —— `YJ-FIREWALL-INPUT`（INPUT 链**第一条**就是跳过去）+ `nat PREROUTING` 的 `1PANEL` 链，链内是几十条单 IP `REJECT`（防爆破累积）
4. **Docker** —— 27 条规则，`FORWARD` 里 `DOCKER-USER`/`DOCKER-ISOLATION`/各 bridge 的 ACCEPT

后果：`-I` 插头的做法在这里特别不可靠。实测 `iptables -S INPUT` 的顺序已经是 `-P INPUT DROP` → `-A INPUT -j YJ-FIREWALL-INPUT` → 两条 `--dport 53 ACCEPT` → ufw 链，**`wg-iptables` 的插队在 1Panel 之后已经看不到了**。而 `-A FORWARD -s 10.7.0.0/24 -j ACCEPT` 目前在 Docker 规则之前，**Docker daemon 重启会重建整条 FORWARD 链**，届时 WG 的转发放行位置会变化。

设计上的处置：

- `firewall` 包的第一步是**识别本机归谁管**（`ufw status`、`systemctl is-active firewalld`、是否存在 `YJ-FIREWALL-INPUT` / `1PANEL` 链、`docker` 是否在跑），并在 `/api/server` 的 `firewallBackend` 字段里如实回报，而不是假设只有一种
- **绝不与这四方争抢规则顺序。** 面板对防火墙的写操作只有一条：改 WG 端口时替换自己那条 `--dport` 规则。其余一律只读 + 提示
- 面板检测"隧道不通"时，除了 4.2 的云侧安全组提示，还要检查 `FORWARD` 里 `10.7.0.0/24` 的 ACCEPT 是否已被 Docker 重建挤掉，并把当前链内容回显出来

#### 现网暴露（用户已知悉，选择暂不处理）

外网探测确认 `3306`(MySQL)、`6379`(Redis)、`9000`(MinIO)、`8080`(后端) **公网可连**，而 `ufw` 并未放行它们 —— 原因是 Docker 发布端口走 `nat PREROUTING` DNAT + `FORWARD` 的 `DOCKER` 链，**绕开 `INPUT` 链，ufw 与 `-P INPUT DROP` 都挡不住**。

这不影响本设计的实现，但影响两件事：**①** 任何"防火墙已放行/已拦截"的判断都不能只看 ufw；**②** README 的安全章节必须写明这条 Docker 绕过，否则用户会误以为 ufw 是边界。收口的唯一可靠手段是云侧安全组。

#### 验收风险已被接受

阶段 1 要跑修复后的 `wg.sh`（重写 `wg0.conf`、`restart wg-quick@wg0` 会掐断在用隧道），阶段 4/5 要 `restart wg-iptables.service`（动 iptables，可能波及 Docker 转发）。用户明确选择在这台现网机上验收，无备用测试机。因此实现计划里每一条改配置的动作都必须自带**回滚步骤**和**执行前快照**，而不是"失败了再想办法"。

## 5. 网络性能优化

### 5.1 先纠正一处无效功：BBR

`wg.sh:1176-1181` 在内核 ≥4.20 时写 `net.core.default_qdisc=fq` 与 `net.ipv4.tcp_congestion_control=bbr`。WG 封装后的流量是 UDP，**不经过 TCP 拥塞控制**，所以这两项对隧道吞吐无影响。它们只作用于服务器自身的 TCP 服务（面板 HTTP、SSH）。

处置：**保留配置**（对管理连接确有益处），但把注释文案从暗示"VPN 提速"改为"仅对 SSH/面板等本机 TCP 生效，与 VPN 隧道无关"。这段是从 hwdsl2 的 IPsec 脚本抄来的，留着不改注释会继续误导后来人。

### 5.2 收益最大且当前完全缺失：MSS clamping

全脚本对 `mtu`、`mss`、`clamp` 零命中 —— `[Interface]` 段只有 `Address`/`PrivateKey`/`ListenPort`（`wg.sh:901-906`），FORWARD 链无任何 MSS 处理。

WG 封装开销 60–80 字节。路径 MTU 发现依赖 ICMP "需要分片"报文，而该报文在大陆出口常被丢弃（PMTUD blackhole）。典型症状正是"**连上了但很难用**"：`ping` 通、SSH 打得开、小请求正常，但 `git clone` 和大页面加载卡死在半途 —— 因为只在大包时才撞上 MTU 限制。

新增规则（v4/v6 各一条），同时进 `wg-iptables.service` 的 `ExecStart` 与 firewalld 的 direct rule：

```
iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
```

这是**唯一能在不改 MTU、不重新分发客户端配置的前提下生效**的修复，因此它是主修手段，5.3 是次要可选项。

### 5.3 MTU 作为可选项，但不改默认值

高丢包链路上把 MTU 从 1420 降到 1280 通常反而更快：丢一个 UDP 包等于丢一个完整内层段，包越小重传代价越小；1280 也是 WG 允许的最小值，彻底避开分片。

**但不作为默认值**，原因是 MTU 是接口级参数 —— 只改服务器端会让服务端发出的包超过客户端接口可接收尺寸，行为比不统一更糟。要改必须两端同改，而客户端的 MTU 在用户设备的 `.conf` 里。所以**改 MTU 属于"需要重新分发客户端配置"的操作类别**，与第 8 节的端口变更同构，必须复用同一套收敛提醒机制。

落地：`[Interface]` 支持可选 `MTU = <值>`，面板提供 1420/1360/1280 三档并说明取舍，附"改动后需重新导入所有客户端"的强提示。`wg.sh` 侧不写这一行（与存量保持一致）。

### 5.4 `nf_conntrack` 上限

> **状态更新（5.8）**：实测 `insert_failed = 0`、表项仅 188/65536，本节从"应做"降级为"仅在出现丢包时再做"。

`MASQUERADE` 隐含为每个连接占一条 conntrack 表项。内核默认上限按内存推导，小内存实例常常只有数万条。**表满会直接丢弃新包且不留日志**，症状恰好是"用一阵子突然变慢"。

实测佐证：目标机（4 核 / 3 GB）`/proc/sys/net/netfilter/nf_conntrack_max` **正好是 65536**，当前表项 200。这个数对一条活跃 VPN + 6 个容器 + 公网扫描噪声的组合来说余量很小，提 4 倍到 262144 是有依据的。

新增 `/etc/sysctl.d/99-wg-netfilter.conf`：

```
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 1200
net.netfilter.nf_conntrack_udp_timeout = 30
```

`udp_timeout = 30` 与客户端 `PersistentKeepalive = 25`（`wg.sh:1138`）配合，保证 NAT 映射在超时前被 keepalive 刷新。

注意 `nf_conntrack` 模块未加载时 `sysctl -p` 会报错：先 `modprobe nf_conntrack`，并沿用现有 `sysctl -e`（忽略不可写键）语义，不因此中断装机。

### 5.5 UDP 缓冲与 NAPI 预算

> **状态更新（5.8）**：`rmem_max` / `wmem_max` 目标机上 hwdsl2 模板**已设为一模一样的 16777216**，这两项作废；`netdev_max_backlog` 与 `netdev_budget` 已应用，但实测显示原本并没有压力（`dropped=0`、`time_squeeze` 占比 0.0277%），属于余量而非修复。

```
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 16384
net.core.netdev_budget = 600
```

作用边界要说清：1420 字节包在 8Mbps 下约 700 pps，稳态压力很低。这些参数的真实作用是**吸收突发**（峰值带宽较高、按流量计费的实例常有瞬时突发额度），不是提高稳态吞吐。

### 5.6 明确不做的优化及原因

- **CPU 亲和 / 中断绑核 / RPS-XPS** —— 理由与 v2 写的不同，但结论不变。v2 说"1–2 核没有并行度"，实测是 **4 核 CVM**，所以核数不是理由。真正的原因：**腾讯云自己的 agent 已经在做这件事** —— `/etc/rc.local` 里能看到 `/usr/local/qcloud/irq/net_smp_affinity.sh`、`rps/set_rps.sh`、`xps/set_xps.sh`、`virtio_blk_smp_affinity.sh` 四个脚本。我们重复设置只会和云厂商的调优互相覆盖，且下次它跑一遍就把我们的改动冲掉。**不动**
- **改用 nftables 后端** —— 这条在 v2 里是伪命题。实测目标机 `readlink -f $(command -v iptables)` = `/usr/sbin/xtables-nft-multi`，**现网早已是 iptables-nft 兼容层**，规则由 nftables 内核后端承载，只是命令接口还叫 iptables。所以既不用改也无需改，`wg.sh` 的 `iptables` 调用在它上面本来就工作。真正要防的是 `check_nftables`（`wg.sh:354-361`）在 RHEL 系上因 `nftables.service` 处于 active 而直接拒绝装机 —— 那是另一个问题，不在本次范围
- **对 WG 流量 `NOTRACK` 省开销** —— 与 `MASQUERADE` 直接冲突，不可行；靠 policy routing 配多个公网 IP 可绕开 NAT，但云主机通常只有一个公网 IP
- **换 `fq_codel`** —— qdisc 只作用于本机 TCP 出口队列，WG 是 UDP，替换无意义
- **隧道内压缩** —— WG 不提供，且现代链路下通常负收益

### 5.8 实测复核（2026-09-20 在目标机执行，结论推翻本节多处假设）

按 5.7 的方法在目标机采了基线。**结果显示 5.4 与 5.5 担心的问题一个都没有发生**，同时暴露出一个本节完全没覆盖、且量级远大于其余各项的问题。

#### 头号问题：这台机器的 virtio 网卡没有任何 TX offload，guest 内修不了

```
tx-tcp-segmentation:           off [fixed]
tx-checksum-ip-generic:        off [fixed]
scatter-gather:                off [fixed]
generic-segmentation-offload:  off [requested on]   ← 内核想开，设备侧拒绝
```

`[fixed]` 表示该特性由宿主机侧的 virtio 后端决定，**guest 里无论怎么设都开不了**。这对 WireGuard 是关键性影响：WG 的吞吐高度依赖 GSO 批量封装，没有它每个隧道包都要独立走一次 UDP 发送 syscall，官方文档给出的退化量级是一个数量级。当前实测隧道下行约 1.2 Mbps。

这不是配置问题，也不是本工具能解决的问题。**出路只有两条**：向腾讯云提工单问宿主机侧能否开启 vhost 的 GSO/TSO，或接受这个天花板。因此本 spec 的性能章节总目标要从"提升 WG 吞吐"改为"**消除突发丢包与 MTU 卡死，把体验修到不受上述天花板影响的稳定状态**"。

#### 顺带查实：`default_qdisc=fq` 是空转的

`tc qdisc show dev eth0` 实际是 `mq` + 每队列 `fq_codel`。因为 eth0 是多队列网卡（2 队列），root qdisc 固定为 `mq`，`net.core.default_qdisc` 对它不起作用 —— 这一行确实从未生效。

但**不删它**。原因两条：① 它在 hwdsl2 的模板文件里，`wg.sh` 每次重装都会重新下载覆盖，手工删等于白删，真要改得改 `wg.sh` 的 `update_sysctl`（归入阶段 6）；② 同一文件里的 `tcp_congestion_control=bbr` **是真正生效的**（sysctl 确认），它对面板 HTTP 与 openresty 这类本机 TCP 有益无害，不该因为 `fq` 那行无效就连带删掉。

> 修正记录：本小节上一版写过"直接删掉两行"的建议，那个建议是错的，已按上述理由撤回。

#### 两条 sysctl 改动的实测评价：是余量，不是修复

已在运行时应用并核对（不重启任何服务、不动 filter 表、不碰容器）：

| 项 | 改前 | 改后 | 实测是否有压力 |
|---|---|---|---|
| `net.core.netdev_max_backlog` | 1000 | 16384 | **无**。`/proc/net/softnet_stat` 第 2 列 `dropped` 全 CPU 累计 **0**（开机 9 个月） |
| `net.core.netdev_budget` | 300 | 600 | **无**。`time_squeeze` 合计 63,139，对 `processed` 2.28 亿 = **0.0277%**，且 10 秒采样期间**零增长** |
| MSS clamping（`mangle` FORWARD，限定 `10.7.0.0/24`） | 无 | 已加 2 条 | **有，且立即生效**：规则已命中 96 / 89 个包并持续增长 |

结论必须写清楚：**三项里只有 MSS clamping 有实测支撑的修复效果**，另两项是廉价的余量（成本约几十 MB 内存），不能宣称它们提升了速度。5.4 的 `conntrack` 同理 —— 当前 188 表项 / 上限 65536，`insert_failed` 开机以来为 0，**该节整节从"应做"降级为"仅在出现丢包时再做"**。

#### 已落地的持久化（2026-09-20）

| 改动 | 载体 | 验证方式 |
|---|---|---|
| MSS clamping 两条规则 | `/usr/local/sbin/wg-mssclamp`（幂等脚本，`-C` 先查再加）+ `wg-mssclamp.service`（oneshot、`RemainAfterExit`、`enabled`、`After=docker 1panel wg-quick@wg0`） | `ExecStop` 干净回收至只剩 `-P FORWARD ACCEPT`；清空后 start 从零添加两条；手动 flush 后 restart 恢复两条；规则已存在时启动不累积重复 |
| `netdev_max_backlog=16384`、`netdev_budget=600` | `/etc/sysctl.d/99-wg-softnet.conf`（新建独立文件，不改 hwdsl2 那份） | 把运行时改成一个不存在于任何文件的 1234/432，`sysctl --system` 精确恢复为 16384/600；`systemctl restart systemd-sysctl` 后不变 |

**未采用 `netfilter-persistent`** —— 它会快照整张规则表并在开机恢复，而这台机器上 `YJ-FIREWALL-INPUT` 已有 **884 条** 1Panel 动态累积的 REJECT、Docker 另有 27 条运行时规则；冻结并恢复它们会与两者的动态更新互相打架。

每次改动后均复检：`filter` 表 FORWARD 四条原样未动、`INPUT` 未动、Docker 27 条、YJ 884 条、6 个容器全部在、站点 `HTTP 200`、隧道握手时间戳持续刷新。

#### 为什么 MSS 规则要放在 `mangle` 而不是 `filter`

`filter` 表 FORWARD 的策略是 `DROP`，且头部已有 `-s 10.7.0.0/24 -j ACCEPT` 等接受规则 —— **包一旦被 ACCEPT 就离开该链**，追加在末尾的 TCPMSS 规则永远轮不到执行。而 netfilter 钩子顺序是 `mangle` → `filter`，把 clamp 放在 `mangle` FORWARD 才能在包被接受前改掉 MSS。附带好处：这张表原本是空的（只有 `-P FORWARD ACCEPT`），完全避开 4.6 所述四个写入方的规则顺序竞争。

`--clamp-mss-to-pmtu` 在两个方向上取的都是**出接口**路由的 MTU：下行（服务器→客户端）走 `wg0`（1420）→ 夹到 1380，正确；上行（客户端→外网）走 `eth0`（1500）→ 夹到 1460，而 TCPMSS 只降不升，客户端自己已夹到 1380 的值不会被抬高，也正确。

#### 待验证（不能从服务器侧完成）

隧道内真实路径 MTU 与饱和吞吐**必须在手机客户端侧测** —— 上一轮尝试用"从服务器 ping 内网 DNS 探测 PMTU"的测法本身无效（测的是内网那跳，不是隧道）。清单见 5.7。

## 6. 整体架构

```
wg-wg执行文件/                    # 仓库根（建议 git init，见第 14 节）
├── wg.sh                         # 留在原位：README 的 raw URL 指向根目录，移动即失效
├── README.md
├── LICENSE
├── panel/
│   ├── go.mod                    # Go 1.23
│   ├── main.go                   # flag 解析、首启生成凭据、graceful shutdown
│   ├── embed.go                  # go:embed web/dist
│   ├── internal/
│   │   ├── config/               # 监听地址、wg0.conf 与凭据/状态/备份路径
│   │   ├── auth/                 # argon2id 口令哈希、session 表、限速、改密
│   │   ├── wgconf/               # 解析 / 原样写回 / flock / IP 分配 / 备份
│   │   ├── keygen/               # curve25519 纯 Go 生成私钥、PSK
│   │   ├── status/               # `wg show` 输出解析
│   │   ├── firewall/             # 写入方识别（ufw / firewalld / 1Panel / Docker）+ 端口规则替换，见 4.6
│   │   ├── apply/                # wg syncconf / systemctl restart 封装（可注入 fake）
│   │   ├── audit/                # 操作审计日志
│   │   └── api/                  # 路由、中间件、handler
│   └── web/                      # Vue 3 + Vite + TS 源码，构建产物 dist/ 供 embed
├── scripts/build.sh              # 前端 build → go embed → 交叉编译 linux/{amd64,arm64}
├── deploy/wg-panel.service       # systemd unit
├── fixtures/                     # golden 测试：wg0.conf 两份（含/不含 IPv6）、wg show 输出若干
└── docs/superpowers/specs/
```

依赖清单（刻意最小）：`golang.org/x/crypto`（curve25519、argon2）、`github.com/skip2/go-qrcode`、标准库 `net/http`。不引入 web 框架，路由用 `http.ServeMux`（Go 1.22+ 支持带方法与路径段匹配）。

### 为什么面板直接读写 `wg0.conf`（而非 exec `wg.sh`）

面板需要结构化 JSON（peer 列表、握手时间、流量）。走 `wg.sh --listclients` 就得从 `nl -s ') '` 的编号文本反解，走 QR 就得解析 `qrencode -t ansiutf8` 的 ASCII 方块 —— 都脆弱、无并发控制、错误只能靠 exit code。直接持有读写权换来可测试性与真实数据结构。

代价是 peer 生成逻辑在 bash 和 Go 各一份，有意识接受：`wg.sh` 侧只剩安装期创建第一个客户端一处，重复面已被压到最小。

## 7. 数据模型与解析规则

```go
type Peer struct {
    Name         string   // BEGIN_PEER / END_PEER 之间的标识
    PublicKey    string   // base64，43 字符
    PresharedKey string   // 敏感；默认不出现在任何 API 响应中
    AllowedIPs   []string // "10.7.0.5/32"、"fddd:2c4:2c4:2c4::5/128"
    DNS          []string // 来自新增的 "# DNS" 注释行；可为空，见 7.2
    Raw          []string // 该 peer 块的原始行，用于原样写回
}

type Server struct {
    Address    []string
    PrivateKey string // 敏感；只用于推导 serverPublicKey
    ListenPort int
    MTU        int    // 0 表示未设置，沿用 wg-quick 默认
    Endpoint   string // 来自 "# ENDPOINT" 注释行
    RawHeader  []string
    Peers      []Peer
}
```

### 7.1 原样写回是硬要求

`wgconf` 解析器**不做格式美化**。改动的键在原行位置替换，未改动的块（含 `Raw`）逐行原样输出，保留所有注释、空行和 peer 顺序。

原因：`wg.sh` 的 `update_wg_conf` 依赖精确 sed 模式 `/^# BEGIN_PEER $client/,/^# END_PEER $client/p`。任何格式漂移（标记行前后加空行、键顺序调整、缩进变化）都会让 `wg.sh` 自己的菜单坏掉，而这属于"基础功能"。

配套测试：读入真实 `wg.sh` 产物 → 解析 → 写出 → 断言字节完全相同（13.1）。

### 7.2 peer 块新增 `# DNS` 注释行

`wg0.conf` 的 peer 块原本只有 `PublicKey`/`PresharedKey`/`AllowedIPs`（`wg.sh:1118-1123`）—— **客户端的 `DNS = ...` 只存在于导出的 `.conf` 文件里（`wg.sh:1131`），服务器端没有任何记录。**

后果很实际：面板按 `wg0.conf` 反向重建客户端配置时，DNS 只能回落默认值。一个当初选了内网 DNS 的客户端，从 `export.zip` 拿到的是公共 DNS 配置，而且不会报错，只是解析变慢。

**这不是假想场景，现网上已经有一份会踩到**：目标机唯一那个 peer 叫 `233`，其 `/home/ubuntu/233.conf` 里是 `DNS = 223.5.5.5`（恰好是 D1 那个走错分支的产物），而 `wg0.conf` 的 peer 块里**确实只有 `PublicKey`/`PresharedKey`/`AllowedIPs` 三行**，没有任何 DNS 痕迹。也就是说：现在用面板改一次端口再导 zip，`233` 就会拿到一份 DNS 被静默改掉的配置。

方案：在 `# BEGIN_PEER` 之后追加一行

```
# BEGIN_PEER phone
# DNS 183.60.83.19,183.60.82.98
```

- 与 `# ENDPOINT` 同属"注释扩展"套路，`wg` 与 `wg-quick` 都忽略注释，零功能影响
- `wg.sh` 的 sed 区间会把这行一起送给 `wg syncconf`，注释被 wg 忽略，安全
- **存量 peer 没有这一行** → 面板回落到 `config` 默认值，`dnsKnown=false`，导出界面明示"该客户端 DNS 未知，将使用默认值"，不静默替换
- 代价：`wg.sh` 的 `new_client` 也要开始写这行，否则首个客户端与后续客户端行为不一致。归入阶段 6

### 7.3 兼容性红线（不得变更，否则存量客户端无法被面板识别）

- IPv4 子网 `10.7.0.0/24`，服务器 `10.7.0.1`，客户端 `.2`–`.254`
- IPv6 子网 `fddd:2c4:2c4:2c4::/64`，服务器 `::1`，客户端 `::<n>`
- 客户端 `AllowedIPs = 0.0.0.0/0, ::/0`，`PersistentKeepalive = 25`
- peer 块注释标记格式，`# ENDPOINT <addr>`

### 7.4 IP 分配

写锁内扫描全部 peer 的 `AllowedIPs`，取 `10.7.0.x` 已占用集合，分配最小可用 `x ∈ [2,254]`。IPv6 末段与 IPv4 末段取同一数值（与 `wg.sh:1122` 一致）。`.254` 用尽返回 `409` + `subnet_exhausted`。

## 8. 端口 / Endpoint / MTU 变更流程

这是面板中唯一多步、跨系统状态、且**无法完全自动收敛**的操作。根本约束：服务端配置可以原子改完，但客户端 `.conf` 分散在用户设备上，面板没有远程推送能力。设计重点因此不是"怎么改"，而是"怎么让改动带着待重新分发的痕迹"。

流程（任一步失败即按快照回滚）：

1. `flock /etc/wireguard/wg0.conf.lock`，全程持锁
2. 完整解析 `wg0.conf`，失败立即拒绝（见 11.1）。原始字节存内存快照，同时在 `/var/backups/wg-panel/wg0.conf.<RFC3339>.bak` 落一份磁盘备份（保留 20 份）
3. 预校验：`listenPort ∈ [1,65535]`；`endpoint` 为合法 IPv4 或 FQDN（与 `wg.sh` 的 `check_ip`/`check_dns_name` 等价）；`mtu ∈ {1420,1360,1280}` 或留空
   **端口占用检查仅在端口确实变化时执行** —— 只改 `endpoint`（DDNS 换 IP、内网转公网）是最高频场景，此时 WG 自己正占着该端口，无条件检查必然误报。检查用 `ss -lun 'sport = :<newport>'` 并排除 `wg0` 本身（`443` 撞 nginx、`53` 撞 dnsmasq 是最典型翻车）
4. 只替换 `ListenPort`、`MTU`、`# ENDPOINT` 三处；**绝不触碰任何 `PrivateKey`/`PresharedKey` 行**
5. 原子落盘：同目录 `wg0.conf.new` → `fsync` → `os.Rename` → 权限 `0600`、属主 `root:root`
6. 生效，按防火墙类型分叉：
   - 探测：`systemctl is-active --quiet firewalld.service`（与 `wg.sh:913` 同一判据）
   - **iptables 分支且端口有变化** → `systemctl restart wg-iptables.service`
   - **firewalld 分支且端口有变化** → `firewall-cmd --remove-port=<旧>/udp` 及其 `--permanent` 版本，再 `--add-port=<新>/udp` 及 `--permanent` 版本。**不调 `--reload`** —— reload 会打断 `wg-quick` 已装入的规则
   - 最后 `systemctl restart wg-quick@wg0`

   > v1 在此无条件 restart `wg-iptables.service`。该 unit 在 firewalld 机器上根本不存在（`create_firewall_rules` 的 if 分支不创建它），会让这类机器**永远改不了端口** —— 回滚逻辑把每次尝试都判为失败。
7. 步骤 3–6 任一失败 → 用步骤 2 快照恢复 → 再 restart 一次 → 返回 `400`/`500`，响应体带失败步骤
8. 成功后写 `/var/lib/wg-panel/state.json`：`redistributeNeeded: true`、变更时间、受影响 peer 数

第 8 步是核心，因为服务端改完不等于网络可用。面板顶部据此常驻横幅："服务器参数已变更，N 个客户端需要重新导入配置"。

**收敛判据用真实信号，不用人工确认。** v1 写的是"下载 `export.zip` 后由前端确认清除"，而前端发个请求就能清掉提醒，标记形同虚设。改为：持续对比每个 peer 的 `latestHandshake` 与变更时间戳 —— 握手时间**晚于**变更时间的 peer，说明确实拿到新配置并成功重连，视为已收敛。全部收敛则自动清除横幅；否则持续列出未收敛 peer 名单。这把"用户自己保证"的软约束变成可验证的事实。

## 9. 客户端配置生成与私钥落盘策略

- **面板创建的客户端不落盘。** 配置只在内存生成，经 `config`/`qr.png`/`export.zip` 三个认证接口返回，全带 `Cache-Control: no-store`。理由：私钥落盘等于多一个泄露面，而 `wg0.conf` 已完整保存服务器侧所需的一切。
- **面板删除 peer 时报告并清理孤儿配置文件。** 在 `get_export_dir`（`wg.sh:999-1011`）与 `/etc/wireguard/clients` 查找同名 `<name>.conf`；找到则删除并写审计日志，找不到则只记不报错。否则磁盘上留下一个含明文私钥、对应 peer 却已不存在的文件 —— 那比从不落盘更糟。

  **但家目录这一路径面板实际够不到**，这是设计与设计之间的冲突：12.2 的 `ProtectHome=yes` 会让服务进程里的 `/home` 看起来是空的，所以面板**无法删除** `/home/ubuntu/233.conf` 这类文件。取舍是**保留 `ProtectHome=yes`**（不给一个 root HTTP 服务开全部家目录的读权限，代价远小于省下的几次 `rm`），因此清理动作降级为：

  - 面板检测：读 `wg0.conf` 里 peer 名与 `/etc/wireguard/` 下自己可见的路径，把"该客户端配置可能仍留在 `<推测路径>/<name>.conf`"作为**待办提示**显示在删除成功页，并给出可直接复制的 `sudo rm -f <path>` 命令
  - 不谎报"已清理"。文案必须是"请在服务器上执行以下命令删除含私钥的配置文件"
  - `/etc/wireguard/clients/`（若将来改用该目录）面板有写权限，可以真删 —— 只有家目录这条路径是只报告不执行

  顺带一个真实权限事实：`/home/ubuntu` 是 `drwxr-x---`、属主 `ubuntu`，而现网那份 `233.conf`（`0600`，内含明文 `PrivateKey`，对应正在使用的 peer `233`）就在这里 —— 所以"只报告不执行"不是理论上的退让，是唯一可行的方案。
- `wg.sh` 现有的家目录导出行为保持不变（装机后需要有个能直接扫的东西），但 README 增一行提示：配置含私钥，导入设备后请删除服务器上的 `~/<name>.conf`。更进一步，`wg.sh` 在导出成功后**应主动打印这条删除命令**，而不是只写在文档里。

## 10. API 与鉴权

### 接口

```
POST   /api/login                        {username,password} -> Set-Cookie
POST   /api/logout
GET    /api/session                      -> {authenticated, mustChangePassword}
PUT    /api/password                     {oldPassword,newPassword}

GET    /api/server                       -> {installed,endpoint,listenPort,mtu,subnetV4,subnetV6,serverPublicKey,peersTotal,firewallBackend}
PUT    /api/server/endpoint              {listenPort,endpoint,mtu}   # 第 8 节流程
GET    /api/redistribution               -> {needed,changedAt,pendingPeers[]}
GET    /api/status                       -> [{name,publicKey,latestHandshake,endpoint,transferRx,transferTx}]

GET    /api/clients                      -> [{name,ipV4,ipV6,publicKey,dnsKnown}]   # 不含 PSK
POST   /api/clients                      {name,dns[],dnsCustom?} -> {name,ipV4,config}
DELETE /api/clients/{name}
POST   /api/clients/{name}/rotate-key    -> {name,config}
GET    /api/clients/{name}/config        -> text/plain，Content-Disposition: attachment
GET    /api/clients/{name}/qr.png        -> image/png
GET    /api/clients/export.zip           -> 全部客户端 .conf 打包
GET    /api/version                      -> {version,commit,buildTime}
```

`/api/redistribution` 只读；标记由第 8 步写入、由收敛判据自动清除，**不提供人工清除接口**（否则回到 v1 的软约束）。

客户端 DNS 入参校验：每个地址须为合法 IPv4 或 IPv6；预设列表沿用 `select_dns`（`wg.sh:1013-1063`）的选项集合，面板复刻该列表并提供"自定义"输入。不接受主机名（客户端配置的 `DNS` 必须是地址）。

### 安全控制

- 凭据 `/etc/wg-panel/credentials.json`（`0600`），argon2id（`m=64MiB,t=3,p=2`）+ 随机 salt
- 首启无凭据：生成 20 位随机密码打印到 stdout **一次**，置 `mustChangePassword`，前端强制跳转改密
- Session：`HttpOnly` + `SameSite=Strict` cookie，12h，服务端内存表 + 空闲回收；进程重启使全部会话失效（可接受）
- CSRF：`SameSite=Strict` 为主，辅以非 GET 必须携带自定义头 `X-Requested-With: wg-panel`；不放任何 CORS 规则，跨源脚本过不了预检
- 防爆破：同 IP 连续 5 次失败后指数退避（5s → 15s → 60s → 5min）
- 默认 `--listen 127.0.0.1:8734`。**不用 8080** —— 实测目标机上 `docker-proxy` 已把 `0.0.0.0:8080` 绑走（`hayden-backend` 发布的），面板会以 `bind: address already in use` 启动失败。`8734` 经 `ss -lntu` 确认空闲。端口冲突时面板必须打印"端口被 `<进程名>` 占用"并以非零码退出，而不是静默换端口 —— 那样用户下次 `ssh -L` 会转错地方
- 若 `--listen` 指向非回环地址且未提供 `--tls-cert/--tls-key`，**启动即失败**，除非显式 `--allow-insecure`；错误信息直接给出 `ssh -L 8734:127.0.0.1:8734 <host>` 用法
- 敏感数据边界：`PrivateKey` 与 `PresharedKey` 不出现在任何列表/详情接口响应体；仅在 `config`/`qr.png`/`export.zip` 三个明确导出接口返回，带 `no-store` 且不写访问日志
- **`status` 包的一条硬约束（2026-09-20 采集 fixture 时踩出来的雷）**：`wg show <iface> dump` 的列序里，接口行第 2 列是**明文 private key**、peer 行第 2 列是**明文 preshared key** —— 与 `wg show <iface>` 的 `(hidden)` 行为完全不同。`dump` 制表符分隔、比人类可读输出好解析，实现时几乎一定会想用它，因此必须写死：使用 `dump` 时**显式丢弃第 2 列**再进结构体，且任何情况下都不得把 `dump` 的原始输出写进日志、错误信息、API 响应或 `/api/status`。单测必须覆盖"`dump` 输入 → 响应体不含密钥"这条断言（见 13.1）
- 名称校验：`^[A-Za-z0-9_-]{1,15}$`。**合法字符集**与 `set_client_name`（`wg.sh:159-163`）一致，处理方式刻意更严 —— `wg.sh` 静默把非法字符替换为 `_` 并截断到 15 字符，面板直接 `400` 拒绝。GUI 下静默改名会让用户导入一个与输入不同的 peer。副作用是面板产出的名称必然是 `wg.sh` 也认可的合法值，两个入口可互相管理

## 11. 错误处理

- 统一 `{"error":{"code":"...","message":"..."}}`。状态码：校验失败 `400`、未认证 `401`、名称冲突/子网耗尽/解析降级 `409`、`wg0.conf` 不存在 `503`、内部失败 `500`
- `wg0.conf` 不存在 → 前端展示引导页，给出安装命令 `curl -o wg.sh <url> && sudo bash wg.sh --auto --serveraddr <公网IP>`，而非空白报错
- 命令失败时 stderr 原文进服务端日志，响应体只回分类错误码 —— 不把 iptables/systemctl 输出泄漏到前端
- 持锁期间进程被杀：`flock` 由内核随进程释放，不遗留死锁；写入走 temp + rename，不会留下半截配置
- 前端对 `POST/DELETE` 做乐观更新失败回滚，并在列表顶部展示最近一次操作结果

### 11.1 `wg0.conf` 解析失败时的只读降级模式

v1 只定义了"文件不存在"，漏了"文件存在但读不懂"（被人手改坏、上游格式变化）。这个状态下若允许写，一次"改端口"就会把部分有效内容覆盖成面板脑补的默认结构，**把一个语法错误放大成配置丢失**。

处置：启动时与每次写操作前都做完整解析。失败则进入只读降级模式 —— 所有写接口返回 `409 config_unparseable` 并**绝不写回**；`GET /api/clients` 返回原文（截断 4KB）供人工定位；页面明示"面板已停止写入，`wg.sh` 菜单仍可使用"。降级模式不阻止用户用 `wg.sh` 修复，两者不互斥。

## 12. 面板部署与运维

### 12.1 必须承认的安全事实

**面板是一个以 root 运行、且能执行 `wg` 与 `systemctl` 的网络服务。** 它的安全边界只有 HTTP 层鉴权和 localhost 监听。一旦被攻破（任意 handler 存在路径穿越或参数注入），整台机器即失守。因此三条硬约束：

1. **不接受任何路径输入，不做任何 shell 字符串拼接。** peer 名、endpoint、port、mtu 全部经白名单正则校验后，作为 `exec.Command` 的独立 argv 元素传递 —— 绝不经过 `sh -c`
2. **保持默认 localhost。** `--allow-insecure` 的后果在启动时二次确认，并在页面常驻显示"当前无 TLS 且监听公网"警告
3. **面板无任何出站网络请求** —— 不检查更新、不上报使用、不拉远端配置。4.2 那种"检测握手情况"是本地 `wg show`，不是外部探测。这条同时压缩供应链面与云主机出流量

### 12.2 systemd unit（`deploy/wg-panel.service`）

```
[Service]
Type=simple
ExecStart=/usr/local/bin/wg-panel
Restart=on-failure
RestartSec=3
User=root
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/etc/wireguard /var/lib/wg-panel /etc/wg-panel /var/backups/wg-panel
```

`ProtectSystem=strict` 是这里唯一可行的折衷：面板不能降权（要写 `/etc/wireguard`、要控制 systemd），但可以把写范围限制到四个目录。`ProtectHome=yes` 顺带挡住读取 `wg.sh` 导出到用户家目录的那些 `.conf` —— 代价是面板删不掉它们，第 9 节已就此把清理动作明确降级为"只报告不执行"，这是有意的取舍而非疏漏。

### 12.3 日志与审计

标准库 `log/slog`，JSON，输出 stdout 交 journald（自带轮转，不引入外部日志库）。审计记录 `peer add/remove/rotate-key`、`endpoint change`、`login ok/fail`、`password change`，字段 `{ts, actor, action, target, result, remote}`。三类导出接口只记 `action=export target=<name>`，不记响应体。

`endpoint change` 记录旧端口与新端口，这也是 D4 里"卸载时取全部曾用端口"的数据来源。

### 12.4 目标机（现网）首次部署顺序

**这台机器上 WG 已装好且正在使用**，所以顺序与空白机不同 —— 跳过第 3 步，不做重装。

1. 腾讯云控制台 → CVM **安全组** → 确认已放行当前 WG 端口（现网为 `UDP 53`）。若尚未放行，先加规则再动主机 —— 注意这一步在云侧，与 `wg.sh` 无关，脚本做不了
2. 顺手收口：把 `3306 / 6379 / 9000 / 9001 / 8080 / 3000` 从安全组里删掉（4.6 的现网暴露，用户当前选择暂不处理，但 README 要写）
3. ~~`sudo bash wg.sh`~~ —— **不要在现网跑装机流程**。它会 `restart wg-quick@wg0`，正在用的隧道会掉线；`233` 这个唯一 peer 需要手机端重连。修复版 `wg.sh` 的验证放到阶段 1 的专门窗口，并提前告知会断线
4. 上传 `wg-panel` 二进制与 unit，`systemctl enable --now wg-panel`（监听 `127.0.0.1:8734`，与 `docker-proxy` 的 8080 无冲突）
5. 本机 `ssh -L 8734:127.0.0.1:8734 ubuntu@49.233.166.212`，浏览器开 `http://127.0.0.1:8734`，初始密码见 `journalctl -u wg-panel`
6. 面板首次读取现网 `wg0.conf`（`ListenPort = 53`、单 peer `233`、无 `# DNS` 行）→ 应正确列出 `233` 且 `dnsKnown=false`

空白机的标准顺序仍然是：安全组放行 → `curl` 拉脚本 → `sudo bash wg.sh --auto --serveraddr <公网IP> --port <实测空闲端口>` → 装面板 → SSH 转发访问。

## 13. 测试策略

### 13.1 可自动化覆盖（本机 Windows 即可运行）

| 包 | 测试内容 |
|---|---|
| `wgconf` | **golden 往返**：读入 `fixtures/` 中 `wg.sh` 真实产物（含 IPv6 / 不含 IPv6 两份，后者是 4.4 的主场景），解析→写出，断言字节完全相同；再断言增、删、改端口、改 endpoint、改 MTU 后重解析正确，且标记行仍匹配 `wg.sh` 的 sed 模式；缺 `# DNS` 行的存量 peer 走 7.2 回落分支 |
| `keygen` | 纯 Go curve25519 输出与 `wg genkey`/`wg pubkey` 产物格式一致（base64 可解码、解码后 32 字节） |
| `status` | 多份 `wg show` fixture：从未握手的 peer、endpoint 带 IPv6 方括号、空接口；**以及一条安全断言：喂入 `wg show dump` 制式的输入（第 2 列含明文私钥/PSK）后，解析结果与任何序列化输出中都不出现该密钥串** |
| `firewall` | 两个分支各自的命令序列正确性（含"不加 `--reload`"这条断言） |
| `api` | `httptest` + fake `apply.Runner`，覆盖登录、CRUD、权限、错误码映射、降级模式拒绝写入；测试内不外呼真实命令 |

### 13.2 本地无法验证（必须承认的边界）

`wg syncconf`、`systemctl restart`、iptables/firewalld 变更都依赖 Linux 内核 WG 模块。开发机是 Windows，这些路径本地跑不了。

处理：所有真实生效动作收敛到 `apply.Runner` 接口后，单测注入 fake —— **逻辑分支可测，实际效果不可测**。实际效果以第 16 节为准，逐条在 VPS 上勾，不以"代码写完"当作"功能可用"。

### 13.3 `fixtures/` 的来源与脱敏要求

v2 把这件事当成阻塞项（"Windows 上跑不了 `wg.sh`，得先去 VPS 采"）。**实机核查已经把这条路打通了**：目标机上就有一份现成的真实产物 —— `/etc/wireguard/wg0.conf`（`ListenPort = 53`、单 peer `233`、无 IPv6 段、含 `# ENDPOINT 49.233.166.212` 与 `# 请勿修改以下注释行` 头部），以及对应的 `wg show wg0` 文本输出。两者结构上都已在本轮核查中确认。

**硬约束：fixture 必须脱敏，绝不能把现网的真实密钥提交进仓库。**

现网 `wg0.conf` 权限是 `-rw------- root:root`，里面有真实的服务器 `PrivateKey` 与 peer `PresharedKey`。这条隧道正在被实际使用，密钥泄露等于任何人都能解密/冒充。因此：

- 入库前把 `PrivateKey` / `PresharedKey` 的值替换为**固定测试向量**（合法 base64、32 字节，但明确不是任何真实密钥），并在文件头加一行 `# TEST FIXTURE ONLY — keys are synthetic`
- 公钥也一并替换成与合成私钥配对的值，保证 `keygen` 与解析测试用的是自洽数据
- 客户端真实出口 IP/端口（`wg show` 里的 `endpoint:` 字段，即设备所在网络的公网地址）一律替换为占位值。**这条同样适用于本 spec 之外的所有文档与 README**
- 仓库根 `.gitignore` 加 `fixtures/raw/`，任何未脱敏的原始采集**不得进入 git**；`git init` 之前就配好
- 成功标准新增一条：仓库内 grep 不到任何与现网 `wg0.conf` 相同的密钥字符串，也 grep 不到客户端的真实出口 IP
- **本文件自身也要过这条线**：`49.233.166.212` 是服务器自己的地址、出现在部署说明里必要，可以保留；但客户端侧的出口 IP 不写。仓库若按 README 那样公开，任何真实密钥、客户端 IP 都等于公开

至于"含 IPv6"的第二份 fixture，现网没有（4.4 已确认无全局 IPv6）。改为**按 `wg.sh:902` 与 `wg.sh:1122` 的模板手工合成**一份含 `fddd:2c4:2c4:2c4::` 段的样本，并在注释里标明它是合成而非实采 —— 它只用于验证解析分支，不需要来自真机。

`127.0.0.1:8734` 之类端口信息在 fixture 里同样用占位值。

## 14. 分阶段实施

0. **前置动作（新增，因实机核查而必须）** —— `git init` + `.gitignore`（含 `fixtures/raw/`）；在现网安全组确认 `UDP 53` 已放行；采集并脱敏 fixture。**D1 的"保住端口放行"三条硬约束（见 3.D1 末尾）必须在这一阶段完成验证，因为它决定后面敢不敢删那两行 `iptables`**
1. **`wg.sh` 修复** — D1、D2、D3、D4、D5。纯 bash，交付即有价值（不再破坏云主机 DNS），可独立上线
2. **Go 骨架 + `wgconf`** — 解析器与 golden 往返测试。整个面板的地基，必须先绿
3. **只读面板** — `auth` + `/api/server`、`/api/clients`、`/api/status` + 前端列表页。不改任何系统状态，可在生产机安全部署。**在现网上这一步是首选落地点**：只读、能立刻验证解析器对 `ListenPort = 53` + 单 peer + 无 IPv6 这份真实配置是否正确
4. **写操作** — `keygen` + peer 增删改 + `firewall`/`apply` + `flock` + QR/配置导出 + 审计。VPS 验收第一轮
5. **变更类操作** — 第 8 节全流程（端口/endpoint/MTU）+ 握手收敛判据 + `export.zip`。VPS 验收第二轮。**注意在现网做这一阶段会主动掐断在用隧道**，需要单独安排窗口
6. **`wg.sh` 与面板对齐** — `# DNS` 注释行写入、性能项落地（5.2–5.5）、面板与菜单并存一致性复查；另修一处阶段 1 发现的标签错位：`select_dns` 中注释写 `Cloudflare DNS（1.1.1.1, 1.0.0.1）` 而实际赋值是 `dns="223.5.5.5"`（阿里 DNS）。面板第 10 节要复刻这个预设列表，标签不改就会把错的说明抄过去
7. **性能验收** — 按 5.7 做前后对比并记录数据；无对比数据则该项视为未完成

本 spec 是八个阶段的整体蓝图，但**实现计划按阶段各写一份**。理由：阶段 0 与 1 交付后就能独立产生价值，而阶段 4、5、7 的验收依赖在现网动手（会断线），把纯 bash 修复和它们排在一份计划里，会让前面的可交付成果被后面的验证瓶颈拖住。**下一份实现计划覆盖阶段 0、1、2。**

阶段 2 的 fixture 依赖已由阶段 0 消解（13.3），两者现在在同一份计划里按顺序排。`git init` 亦已在阶段 0 完成，本 spec 与各阶段改动均已入库。

## 15. 明确不做

- WG 本体的安装/卸载向导搬进面板（面板只检测并引导去跑 `wg.sh`）
- 备份恢复的 UI（第 8 步已自动落磁盘备份；恢复属人工操作，做成 UI 反而容易误触）
- 多用户、权限分级（单管理员 + localhost 已是足够的安全模型）
- 客户端到期时间、流量配额（`wg` 内核不提供持久化计数，要做就得引入外部记账，另一个项目量级）
- UDP-over-TCP 混淆、AmneziaWG 适配（见 4.5：换端口只对按端口/协议号过滤有效，对协议特征识别无效）
- 突破云侧带宽上限的任何尝试（4.1：做不到）
- 自动 MTU 探测（需主动打流量，不适合放进管理面板；改成 5.3 的人工三档选择）
- CI/shellcheck 门禁、覆盖率要求

## 16. 成功标准

装机类（`wg.sh`）：

1. `curl -o wg.sh ... && sudo bash wg.sh` 在 Ubuntu 22.04/24.04、Debian 12、AlmaLinux/Rocky/CentOS Stream 9 干净实例上一次成功。RHEL 系需 `nftables.service` 未启用，否则 `check_nftables`（`wg.sh:354-361`）主动拒绝 —— 既有设计，不在修改范围
2. 在**干净实例**上先往 `resolved.conf` 写一个哨兵注释行，跑完脚本后该文件与 `/etc/resolv.conf` **字节完全未变**，且 `resolvectl dns` 的每链路地址仍是 DHCP 下发的那组（目标机实测为 `eth0: 183.60.83.19 183.60.82.98`），`getent hosts mirrors.tencentyun.com` 解析成功（验证 D1）。现网那台机器的 `resolved.conf` **已经是 0 字节**，无法再做这个对比，所以此条只能在干净实例或其它主机上验
3. 在容器或不支持的系统上 `sudo bash wg.sh`，报错退出后系统文件均未被改动（验证 D1 删除顶层块的效果，本次最重要的回归项）
4. 不同目录连续运行两次，行为一致，不再产生 `wg.txt`（验证 D1）
5. firewalld 系统上 `/etc/rc.local` 不含 `wg-iptables.service` 字样（验证 D4）

面板类：

6. 面板列出 `wg.sh` 装出的全部存量客户端，含第一个客户端，无遗漏无乱码；对无 `# DNS` 行的存量 peer，`dnsKnown=false` 且导出界面明示
7. 面板新增客户端可被手机官方 App 扫码连上，隧道内 `ping 10.7.0.1` 与外网访问正常
8. 面板删除客户端后 `wg show wg0` 中该 peer 立即消失（验证 D2），且家目录同名 `.conf` 被一并删除（验证第 9 节）
9. 面板改端口后：`ss -lun` 显示新端口、旧端口放行规则已被替换（**iptables 与 firewalld 两种系统分别验证**）、横幅出现、`export.zip` 内所有 `Endpoint` 为新端口
10. 面板只改 `endpoint`（不动端口）时不因端口占用检查而失败，且不重启 `wg-iptables.service`
11. 改端口后，未重新导入的 peer 其 `latestHandshake` 停在旧值、横幅持续列出它；重新导入并握手成功后横幅自动消失（验证第 8 节收敛判据）
12. 手工把 `wg0.conf` 改坏（删掉一个 `# END_PEER`），面板进入只读降级、写接口全 `409`、文件未被再次写入；用 `wg.sh` 修复后面板自动恢复可写（验证 11.1）
13. `wg.sh` 交互菜单在面板存在时全部可用；其新增客户端立即被面板列出，面板新增客户端可被 `wg.sh --removeclient` 删除（验证 7.1 原样写回）
14. 默认监听下从公网直接访问面板端口失败；未登录时任何写操作 `401`；`GET /api/clients` 响应体不含 `PrivateKey`/`PresharedKey` 字符串
15. 轻量控制台防火墙未放行时，面板在"所有 peer 从未握手"状态下显示定向防火墙提示，而非笼统报错（验证 4.2）

性能类（需 5.7 的对比数据，无数据视为未达成）：

16. MSS clamping 生效后，隧道内 `ping -M do -s 1400` 不再出现"小包通、大包卡死"；`iptables -S FORWARD` 含 `TCPMSS --clamp-mss-to-pmtu`
17. `conntrack -S` 与 `wc -l /proc/net/nf_conntrack` 显示表项远低于新上限，且满载复制过程中不再出现突发速率塌陷
18. 同一客户端同时段 `iperf3 -u` 前后对比：峰值带宽利用率提升有实测数字支撑

自动化与安全：

19. 13.1 节五类测试全部通过
20. **D1 删除后隧道不能断**：在现网（WG 跑在 `UDP 53`）删除那两行 `--dport 53 ACCEPT` 之后，`iptables -S INPUT` 里仍有一条由 `wg-iptables.service` 提供、覆盖 `ListenPort` 的 udp 放行规则，且 `wg show wg0 latest handshake` 在删除操作后仍能刷新（手机侧无需任何动作）。**这是本次唯一一条"做错就直接把用户现网搞挂"的标准，必须最先验**
21. 面板启动时若 `8734` 被占用，进程以非零码退出并打印占用者进程名，不自动改用其它端口
22. 仓库全文（含 fixture、本 spec、README）grep 不到现网 `wg0.conf` 中的任何 `PrivateKey`/`PresharedKey`/`PublicKey` 值，也 grep 不到客户端侧的真实出口 IP（13.3）
23. `firewallBackend` 字段在现网如实报告"存在 ufw + 1Panel(`YJ-FIREWALL-INPUT`) + Docker 规则"这一事实，而不是只回 `iptables`

## 17. v2 → v3 修订对照

2026-09-20 用只读 SSH 命令核查目标服务器后，以下 v2 判断被推翻或补强。记录在此是为了让后来人知道每条结论的证据来源，而不只是结论。

| # | v2 的说法 | 实测 | 落到 spec 的位置 |
|---|---|---|---|
| 1 | 机型是腾讯云**轻量**应用服务器 | `product_name=CVM`，4 核 / 3 GB，主机名 `VM-0-15-ubuntu` | 第 2 节决策表、4.2、12.4 |
| 2 | 内网 DNS 是 `100.100.2.136/138` | 实际是 DHCP 每链路 `183.60.83.19/183.60.82.98` | 3.D1、4.6、7.2 示例、16 条 2 |
| 3 | 推荐大陆节点改用 `UDP 443` | UDP 443 被 openresty 的 4 个 QUIC worker 占满，改上去会起不来 | **撤销推荐**，改为强制 `ss` 实测（4.5） |
| 4 | 面板默认监听 `127.0.0.1:8080` | `0.0.0.0:8080` 已被 `docker-proxy`（后端容器）绑走 | 改 `8734`（第 10 节、16 条 21） |
| 5 | 防火墙有 iptables / firewalld **两个分支** | 实为**四个写入方**：iptables-nft + ufw + 1Panel `YJ-FIREWALL-INPUT` + Docker 27 条；`wg-iptables` 的 `-I` 插队已看不到 | 4.6 新增小节、`firewall` 包职责、16 条 23 |
| 6 | "轻量 1–2 核，无并行度"故不做绑核 | 4 核，且腾讯云 qcloud agent 已在跑 `set_rps.sh`/`set_xps.sh`/`net_smp_affinity.sh` | 5.6 换理由、保留结论 |
| 7 | `nf_conntrack_max` "可能只有数万条"（推测） | 实测**正好 65536**，当前 200 表项 | 5.4 由推测改为实测佐证 |
| 8 | 假设 IPv6 分支需要覆盖但不确定 | `ip -6 addr scope global` 为空，`wg0.conf` 无 `fddd::` 段 → 无 IPv6 是**主场景** | 4.4、13.1、13.3 |
| 9 | B1 的破坏是"读代码推断出来的" | 已发生：`resolved.conf` 与 `.bak` **均 0 字节**，时间戳为脚本执行当天 | 3.D1 改为实机证据 |
| 10 | 客户端 DNS 丢失是"理论后果" | 现网 `233.conf` 的 `DNS = 223.5.5.5` 在 `wg0.conf` 里确实无痕迹 | 7.2 加实证 |
| 11 | 孤儿私钥文件是假想风险 | `/home/ubuntu/233.conf` 真实存在，`0600 ubuntu:ubuntu` | 第 9 节 |
| 12 | 面板与 `wg.sh` 争抢写入靠 `flock` 解决 | 家目录 `drwxr-x---` + `ProtectHome=yes` → 面板**根本删不到**家目录配置 | 第 9 节降级为"只报告不执行" |
| **13** | **（新发现，v2 完全没有）删 DNS 逻辑会连带删掉 WG 的端口放行** | `wg.sh:28/40` 那两行 `--dport 53 ACCEPT` 名义上是 DNS，实际正是 WG 跑在 53 时的 INPUT 放行；`-P INPUT DROP` 下删了隧道就断 | **3.D1 新增三条硬约束 + 16 条 20** |

第 13 条是这批修订里唯一会**直接搞挂现网**的，也是纯读代码永远发现不了的 —— 它依赖"这台机器的 WG 恰好在 53 上"和"这台机器的 INPUT 默认 DROP"两个巧合叠加。
