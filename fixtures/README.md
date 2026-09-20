# fixtures/

golden 测试用的输入样本。`.gitattributes` 里对 `fixtures/**` 设了 `-text`，
禁止任何换行符转换 —— golden 往返要求字节完全一致。

## 样本清单

| 文件 | 内容 | 来源 |
|---|---|---|
| `wg0-no-ipv6.conf` | `wg.sh` 装机产物，`ListenPort = 53`、单 peer、无 IPv6 段 | 2026-09-20 从目标服务器实采，已脱敏 |
| `wg-show-single-peer.txt` | `wg show wg0` 的人类可读输出，含活跃 peer | 同上 |

**尚缺**（阶段 2 开工时补）：

- `wg0-ipv6.conf` —— 含 `fddd:2c4:2c4:2c4::` 段的变体。目标服务器没有全局 IPv6（spec 4.4），
  所以这份按 `wg.sh:902` 与 `wg.sh:1122` 的模板手工合成，并在文件头注明来源
- `wg-show-never-handshook.txt` —— `latest handshake: never` 与 `transfer: 0.00 KiB received, 0.00 KiB sent`
  的分支，用于验证 spec 4.2 的"从未握手 → 提示云侧防火墙"判定
- `wg-show-empty.txt` —— 接口在但零 peer

## 脱敏做法（为什么可以直接提交）

替换在**服务器上就地完成**，真实私钥从未落到本机磁盘或进入 git。替换值是用
`wg genkey` / `wg genpsk` 现生成的合法一次性密钥，因此：

- 格式与真实数据完全一致（base64、44 字符、解码后 32 字节），`keygen` 测试不会因
  为占位符长度不对而失真
- `wg0-no-ipv6.conf` 的 `PrivateKey` 与 `wg-show-single-peer.txt` 的 `public key`
  是**同一对**合成密钥，两个文件可以交叉引用
- `# ENDPOINT` 用 `203.0.51.10`、peer 出口用 `198.51.100.77`（RFC 5737 文档保留地址）
- peer 名改为 `testphone`，服务器 IP 与客户端真实出口 IP 均不出现

## ⚠️ 采集这类样本时的雷区：绝不要用 `wg show dump`

`wg show <iface>` 会用 `(hidden)` 屏蔽敏感字段，很容易让人以为 `dump` 也一样。
**它不一样。** `wg show <iface> dump` 按 man 页的列序：

```
接口行:  if_name \t private_key \t public_key \t listen_port \t fwmark
peer 行:  public_key \t preshared_key \t endpoint \t allowed_ips \t latest_handshake \t transfer_rx \t transfer_tx \t persistent_keepalive
```

**第二列就是明文私钥和明文 PSK。** 本轮采集时就是因为顺手加了 `dump`，把目标服务器的
真实私钥与 PSK 打进了输出（随即废弃，未入库）。

这条对面板实现是直接约束，见 spec 第 10 节"敏感数据边界"：`status` 包若为了好解析
而改用 `dump`，必须显式丢弃第 2 列，且任何情况下都不得把 dump 原始输出写进日志、
错误信息或 API 响应。
