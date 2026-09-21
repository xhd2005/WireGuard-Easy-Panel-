package status

import (
	"fmt"
	"strconv"
	"strings"
)

// DeviceStatus 表示 WireGuard 接口及其全部 peer 的运行态信息。
// 字段中刻意不定义 PrivateKey 或 PresharedKey，从结构体级别消除泄漏可能。
type DeviceStatus struct {
	Interface       string       `json:"interface"`
	PublicKey       string       `json:"publicKey"`
	ListenPort      int          `json:"listenPort"`
	Peers           []PeerStatus `json:"peers"`
	AllNeverHandshake bool       `json:"allNeverHandshake"` // 所有 peer 从未握手（用于 4.2 防火墙告警）
}

// PeerStatus 描述单个 peer 的在线与流量状态。
type PeerStatus struct {
	PublicKey       string   `json:"publicKey"`
	Endpoint        string   `json:"endpoint"`        // 可为空或 "(none)"
	AllowedIPs      []string `json:"allowedIPs"`
	LatestHandshake string   `json:"latestHandshake"` // 人类可读串，如 "12 seconds ago" 或 "(never)"
	HandshakeTime   int64    `json:"handshakeTime"`   // Unix 秒时间戳（若能解析）
	HasHandshook    bool     `json:"hasHandshook"`
	TransferRx      string   `json:"transferRx"`      // 人类可读格式，如 "361.72 MiB"
	TransferTx      string   `json:"transferTx"`
	TransferRxBytes int64    `json:"transferRxBytes"`
	TransferTxBytes int64    `json:"transferTxBytes"`
	RxSpeed         string   `json:"rxSpeed,omitempty"`    // 瞬时下行速率，如 "1.2 MB/s"
	TxSpeed         string   `json:"txSpeed,omitempty"`    // 瞬时上行速率，如 "340 KB/s"
	RxSpeedBytes    int64    `json:"rxSpeedBytes,omitempty"`
	TxSpeedBytes    int64    `json:"txSpeedBytes,omitempty"`
	TotalRx         string   `json:"totalRx,omitempty"`    // 历史持久化累计下行流量
	TotalTx         string   `json:"totalTx,omitempty"`    // 历史持久化累计上行流量
	TotalRxBytes    int64    `json:"totalRxBytes,omitempty"`
	TotalTxBytes    int64    `json:"totalTxBytes,omitempty"`
}

// ParseShow 解析 `wg show` 输出（支持人类可读格式以及 tab 分隔的 dump 格式）。
func ParseShow(raw string) (*DeviceStatus, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return &DeviceStatus{AllNeverHandshake: true}, nil
	}

	// 依据首行是否含制表符判断是 dump 格式还是普通人类可读格式
	firstLine := strings.SplitN(trimmed, "\n", 2)[0]
	if strings.Contains(firstLine, "\t") {
		return parseDump(trimmed)
	}
	return parseHuman(trimmed)
}

// parseHuman 解析 `wg show <iface>` 的标准输出。
func parseHuman(raw string) (*DeviceStatus, error) {
	st := &DeviceStatus{}
	lines := strings.Split(raw, "\n")

	var curPeer *PeerStatus
	flushPeer := func() {
		if curPeer != nil {
			curPeer.HasHandshook = isHandshook(curPeer.LatestHandshake)
			st.Peers = append(st.Peers, *curPeer)
			curPeer = nil
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "interface:") {
			flushPeer()
			st.Interface = strings.TrimSpace(strings.TrimPrefix(trimmed, "interface:"))
			continue
		}
		if strings.HasPrefix(trimmed, "peer:") {
			flushPeer()
			curPeer = &PeerStatus{
				PublicKey: strings.TrimSpace(strings.TrimPrefix(trimmed, "peer:")),
			}
			continue
		}

		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		if curPeer == nil {
			// Interface 属性
			switch key {
			case "public key":
				st.PublicKey = val
			case "listening port":
				if n, err := strconv.Atoi(val); err == nil {
					st.ListenPort = n
				}
			}
		} else {
			// Peer 属性
			switch key {
			case "endpoint":
				if val != "(none)" {
					curPeer.Endpoint = val
				}
			case "allowed ips":
				for _, ip := range strings.Split(val, ",") {
					if t := strings.TrimSpace(ip); t != "" {
						curPeer.AllowedIPs = append(curPeer.AllowedIPs, t)
					}
				}
			case "latest handshake":
				curPeer.LatestHandshake = val
			case "transfer":
				rxStr, txStr, rxBytes, txBytes := parseHumanTransfer(val)
				curPeer.TransferRx = rxStr
				curPeer.TransferTx = txStr
				curPeer.TransferRxBytes = rxBytes
				curPeer.TransferTxBytes = txBytes
			}
		}
	}
	flushPeer()
	checkAllNever(st)
	return st, nil
}

// parseDump 解析 `wg show <iface> dump` 的 tab 分隔输出。
//
// ⚠️ 极其关键的安全约束（spec 10 / 13.1）：
// 接口行第 2 列是明文 PrivateKey，peer 行第 2 列是明文 PresharedKey！
// 此函数必须显式丢弃第 2 列，绝不读入、绝不存盘、绝不在返回值中出现！
func parseDump(raw string) (*DeviceStatus, error) {
	st := &DeviceStatus{}
	lines := strings.Split(raw, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		if i == 0 {
			// 接口行: if_name \t private_key \t public_key \t listen_port \t fwmark
			// cols[0] = if_name
			// cols[1] = private_key (🔥 必须直接丢弃！)
			// cols[2] = public_key
			// cols[3] = listen_port
			if len(cols) >= 4 {
				st.Interface = cols[0]
				st.PublicKey = cols[2]
				if n, err := strconv.Atoi(cols[3]); err == nil {
					st.ListenPort = n
				}
			}
			continue
		}

		// peer 行: public_key \t preshared_key \t endpoint \t allowed_ips \t latest_handshake \t transfer_rx \t transfer_tx \t persistent_keepalive
		// cols[0] = public_key
		// cols[1] = preshared_key (🔥 必须直接丢弃！)
		// cols[2] = endpoint
		// cols[3] = allowed_ips
		// cols[4] = latest_handshake (unix timestamp)
		// cols[5] = transfer_rx (bytes)
		// cols[6] = transfer_tx (bytes)
		if len(cols) >= 7 {
			p := PeerStatus{
				PublicKey: cols[0],
			}
			if cols[2] != "(none)" && cols[2] != "" {
				p.Endpoint = cols[2]
			}
			for _, ip := range strings.Split(cols[3], ",") {
				if t := strings.TrimSpace(ip); t != "" {
					p.AllowedIPs = append(p.AllowedIPs, t)
				}
			}
			if hs, err := strconv.ParseInt(cols[4], 10, 64); err == nil {
				p.HandshakeTime = hs
				if hs > 0 {
					p.HasHandshook = true
					p.LatestHandshake = fmt.Sprintf("%d (unix)", hs)
				} else {
					p.LatestHandshake = "(never)"
				}
			} else {
				p.LatestHandshake = cols[4]
			}
			if rx, err := strconv.ParseInt(cols[5], 10, 64); err == nil {
				p.TransferRxBytes = rx
				p.TransferRx = formatBytes(rx)
			}
			if tx, err := strconv.ParseInt(cols[6], 10, 64); err == nil {
				p.TransferTxBytes = tx
				p.TransferTx = formatBytes(tx)
			}
			st.Peers = append(st.Peers, p)
		}
	}
	checkAllNever(st)
	return st, nil
}

func checkAllNever(st *DeviceStatus) {
	if len(st.Peers) == 0 {
		st.AllNeverHandshake = true
		return
	}
	for _, p := range st.Peers {
		if p.HasHandshook {
			st.AllNeverHandshake = false
			return
		}
	}
	st.AllNeverHandshake = true
}

func isHandshook(hs string) bool {
	if hs == "" || hs == "(never)" || hs == "0" {
		return false
	}
	return true
}

// parseHumanTransfer 解析如 "361.72 MiB received, 3.66 GiB sent"
func parseHumanTransfer(val string) (rxStr, txStr string, rxBytes, txBytes int64) {
	parts := strings.Split(val, ",")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if strings.HasSuffix(trimmed, "received") {
			s := strings.TrimSpace(strings.TrimSuffix(trimmed, "received"))
			rxStr = s
			rxBytes = parseBytes(s)
		} else if strings.HasSuffix(trimmed, "sent") {
			s := strings.TrimSpace(strings.TrimSuffix(trimmed, "sent"))
			txStr = s
			txBytes = parseBytes(s)
		}
	}
	return
}

func parseBytes(s string) int64 {
	fields := strings.Fields(s)
	if len(fields) != 2 {
		return 0
	}
	val, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	unit := strings.ToLower(fields[1])
	switch unit {
	case "b":
		return int64(val)
	case "kib", "kb":
		return int64(val * 1024)
	case "mib", "mb":
		return int64(val * 1024 * 1024)
	case "gib", "gb":
		return int64(val * 1024 * 1024 * 1024)
	case "tib", "tb":
		return int64(val * 1024 * 1024 * 1024 * 1024)
	}
	return int64(val)
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	return fmt.Sprintf("%.2f %s", float64(b)/float64(div), units[exp])
}

// String 调试输出，绝不包含私钥
func (s *DeviceStatus) String() string {
	return fmt.Sprintf("DeviceStatus{iface=%s port=%d peers=%d allNever=%t}",
		s.Interface, s.ListenPort, len(s.Peers), s.AllNeverHandshake)
}

// String 调试输出，绝不包含私钥
func (p *PeerStatus) String() string {
	return fmt.Sprintf("PeerStatus{pub=%s endpoint=%s hs=%s rx=%s tx=%s}",
		p.PublicKey, p.Endpoint, p.LatestHandshake, p.TransferRx, p.TransferTx)
}
