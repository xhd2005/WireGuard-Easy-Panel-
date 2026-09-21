package clientconf

import (
	"fmt"
	"strings"
)

// Params 包含生成客户端 .conf 文件所需的完整参数。
type Params struct {
	ClientName       string
	ClientPrivateKey string
	ClientIPv4       string // 形如 "10.7.0.2/24"
	ClientIPv6       string // 形如 "fddd:2c4:2c4:2c4::2/64"，若无则为空
	DNS              []string
	ServerPublicKey  string
	PresharedKey     string
	ServerEndpoint   string // 形如 "49.233.166.212:53"
	MTU              int    // 若 > 0 则写入
}

// Generate 生成客户端标准 wireguard 配置文件内容。
func Generate(p Params) string {
	dnsStr := "183.60.83.19, 183.60.82.98"
	if len(p.DNS) > 0 {
		dnsStr = strings.Join(p.DNS, ", ")
	}

	addr := p.ClientIPv4
	if p.ClientIPv6 != "" {
		addr += ", " + p.ClientIPv6
	}

	var sb strings.Builder
	sb.WriteString("[Interface]\n")
	fmt.Fprintf(&sb, "Address = %s\n", addr)
	fmt.Fprintf(&sb, "DNS = %s\n", dnsStr)
	fmt.Fprintf(&sb, "PrivateKey = %s\n", p.ClientPrivateKey)
	if p.MTU > 0 {
		fmt.Fprintf(&sb, "MTU = %d\n", p.MTU)
	}

	sb.WriteString("\n[Peer]\n")
	fmt.Fprintf(&sb, "PublicKey = %s\n", p.ServerPublicKey)
	fmt.Fprintf(&sb, "PresharedKey = %s\n", p.PresharedKey)
	sb.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	fmt.Fprintf(&sb, "Endpoint = %s\n", p.ServerEndpoint)
	sb.WriteString("PersistentKeepalive = 25\n")

	return sb.String()
}
