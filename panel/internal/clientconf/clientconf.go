package clientconf

import (
	"fmt"
	"strings"
)

// RouteMode 定义客户端隧道的路由分流模式。
type RouteMode string

const (
	RouteModeFull   RouteMode = "full"   // 全局代理模式：所有公网与内网流量均走隧道
	RouteModeSplit  RouteMode = "split"  // 内网分流模式：仅组网虚拟子网走隧道，其余走本地高速宽带
	RouteModeCustom RouteMode = "custom" // 自定义网段路由
)

// DefaultPublicDNS 默认公共 DNS（中立、全球可用）。
var DefaultPublicDNS = []string{"1.1.1.1", "8.8.8.8"}

// Params 包含生成客户端 .conf 文件所需的完整参数。
type Params struct {
	ClientName       string
	ClientPrivateKey string
	ClientIPv4       string // 形如 "10.7.0.2/24"
	ClientIPv6       string // 形如 "fddd:2c4:2c4:2c4::2/64"，若无则为空
	DNS              []string
	ServerPublicKey  string
	PresharedKey     string
	ServerEndpoint   string // 形如 "203.0.113.1:51820"
	MTU              int    // 若 > 0 则写入
	RouteMode        RouteMode
	CustomAllowedIPs []string
	ServerSubnetV4   string // 形如 "10.7.0.0/24"
	ServerSubnetV6   string // 形如 "fddd:2c4:2c4:2c4::/64"
}

// Generate 生成客户端标准 wireguard 配置文件内容。
func Generate(p Params) string {
	dns := p.DNS
	if len(dns) == 0 {
		dns = DefaultPublicDNS
	}
	dnsStr := strings.Join(dns, ", ")

	addr := p.ClientIPv4
	if p.ClientIPv6 != "" {
		addr += ", " + p.ClientIPv6
	}

	var allowedIPs []string
	switch p.RouteMode {
	case RouteModeSplit:
		if p.ServerSubnetV4 != "" {
			allowedIPs = append(allowedIPs, p.ServerSubnetV4)
		} else {
			allowedIPs = append(allowedIPs, "10.7.0.0/24")
		}
		if p.ServerSubnetV6 != "" {
			allowedIPs = append(allowedIPs, p.ServerSubnetV6)
		}
	case RouteModeCustom:
		if len(p.CustomAllowedIPs) > 0 {
			allowedIPs = p.CustomAllowedIPs
		} else {
			allowedIPs = []string{"10.7.0.0/24"}
		}
	default: // RouteModeFull
		allowedIPs = []string{"0.0.0.0/0"}
		if p.ClientIPv6 != "" || p.ServerSubnetV6 != "" {
			allowedIPs = append(allowedIPs, "::/0")
		}
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
	fmt.Fprintf(&sb, "AllowedIPs = %s\n", strings.Join(allowedIPs, ", "))
	fmt.Fprintf(&sb, "Endpoint = %s\n", p.ServerEndpoint)
	sb.WriteString("PersistentKeepalive = 25\n")

	return sb.String()
}
