// Package wgconf 解析并改写 wg.sh 生成的 wg0.conf。
//
// 设计上有两条不可动摇的约束，其余实现细节都为它们服务：
//
//  1. 原样写回。未做修改时 Marshal() 必须与输入字节完全相同；有修改时只改动
//     目标行。wg.sh 的 update_wg_conf 依赖精确的 sed 区间
//     `/^# BEGIN_PEER x/,/^# END_PEER x/p`，任何格式漂移都会让 wg.sh 自己的
//     菜单坏掉。因此内部以 []string 保存原始行，编辑只替换命中的那一行。
//  2. 敏感字段不外传。PrivateKey / PresharedKey 会被解析出来供生成客户端配置，
//     但绝不出现在 String()、错误信息或任何日志里。
package wgconf

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	markerBegin     = "# BEGIN_PEER "
	markerEnd       = "# END_PEER "
	markerDNS       = "# DNS "
	markerEndpoint  = "# ENDPOINT "
	markerDisabled  = "# DISABLED"
	markerRouteMode = "# ROUTE_MODE "

	minClientOctet = 2
	maxClientOctet = 254
)

var (
	reSection     = regexp.MustCompile(`^\s*\[([A-Za-z]+)\]\s*$`)
	reKeySimple   = regexp.MustCompile(`(?i)^(\s*[A-Za-z][A-Za-z0-9_]*\s*=\s*)(.*?)(\s*)$`)
	reEndpoint    = regexp.MustCompile(`(?i)^(\s*# ENDPOINT[ \t]+)(.*?)([ \t]*)$`)
	// 与 wg.sh 的 check_ip / check_dns_name 等价
	reIPv4      = regexp.MustCompile(`^((\d{1,3})\.){3}(\d{1,3})$`)
	reFQDN      = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	reV4CIDR    = regexp.MustCompile(`^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/\d{1,2}$`)
	reKeyPrefix = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9_]*)\s*=`)
)

// Peer 是配置里一个 [Peer] 块。
type Peer struct {
	Name         string
	PublicKey    string
	PresharedKey string
	AllowedIPs   []string
	// DNS 来自 wg.sh 不生成的 "# DNS" 注释行（见 spec 7.2）。
	// DNSKnown=false 表示这个 peer 是存量数据、服务器端无从得知它当初选的 DNS，
	// 导出时必须明示"将使用默认值"，不能静默替换。
	DNS       []string
	DNSKnown  bool
	Disabled  bool   // 是否被标记禁用
	RouteMode string // 路由模式: "full" | "split" | "custom"
	blockLine int    // 文件内 0 基行号，-1 表示未定位
}

// IPv4Octet 返回该 peer 的 v4 末段（10.7.0.N 的 N），没有则 0。
// 无论 peer 是否被禁用，只要配置中预留了该 IP，就继续占位，防止 IP 碰撞。
func (p *Peer) IPv4Octet() int {
	for _, cidr := range p.AllowedIPs {
		m := reV4CIDR.FindStringSubmatch(strings.TrimSpace(cidr))
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[4])
		if err == nil && n >= minClientOctet && n <= maxClientOctet {
			return n
		}
	}
	return 0
}

// Server 是一份可改写的 wg0.conf。
type Server struct {
	Address    []string
	PrivateKey string
	ListenPort int
	MTU        int
	MTUSet     bool
	Endpoint   string
	Peers      []Peer

	lines   []string
	ifaceAt int // [Interface] 行号
}

// Parse 解析配置内容。任何结构性问题都返回 error —— 调用方据此进入
// 只读降级模式，绝不允许在"看不懂"的状态下写回（spec 11.1）。
func Parse(data []byte) (*Server, error) {
	if len(data) == 0 {
		return nil, errors.New("wgconf: 配置为空")
	}
	s := &Server{lines: strings.Split(string(data), "\n"), ifaceAt: -1}

	for i, ln := range s.lines {
		if m := reSection.FindStringSubmatch(ln); m != nil && strings.EqualFold(m[1], "Interface") {
			s.ifaceAt = i
			break
		}
	}
	if s.ifaceAt < 0 {
		return nil, errors.New("wgconf: 找不到 [Interface] 段")
	}
	if err := s.parseInterface(); err != nil {
		return nil, err
	}
	s.Endpoint = s.endpointValue()
	if err := s.refreshPeers(); err != nil {
		return nil, err
	}
	return s, nil
}

// Marshal 输出当前内容。未修改时与 Parse 的输入字节一致。
func (s *Server) Marshal() []byte {
	return []byte(strings.Join(s.lines, "\n"))
}

func (s *Server) parseInterface() error {
	end := s.interfaceEnd()
	seen := map[string]bool{}
	for i := s.ifaceAt + 1; i < end; i++ {
		k, v, ok := keyValue(s.lines[i])
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "address":
			s.Address = splitList(v)
			seen["address"] = true
		case "privatekey":
			if err := validKey(v, "PrivateKey"); err != nil {
				return err
			}
			s.PrivateKey = v
			seen["privatekey"] = true
		case "listenport":
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("wgconf: ListenPort 无效: %q", v)
			}
			s.ListenPort = n
			seen["listenport"] = true
		case "mtu":
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || n < 1280 || n > 65535 {
				return fmt.Errorf("wgconf: MTU 无效: %q", v)
			}
			s.MTU, s.MTUSet = n, true
		}
	}
	for _, req := range []string{"privatekey", "listenport"} {
		if !seen[req] {
			return fmt.Errorf("wgconf: [Interface] 缺少 %s", req)
		}
	}
	return nil
}

// interfaceEnd 返回 [Interface] 段的结束行号（下一个段首行，或第一个 peer 块，或 EOF）。
func (s *Server) interfaceEnd() int {
	for i := s.ifaceAt + 1; i < len(s.lines); i++ {
		ln := s.lines[i]
		if reSection.MatchString(ln) || strings.HasPrefix(strings.TrimSpace(ln), markerBegin) {
			return i
		}
	}
	return len(s.lines)
}

func (s *Server) endpointValue() string {
	for i := 0; i < s.ifaceAt; i++ {
		if m := reEndpoint.FindStringSubmatch(s.lines[i]); m != nil {
			return strings.TrimSpace(m[2])
		}
	}
	return ""
}

// refreshPeers 从 lines 重新扫描 peer 块。所有写操作后都调用它，
// 因此不存在"缓存的行号因插入/删除而失效"这类问题。
func (s *Server) refreshPeers() error {
	s.Peers = nil
	open := map[string]int{}
	for i := s.ifaceAt + 1; i < len(s.lines); i++ {
		trimmed := strings.TrimSpace(s.lines[i])
		switch {
		case strings.HasPrefix(trimmed, strings.TrimSpace(markerBegin)):
			name := strings.TrimSpace(trimmed[len(strings.TrimSpace(markerBegin)):])
			if err := validPeerName(name); err != nil {
				return err
			}
			if _, dup := open[name]; dup {
				return fmt.Errorf("wgconf: 重复的 BEGIN_PEER: %s", name)
			}
			if _, exists := s.findPeer(name); exists {
				return fmt.Errorf("wgconf: 重复的 peer 名: %s", name)
			}
			open[name] = i
		case strings.HasPrefix(trimmed, strings.TrimSpace(markerEnd)):
			name := strings.TrimSpace(trimmed[len(strings.TrimSpace(markerEnd)):])
			start, ok := open[name]
			if !ok {
				return fmt.Errorf("wgconf: 遇到 END_PEER %s 但没有对应的 BEGIN_PEER", name)
			}
			p, err := s.readPeer(name, start, i)
			if err != nil {
				return err
			}
			s.Peers = append(s.Peers, p)
			delete(open, name)
		}
	}
	if len(open) > 0 {
		names := make([]string, 0, len(open))
		for n := range open {
			names = append(names, n)
		}
		sort.Strings(names)
		return fmt.Errorf("wgconf: 以下 peer 缺少 END_PEER: %s", strings.Join(names, ", "))
	}
	return nil
}

func (s *Server) readPeer(name string, start, end int) (Peer, error) {
	p := Peer{Name: name, blockLine: start, RouteMode: "full"}
	seen := map[string]bool{}
	for i := start + 1; i < end; i++ {
		rawLine := s.lines[i]
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == markerDisabled {
			p.Disabled = true
			continue
		}
		if strings.HasPrefix(trimmed, markerRouteMode) {
			p.RouteMode = strings.TrimSpace(trimmed[len(markerRouteMode):])
			continue
		}
		if strings.HasPrefix(trimmed, markerDNS) {
			p.DNS = splitList(trimmed[len(markerDNS):])
			p.DNSKnown = true
			continue
		}

		// 若当前行带有 "# " 前缀，但内容是核心 Peer 配置（即禁用状态下的属性），剥离前缀解析
		line := rawLine
		if strings.HasPrefix(trimmed, "# ") {
			uncommented := strings.TrimSpace(trimmed[2:])
			if strings.HasPrefix(uncommented, "[Peer]") ||
				strings.HasPrefix(uncommented, "PublicKey") ||
				strings.HasPrefix(uncommented, "PresharedKey") ||
				strings.HasPrefix(uncommented, "AllowedIPs") {
				line = uncommented
			}
		}

		k, v, ok := keyValue(line)
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "publickey":
			if err := validKey(v, "PublicKey"); err != nil {
				return p, fmt.Errorf("peer %s: %w", name, err)
			}
			p.PublicKey = v
			seen["publickey"] = true
		case "presharedkey":
			if err := validKey(v, "PresharedKey"); err != nil {
				return p, fmt.Errorf("peer %s: %w", name, err)
			}
			p.PresharedKey = v
		case "allowedips":
			p.AllowedIPs = splitList(v)
			seen["allowedips"] = true
		}
	}
	if !seen["publickey"] {
		return p, fmt.Errorf("wgconf: peer %s 缺少 PublicKey", name)
	}
	if !seen["allowedips"] {
		return p, fmt.Errorf("wgconf: peer %s 缺少 AllowedIPs", name)
	}
	return p, nil
}

// findPeer 按名字返回 peer 下标。
func (s *Server) findPeer(name string) (Peer, bool) {
	for _, p := range s.Peers {
		if p.Name == name {
			return p, true
		}
	}
	return Peer{}, false
}

// HasPeer 报告同名 peer 是否已存在，供 API 做 409 判断。
func (s *Server) HasPeer(name string) bool { _, ok := s.findPeer(name); return ok }

// SetListenPort 只改 ListenPort 那一行，其余字节不动。
func (s *Server) SetListenPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("wgconf: 端口超出范围: %d", port)
	}
	if err := s.setIfaceKey("ListenPort", strconv.Itoa(port)); err != nil {
		return err
	}
	s.ListenPort = port
	return nil
}

// SetMTU 写入或更新 MTU 键；传 0 表示移除该行（回落到 wg-quick 默认）。
func (s *Server) SetMTU(mtu int) error {
	if mtu == 0 {
		return s.deleteIfaceKey("MTU")
	}
	if mtu < 1280 || mtu > 65535 {
		return fmt.Errorf("wgconf: MTU 超出范围: %d", mtu)
	}
	if err := s.setIfaceKey("MTU", strconv.Itoa(mtu)); err != nil {
		return err
	}
	s.MTU, s.MTUSet = mtu, true
	return nil
}

// SetEndpoint 改写 "# ENDPOINT" 注释行。它是纯注释，wg 会忽略，
// 但面板与 wg.sh 都靠它还原客户端配置里的 Endpoint。
func (s *Server) SetEndpoint(addr string) error {
	if !validEndpoint(addr) {
		return fmt.Errorf("wgconf: endpoint 既不是合法 IPv4 也不是 FQDN: %q", addr)
	}
	for i := 0; i < s.ifaceAt; i++ {
		if m := reEndpoint.FindStringSubmatchIndex(s.lines[i]); m != nil {
			s.lines[i] = s.lines[i][:m[3]] + addr
			s.Endpoint = addr
			return nil
		}
	}
	insert := markerEndpoint + addr
	s.lines = append(s.lines[:s.ifaceAt], append([]string{insert}, s.lines[s.ifaceAt:]...)...)
	s.ifaceAt++
	s.Endpoint = addr
	return nil
}

// AddPeer 在文件末尾追加一个 wg.sh 兼容的 peer 块。
func (s *Server) AddPeer(name, pub, psk string, allowedIPs, dns []string) error {
	if err := validPeerName(name); err != nil {
		return err
	}
	if s.HasPeer(name) {
		return fmt.Errorf("wgconf: peer %s 已存在", name)
	}
	if err := validKey(pub, "PublicKey"); err != nil {
		return err
	}
	if err := validKey(psk, "PresharedKey"); err != nil {
		return err
	}
	if len(allowedIPs) == 0 {
		return errors.New("wgconf: AllowedIPs 不能为空")
	}
	block := []string{markerBegin + name}
	if len(dns) > 0 {
		block = append(block, markerDNS+strings.Join(dns, ","))
	}
	block = append(block,
		"[Peer]",
		"PublicKey = "+pub,
		"PresharedKey = "+psk,
		"AllowedIPs = "+strings.Join(allowedIPs, ", "),
		markerEnd+name,
	)
	return s.appendBlock(block)
}

// RemovePeer 删除该 peer 的整个块（含首尾标记行）。
func (s *Server) RemovePeer(name string) error {
	start, end, ok := s.peerRange(name)
	if !ok {
		return fmt.Errorf("wgconf: 找不到 peer %s", name)
	}
	kept := make([]string, 0, len(s.lines)-(end-start+1))
	kept = append(kept, s.lines[:start]...)
	kept = append(kept, s.lines[end+1:]...)
	s.lines = kept
	return s.refreshPeers()
}

// SetPeerDisabled 切换 Peer 禁用状态。
// 禁用时注释掉该块的核心配置行并插入 # DISABLED，启用时逆向恢复。
func (s *Server) SetPeerDisabled(name string, disabled bool) error {
	start, end, ok := s.peerRange(name)
	if !ok {
		return fmt.Errorf("wgconf: 找不到 peer %s", name)
	}
	p, _ := s.findPeer(name)
	if p.Disabled == disabled {
		return nil
	}

	var newLines []string
	if disabled {
		newLines = append(newLines, s.lines[start]) // BEGIN_PEER
		newLines = append(newLines, markerDisabled)
		for i := start + 1; i < end; i++ {
			ln := s.lines[i]
			t := strings.TrimSpace(ln)
			if t == "" || strings.HasPrefix(t, "#") {
				newLines = append(newLines, ln)
			} else {
				newLines = append(newLines, "# "+ln)
			}
		}
		newLines = append(newLines, s.lines[end]) // END_PEER
	} else {
		for i := start; i <= end; i++ {
			ln := s.lines[i]
			t := strings.TrimSpace(ln)
			if t == markerDisabled {
				continue
			}
			if strings.HasPrefix(t, "# [Peer]") || strings.HasPrefix(t, "# PublicKey") ||
				strings.HasPrefix(t, "# PresharedKey") || strings.HasPrefix(t, "# AllowedIPs") {
				idx := strings.Index(ln, "# ")
				if idx >= 0 {
					ln = ln[:idx] + ln[idx+2:]
				}
			}
			newLines = append(newLines, ln)
		}
	}

	kept := make([]string, 0, len(s.lines)-(end-start+1)+len(newLines))
	kept = append(kept, s.lines[:start]...)
	kept = append(kept, newLines...)
	kept = append(kept, s.lines[end+1:]...)
	s.lines = kept
	return s.refreshPeers()
}

// ReplacePeerKey 就地替换某个 peer 的 PublicKey 与 PresharedKey。
func (s *Server) ReplacePeerKey(name, pub, psk string) error {
	start, end, ok := s.peerRange(name)
	if !ok {
		return fmt.Errorf("wgconf: 找不到 peer %s", name)
	}
	if err := validKey(pub, "PublicKey"); err != nil {
		return err
	}
	if err := validKey(psk, "PresharedKey"); err != nil {
		return err
	}
	for i := start + 1; i < end; i++ {
		k, _, ok := keyValue(s.lines[i])
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "publickey":
			s.lines[i] = setValue(s.lines[i], pub)
		case "presharedkey":
			s.lines[i] = setValue(s.lines[i], psk)
		}
	}
	return s.refreshPeers()
}

// SetPeerDNS 改写 peer 块内的 "# DNS" 注释行。
func (s *Server) SetPeerDNS(name string, dns []string) error {
	start, _, ok := s.peerRange(name)
	if !ok {
		return fmt.Errorf("wgconf: 找不到 peer %s", name)
	}
	line := markerDNS + strings.Join(dns, ",")
	for i := start + 1; i < len(s.lines); i++ {
		t := strings.TrimSpace(s.lines[i])
		if strings.HasPrefix(t, markerEnd) {
			break
		}
		if strings.HasPrefix(t, markerDNS) {
			s.lines[i] = line
			return s.refreshPeers()
		}
	}
	s.lines = append(s.lines[:start+1], append([]string{line}, s.lines[start+1:]...)...)
	return s.refreshPeers()
}

// SetPeerRouteMode 记录该 Peer 的默认路由模式（full / split / custom）。
func (s *Server) SetPeerRouteMode(name, mode string) error {
	start, _, ok := s.peerRange(name)
	if !ok {
		return fmt.Errorf("wgconf: 找不到 peer %s", name)
	}
	line := markerRouteMode + mode
	for i := start + 1; i < len(s.lines); i++ {
		t := strings.TrimSpace(s.lines[i])
		if strings.HasPrefix(t, markerEnd) {
			break
		}
		if strings.HasPrefix(t, markerRouteMode) {
			s.lines[i] = line
			return s.refreshPeers()
		}
	}
	s.lines = append(s.lines[:start+1], append([]string{line}, s.lines[start+1:]...)...)
	return s.refreshPeers()
}

// AllocateOctet 返回 10.7.0.0/24 内最小的空闲末段（2..254）。
func (s *Server) AllocateOctet() (int, error) {
	used := map[int]bool{}
	for i := range s.Peers {
		if n := s.Peers[i].IPv4Octet(); n != 0 {
			used[n] = true
		}
	}
	for n := minClientOctet; n <= maxClientOctet; n++ {
		if !used[n] {
			return n, nil
		}
	}
	return 0, errors.New("wgconf: 子网 10.7.0.2-10.7.0.254 已用尽")
}

func (s *Server) peerRange(name string) (start, end int, ok bool) {
	wantB, wantE := markerBegin+name, markerEnd+name
	for i, ln := range s.lines {
		t := strings.TrimSpace(ln)
		if t == wantB {
			start = i
		}
		if start >= 0 && t == wantE {
			return start, i, true
		}
	}
	return 0, 0, false
}

func (s *Server) appendBlock(block []string) error {
	at := len(s.lines)
	if at > 0 && s.lines[at-1] == "" {
		at--
	}
	out := make([]string, 0, len(s.lines)+len(block))
	out = append(out, s.lines[:at]...)
	out = append(out, block...)
	out = append(out, s.lines[at:]...)
	s.lines = out
	return s.refreshPeers()
}

func (s *Server) setIfaceKey(key, value string) error {
	end := s.interfaceEnd()
	re := regexp.MustCompile(`(?i)^\s*` + key + `\s*=`)
	for i := s.ifaceAt + 1; i < end; i++ {
		if re.MatchString(s.lines[i]) {
			s.lines[i] = setValue(s.lines[i], value)
			return nil
		}
	}
	ins := end
	for ins > s.ifaceAt+1 && strings.TrimSpace(s.lines[ins-1]) == "" {
		ins--
	}
	s.lines = append(s.lines[:ins], append([]string{key + " = " + value}, s.lines[ins:]...)...)
	return nil
}

func (s *Server) deleteIfaceKey(key string) error {
	end := s.interfaceEnd()
	re := regexp.MustCompile(`(?i)^\s*` + key + `\s*=`)
	for i := s.ifaceAt + 1; i < end; i++ {
		if re.MatchString(s.lines[i]) {
			s.lines = append(s.lines[:i], s.lines[i+1:]...)
			s.MTU, s.MTUSet = 0, false
			return nil
		}
	}
	return nil
}

func setValue(line, value string) string {
	m := reKeySimple.FindStringSubmatchIndex(line)
	if m == nil {
		return line
	}
	return line[:m[4]] + value + line[m[6]:]
}

func keyValue(line string) (key, value string, ok bool) {
	m := reKeyPrefix.FindStringSubmatch(line)
	if m == nil {
		return "", "", false
	}
	i := strings.Index(line, "=")
	if i < 0 {
		return "", "", false
	}
	return m[1], strings.TrimSpace(line[i+1:]), true
}

func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func validKey(v, what string) error {
	v = strings.TrimSpace(v)
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return fmt.Errorf("%s 不是合法 base64", what)
	}
	if len(b) != 32 {
		return fmt.Errorf("%s 解码后应为 32 字节，实为 %d", what, len(b))
	}
	return nil
}

func validPeerName(name string) error {
	if name == "" {
		return errors.New("wgconf: peer 名为空")
	}
	if len(name) > 15 {
		return fmt.Errorf("wgconf: peer 名超过 15 字符: %s", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return fmt.Errorf("wgconf: peer 名含非法字符: %q", name)
		}
	}
	return nil
}

func validEndpoint(addr string) bool {
	if reFQDN.MatchString(addr) {
		return true
	}
	m := reIPv4.FindStringSubmatch(addr)
	if m == nil {
		return false
	}
	for _, part := range strings.Split(addr, ".") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// String 用于调试输出。刻意不含任何密钥材料。
func (s *Server) String() string {
	return fmt.Sprintf("Server{endpoint=%s port=%d mtuSet=%t mtu=%d addrs=%d peers=%d}",
		s.Endpoint, s.ListenPort, s.MTUSet, s.MTU, len(s.Address), len(s.Peers))
}
