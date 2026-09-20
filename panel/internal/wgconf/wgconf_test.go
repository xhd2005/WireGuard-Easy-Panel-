package wgconf

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 测试用的合法密钥材料（44 字符 base64，解码后 32 字节）。
// 均为一次性生成值，不对应任何真实隧道。
const (
	kPriv1 = "wFxSCo8a5+PoZcKx8Q+LoS31VBMGOmztUUTcqi5hl0c="
	kPub1  = "mUuGofDVp+yBuo7u6SgGRRfYOao597gC9U8pSXu7BXw="
	kPub2  = "QNW8CtFeh63etjz19XtLl6WY7bDHIlj5WraSnrXWsB4="
	kPsk1  = "zDcuEpcFz1DNPyoVVBWItbOOzqHDrW4smBn/IKam1xM="
	kPsk2  = "8JOCQ2U1aTKDCcNxLMyUMv4LuRP1dsncnv1Ct0MtKoA="
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	// go test 的工作目录是本包目录 panel/internal/wgconf
	p := filepath.Join("..", "..", "..", "fixtures", name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("读取 fixture %s 失败: %v", p, err)
	}
	return b
}

func mustParse(t *testing.T, b []byte) *Server {
	t.Helper()
	s, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse 失败: %v", err)
	}
	return s
}

func sameBytes(a, b []byte) bool { return bytes.Equal(a, b) }

// ---------------------------------------------------------------- 原样写回

func TestGoldenRoundTrip(t *testing.T) {
	for _, f := range []string{"wg0-no-ipv6.conf", "wg0-ipv6.conf"} {
		t.Run(f, func(t *testing.T) {
			in := fixture(t, f)
			s := mustParse(t, in)
			if out := s.Marshal(); !sameBytes(out, in) {
				t.Errorf("Parse→Marshal 未做到字节一致\n--- 期望 ---\n%q\n--- 实际 ---\n%q", in, out)
			}
		})
	}
}

// golden 往返的前提是文件没被换行符转换污染过。
func TestFixturesAreLFOnly(t *testing.T) {
	for _, f := range []string{"wg0-no-ipv6.conf", "wg0-ipv6.conf"} {
		if bytes.ContainsRune(fixture(t, f), '\r') {
			t.Errorf("%s 含 CR —— .gitattributes 的 fixtures/** -text 可能没生效", f)
		}
	}
}

// 只改目标行。注意不能用"按下标逐位比对"—— 插入一行会让其后所有行下标整体
// 平移，看起来像"全变了"。改为：从两侧各自过滤掉"允许变化的行"，再比序列。
func TestEditsTouchOnlyTargetLine(t *testing.T) {
	in := fixture(t, "wg0-ipv6.conf")
	cases := []struct {
		name    string
		mutate  func(*Server) error
		predfix func(string) bool // 命中即为"允许出现/消失的行"
	}{
		{"ListenPort", func(s *Server) error { return s.SetListenPort(443) },
			func(l string) bool { return strings.HasPrefix(strings.TrimSpace(l), "ListenPort") }},
		{"Endpoint", func(s *Server) error { return s.SetEndpoint("198.51.100.24") },
			func(l string) bool { return strings.HasPrefix(strings.TrimSpace(l), "# ENDPOINT") }},
		{"MTU新增", func(s *Server) error { return s.SetMTU(1280) },
			func(l string) bool { return strings.HasPrefix(strings.TrimSpace(l), "MTU") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := mustParse(t, in)
			if err := tc.mutate(s); err != nil {
				t.Fatalf("mutate 失败: %v", err)
			}
			before := filterLines(strings.Split(string(in), "\n"), tc.predfix)
			after := filterLines(strings.Split(string(s.Marshal()), "\n"), tc.predfix)
			if strings.Join(before, "\n") != strings.Join(after, "\n") {
				for i := range before {
					if i >= len(after) || before[i] != after[i] {
						t.Errorf("不该变的行变了：before[%d]=%q after[%d]=%q", i, before[i], i, after[i])
						break
					}
				}
				t.Errorf("过滤后两侧序列不等")
			}
			if strings.Join(strings.Split(string(s.Marshal()), "\n"), "\n") ==
				strings.Join(strings.Split(string(in), "\n"), "\n") {
				t.Error("没有任何行变化，说明改动没生效")
			}
		})
	}
}

func filterLines(lines []string, drop func(string) bool) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if !drop(l) {
			out = append(out, l)
		}
	}
	return out
}

// 回归：SetEndpoint 曾因误用 FindStringSubmatchIndex 的捕获组起点而非终点，
// 把新值拼在旧值前面，导致下一次改写找不到 # ENDPOINT 行、凭空多插一行。
func TestSetEndpointKeepsExactlyOneMarker(t *testing.T) {
	in := fixture(t, "wg0-ipv6.conf")
	s := mustParse(t, in)
	for _, addr := range []string{"198.51.100.24", "wg.example.net", "203.0.51.10"} {
		if err := s.SetEndpoint(addr); err != nil {
			t.Fatal(err)
		}
		out := string(s.Marshal())
		if n := strings.Count(out, "# ENDPOINT"); n != 1 {
			t.Fatalf("改成 %s 后全文应有且仅有 1 行 # ENDPOINT，实为 %d:\n%s", addr, n, out)
		}
		if s2 := mustParse(t, []byte(out)); s2.Endpoint != addr {
			t.Errorf("重解析后 endpoint=%q，期望 %q", s2.Endpoint, addr)
		}
	}
	if !sameBytes(s.Marshal(), in) {
		t.Errorf("绕一圈回到原值后与原文不同:\n%q", s.Marshal())
	}
}

// SetEndpoint 的另一条分支：老配置根本没有 "# ENDPOINT" 行。
// 这条路径会插入新行并让 [Interface] 的行号整体后移，最容易出错。
func TestSetEndpointWhenMarkerMissing(t *testing.T) {
	in := "[Interface]\nAddress = 10.7.0.1/24\nPrivateKey = " + kPriv1 + "\nListenPort = 53\n\n" +
		markerBegin + "a\n[Peer]\nPublicKey = " + kPub1 + "\nAllowedIPs = 10.7.0.2/32\n" + markerEnd + "a\n"
	s := mustParse(t, []byte(in))
	if s.Endpoint != "" {
		t.Fatalf("起点应为空 endpoint，实得 %q", s.Endpoint)
	}
	if err := s.SetEndpoint("203.0.51.77"); err != nil {
		t.Fatal(err)
	}
	out := string(s.Marshal())
	if n := strings.Count(out, markerEndpoint); n != 1 {
		t.Fatalf("应只有一行 # ENDPOINT，实得 %d:\n%s", n, out)
	}
	// 插入点必须在 [Interface] 之前，否则会落进段里被 wg 当异常行
	lines := strings.Split(out, "\n")
	iface, mark := -1, -1
	for i, l := range lines {
		if strings.TrimSpace(l) == "[Interface]" {
			iface = i
		}
		if strings.HasPrefix(l, markerEndpoint) {
			mark = i
		}
	}
	if mark < 0 || iface < 0 || mark > iface {
		t.Errorf("# ENDPOINT 应在 [Interface] 之前：mark=%d iface=%d", mark, iface)
	}
	// 重解析必须读得回来，且 peer 仍完好
	s2 := mustParse(t, []byte(out))
	if s2.Endpoint != "203.0.51.77" {
		t.Errorf("重解析 endpoint=%q", s2.Endpoint)
	}
	if s2.ListenPort != 53 || len(s2.Peers) != 1 || s2.Peers[0].Name != "a" {
		t.Errorf("插入后其它内容受损: %v", s2)
	}
	// 再改一次走的是"替换"分支，不该多出第二行
	if err := s2.SetEndpoint("198.51.100.6"); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(s2.Marshal()), markerEndpoint); n != 1 {
		t.Errorf("第二次改写后仍有 %d 行 # ENDPOINT", n)
	}
}

// 只有 IPv6、没有 v4 /32 的 peer 不得干扰末段分配。
func TestAllocateSkipsV6OnlyPeer(t *testing.T) {
	in := "[Interface]\nPrivateKey = " + kPriv1 + "\nListenPort = 53\n\n" +
		markerBegin + "v6only\n[Peer]\nPublicKey = " + kPub1 +
		"\nAllowedIPs = fddd:2c4:2c4:2c4::9/128\n" + markerEnd + "v6only\n"
	s := mustParse(t, []byte(in))
	if got := s.Peers[0].IPv4Octet(); got != 0 {
		t.Errorf("纯 v6 peer 的 IPv4Octet 应为 0，实得 %d", got)
	}
	if got, err := s.AllocateOctet(); err != nil || got != minClientOctet {
		t.Errorf("v6 peer 不该占用 v4 末段：got=%d err=%v", got, err)
	}
}

// 改了再改回去，必须拿回原始字节 —— 这比"变了多少行"更能证明无格式漂移。
func TestEditsAreReversible(t *testing.T) {
	in := fixture(t, "wg0-ipv6.conf")

	t.Run("端口往返", func(t *testing.T) {
		s := mustParse(t, in)
		_ = s.SetListenPort(443)
		if err := s.SetListenPort(53); err != nil {
			t.Fatal(err)
		}
		if !sameBytes(s.Marshal(), in) {
			t.Errorf("端口改回 53 后与原文不同:\n%q", s.Marshal())
		}
	})

	t.Run("MTU加了又删", func(t *testing.T) {
		s := mustParse(t, in)
		_ = s.SetMTU(1280)
		if err := s.SetMTU(0); err != nil {
			t.Fatal(err)
		}
		if !sameBytes(s.Marshal(), in) {
			t.Errorf("移除 MTU 后与原文不同:\n%q", s.Marshal())
		}
	})

	t.Run("endpoint往返", func(t *testing.T) {
		s := mustParse(t, in)
		orig := s.Endpoint
		_ = s.SetEndpoint("198.51.100.24")
		if err := s.SetEndpoint(orig); err != nil {
			t.Fatal(err)
		}
		if !sameBytes(s.Marshal(), in) {
			t.Errorf("endpoint 改回后与原文不同:\n%q", s.Marshal())
		}
	})
}

// AddPeer → RemovePeer 必须字节可逆；这是"面板与 wg.sh 共用一份文件"的前提。
func TestAddRemovePeerIsByteReversible(t *testing.T) {
	for _, f := range []string{"wg0-no-ipv6.conf", "wg0-ipv6.conf"} {
		t.Run(f, func(t *testing.T) {
			in := fixture(t, f)
			s := mustParse(t, in)
			n0 := len(s.Peers)

			if err := s.AddPeer("tablet", kPub2, kPsk2,
				[]string{"10.7.0.9/32", "fddd:2c4:2c4:2c4::9/128"}, nil); err != nil {
				t.Fatalf("AddPeer 失败: %v", err)
			}
			if len(s.Peers) != n0+1 {
				t.Fatalf("peer 数应为 %d，实为 %d", n0+1, len(s.Peers))
			}
			if err := s.RemovePeer("tablet"); err != nil {
				t.Fatalf("RemovePeer 失败: %v", err)
			}
			if !sameBytes(s.Marshal(), in) {
				t.Errorf("加了又删之后与原文不同:\n%q", s.Marshal())
			}
		})
	}
}

// -------------------------------------------------- 与 wg.sh 的 sed 协议兼容

// wg.sh 的 update_wg_conf 用的是
//   sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" "$WG_CONF"
// 即：标记行必须顶格、形如 "# BEGIN_PEER <name>"、区间内含完整 [Peer] 块。
func TestMarkerCompatWithWgShSed(t *testing.T) {
	s := mustParse(t, fixture(t, "wg0-ipv6.conf"))
	if err := s.AddPeer("tablet", kPub2, kPsk2, []string{"10.7.0.9/32"}, nil); err != nil {
		t.Fatal(err)
	}
	got := sedRangeExtraction(string(s.Marshal()), "tablet")

	want := []string{
		"# BEGIN_PEER tablet",
		"[Peer]",
		"PublicKey = " + kPub2,
		"PresharedKey = " + kPsk2,
		"AllowedIPs = 10.7.0.9/32",
		"# END_PEER tablet",
	}
	if len(got) != len(want) {
		t.Fatalf("sed 区间取到 %d 行，期望 %d 行:\n%q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 行不符: 期望 %q 实为 %q", i, want[i], got[i])
		}
	}
	// 对存量 peer 也要能取到，证明面板写过的文件 wg.sh 仍读得动
	if phone := sedRangeExtraction(string(s.Marshal()), "phone"); len(phone) != 6 {
		t.Errorf("存量 peer phone 的块行数异常: %q", phone)
	}
	// 含 # DNS 的 peer，块内应多一行且仍在区间内
	laptop := sedRangeExtraction(string(s.Marshal()), "laptop")
	if len(laptop) != 7 || !strings.HasPrefix(laptop[1], "# DNS ") {
		t.Errorf("laptop 块应含 # DNS 行，实得 %q", laptop)
	}
}

// 复刻 wg.sh 那句 sed 的行区间语义（首尾标记行都包含在内）。
func sedRangeExtraction(content, name string) []string {
	lines := strings.Split(content, "\n")
	var out []string
	in := false
	for _, ln := range lines {
		switch strings.TrimSpace(ln) {
		case markerBegin + name:
			in = true
		case markerEnd + name:
			if in {
				return append(out, ln)
			}
		}
		if in {
			out = append(out, ln)
		}
	}
	return nil
}

// ------------------------------------------------------------------ DNS 回落

func TestDNSKnownFlag(t *testing.T) {
	s := mustParse(t, fixture(t, "wg0-ipv6.conf"))
	byName := map[string]Peer{}
	for _, p := range s.Peers {
		byName[p.Name] = p
	}
	if p := byName["phone"]; p.DNSKnown || len(p.DNS) != 0 {
		t.Errorf("无 # DNS 行的存量 peer 应为 DNSKnown=false，实得 %+v", p)
	}
	p := byName["laptop"]
	if !p.DNSKnown || len(p.DNS) != 2 || p.DNS[0] != "183.60.83.19" {
		t.Errorf("laptop 的 # DNS 未被正确解析: %+v", p)
	}
}

func TestSetPeerDNSInsertsThenReplaces(t *testing.T) {
	s := mustParse(t, fixture(t, "wg0-ipv6.conf"))
	// phone 原先没有 # DNS
	if err := s.SetPeerDNS("phone", []string{"1.1.1.1", "1.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if !s.Peers[0].DNSKnown || len(s.Peers[0].DNS) != 2 {
		t.Fatalf("插入后应可读回: %+v", s.Peers[0])
	}
	lines := strings.Split(string(s.Marshal()), "\n")
	idx := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == markerBegin+"phone" {
			idx = i
		}
	}
	if idx < 0 || lines[idx+1] != markerDNS+"1.1.1.1,1.0.0.1" {
		t.Errorf("# DNS 应紧跟在 BEGIN 之后，实得 %q", lines[idx+1])
	}
	// 再改一次不应新增第二行
	if err := s.SetPeerDNS("phone", []string{"223.5.5.5"}); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(s.Marshal()), markerDNS); n != 2 {
		t.Errorf("全文应有 2 行 # DNS（phone+laptop），实为 %d", n)
	}
}

// -------------------------------------------------------------- 地址与分配

func TestAllocateOctet(t *testing.T) {
	cases := []struct {
		file string
		want int
	}{
		{"wg0-no-ipv6.conf", 3}, // 只占了 .2
		{"wg0-ipv6.conf", 4},    // 占了 .2 .3
	}
	for _, tc := range cases {
		s := mustParse(t, fixture(t, tc.file))
		got, err := s.AllocateOctet()
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if got != tc.want {
			t.Errorf("%s: 期望 %d 实得 %d", tc.file, got, tc.want)
		}
	}
	// 空子网应给 2；满子网应报错
	base := "[Interface]\nPrivateKey = " + kPriv1 + "\nListenPort = 51820\n\n"
	var sb strings.Builder
	sb.WriteString(base)
	for n := minClientOctet; n <= maxClientOctet; n++ {
		fmt.Fprintf(&sb, "%sx%d\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.7.0.%d/32\n%sx%d\n",
			markerBegin, n, kPub1, n, markerEnd, n)
	}
	s := mustParse(t, []byte(sb.String()))
	if _, err := s.AllocateOctet(); err == nil {
		t.Error("子网已用尽却仍然分配成功")
	}

	// 注释里出现的假 AllowedIPs 不得影响分配
	tricky := base + markerBegin + "a\n[Peer]\nPublicKey = " + kPub1 +
		"\nAllowedIPs = 10.7.0.2/32\n" + markerEnd + "a\n" +
		"# 备注 AllowedIPs = 10.7.0.2/32 这行只是注释\n"
	s2 := mustParse(t, []byte(tricky))
	if got, _ := s2.AllocateOctet(); got != 3 {
		t.Errorf("分配应跳过已占用的 .2 给出 3，实得 %d", got)
	}
}

func TestIPv4OctetParsing(t *testing.T) {
	s := mustParse(t, fixture(t, "wg0-ipv6.conf"))
	want := map[string]int{"phone": 2, "laptop": 3}
	for _, p := range s.Peers {
		if w := want[p.Name]; p.IPv4Octet() != w {
			t.Errorf("%s: 期望末段 %d 实得 %d (AllowedIPs=%v)", p.Name, w, p.IPv4Octet(), p.AllowedIPs)
		}
	}
}

// ------------------------------------------------------------------ 解析报错

func TestParseRejectsBrokenConfig(t *testing.T) {
	head := "# ENDPOINT 203.0.51.10\n\n[Interface]\nAddress = 10.7.0.1/24\nPrivateKey = " +
		kPriv1 + "\nListenPort = 53\n\n"
	peer := markerBegin + "a\n[Peer]\nPublicKey = " + kPub1 + "\nAllowedIPs = 10.7.0.2/32\n" + markerEnd + "a\n"

	cases := []struct {
		name  string
		input string
	}{
		{"空文件", ""},
		{"缺少 Interface 段", "# ENDPOINT x\nListenPort = 53\n"},
		{"缺少 PrivateKey", "# E\n[Interface]\nListenPort = 53\n"},
		{"缺少 ListenPort", "[Interface]\nPrivateKey = " + kPriv1 + "\n"},
		{"ListenPort 非数字", "[Interface]\nPrivateKey = " + kPriv1 + "\nListenPort = abc\n"},
		{"ListenPort 越界", "[Interface]\nPrivateKey = " + kPriv1 + "\nListenPort = 70000\n"},
		{"PrivateKey 非法 base64", "[Interface]\nPrivateKey = @@@\nListenPort = 53\n"},
		{"PrivateKey 长度不对", "[Interface]\nPrivateKey = AAAA\nListenPort = 53\n"},
		{"BEGIN 无 END", head + strings.TrimSuffix(peer, markerEnd+"a\n")},
		{"END 无 BEGIN", head + markerEnd + "ghost\n"},
		{"peer 名重复", head + peer + peer},
		{"peer 缺 PublicKey", head + markerBegin + "a\n[Peer]\nAllowedIPs = 10.7.0.2/32\n" + markerEnd + "a\n"},
		{"peer 名含空格", head + markerBegin + "bad name\n[Peer]\nPublicKey = " + kPub1 +
			"\nAllowedIPs = 10.7.0.2/32\n" + markerEnd + "bad name\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.input)); err == nil {
				t.Errorf("本该解析失败却成功了：这会打开“在看不懂的状态下写回”的口子")
			}
		})
	}
}

// 合法但形状陌生的配置也必须能读：键可以不带空格，缩进可以不同。
func TestParseToleratesFormattingVariants(t *testing.T) {
	in := "[Interface]\nPrivateKey="+kPriv1+"\nListenPort=51820\nMTU=1420\n\n"+
		markerBegin+"a\n[Peer]\n  PublicKey = "+kPub1+"\n  PresharedKey="+kPsk1+
		"\n  AllowedIPs = 10.7.0.7/32\n"+markerEnd+"a\n"
	s := mustParse(t, []byte(in))
	if s.ListenPort != 51820 || !s.MTUSet || s.MTU != 1420 {
		t.Errorf("基础字段解析错: %+v", s)
	}
	if s.Peers[0].IPv4Octet() != 7 || s.Peers[0].PresharedKey != kPsk1 {
		t.Errorf("peer 解析错: %+v", s.Peers[0])
	}
	if !sameBytes(s.Marshal(), []byte(in)) {
		t.Error("异形格式未做到原样写回")
	}
	// 改端口时必须保留 "ListenPort=51820" 这种无空格风格
	if err := s.SetListenPort(443); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(s.Marshal()), "ListenPort=443") {
		t.Errorf("改动破坏了原有分隔风格:\n%s", s.Marshal())
	}
}

// ---------------------------------------------------------------- 敏感数据

// 密钥只应存在于结构体字段里，不得通过 String() 或错误信息外泄。
func TestNoKeyMaterialInOutputs(t *testing.T) {
	s := mustParse(t, fixture(t, "wg0-ipv6.conf"))
	if strings.Contains(s.String(), kPriv1) || strings.Contains(s.String(), kPsk1) {
		t.Error("String() 泄漏了密钥")
	}
	// 连密钥的前 12 字符都不该出现，避免部分脱敏的假象
	for _, frag := range []string{kPriv1[:12], kPsk1[:12], kPub1[:12]} {
		if strings.Contains(s.String(), frag) {
			t.Errorf("String() 含密钥片段 %q", frag)
		}
	}
	// 报错路径同样不得回显密钥
	_, err := Parse([]byte("[Interface]\nPrivateKey = " + kPriv1 + "\nListenPort = bad\n"))
	if err == nil {
		t.Fatal("本该报错")
	}
	if strings.Contains(err.Error(), kPriv1) {
		t.Errorf("错误信息含私钥: %v", err)
	}
}

func TestEndpointValidation(t *testing.T) {
	s := mustParse(t, fixture(t, "wg0-ipv6.conf"))
	for _, bad := range []string{"", "999.1.1.1", "1.2.3", "not a host", "256.256.256.256", "vpn_*.example.com"} {
		if err := s.SetEndpoint(bad); err == nil {
			t.Errorf("endpoint %q 本该被拒绝", bad)
		}
	}
	for _, ok := range []string{"203.0.51.10", "vpn.example.com", "10.0.0.5"} {
		if err := s.SetEndpoint(ok); err != nil {
			t.Errorf("endpoint %q 本该通过: %v", ok, err)
		}
	}
}

func TestPeerNameValidation(t *testing.T) {
	s := mustParse(t, fixture(t, "wg0-no-ipv6.conf"))
	bad := []string{"", "has space", "semi;colon", "back`tick", "$(rm -rf /)", "a/b", "带中文", strings.Repeat("x", 16)}
	for _, n := range bad {
		if err := s.AddPeer(n, kPub1, kPsk1, []string{"10.7.0.9/32"}, nil); err == nil {
			t.Errorf("peer 名 %q 本该被拒绝", n)
		}
	}
	// 合法字符集：字母数字下划线短横
	for _, n := range []string{"a", "phone-1", "Desk_2", "A9"} {
		if err := s.AddPeer(n, kPub1, kPsk1, []string{"10.7.0.9/32"}, nil); err != nil {
			t.Errorf("peer 名 %q 本该通过: %v", n, err)
		}
		_ = s.RemovePeer(n)
	}
	if err := s.AddPeer("testphone", kPub1, kPsk1, []string{"10.7.0.9/32"}, nil); err == nil {
		t.Error("重名 peer 本该被拒绝")
	}
}

// 改动后重新解析，字段必须与改动意图一致（防止"写进去了但读不回来"）。
func TestMutationsSurviveReparse(t *testing.T) {
	s := mustParse(t, fixture(t, "wg0-ipv6.conf"))
	if err := s.SetListenPort(8443); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEndpoint("wg.example.net"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMTU(1280); err != nil {
		t.Fatal(err)
	}
	if err := s.AddPeer("tablet", kPub2, kPsk2, []string{"10.7.0.9/32", "fddd:2c4:2c4:2c4::9/128"},
		[]string{"183.60.83.19"}); err != nil {
		t.Fatal(err)
	}
	s2 := mustParse(t, s.Marshal())
	if s2.ListenPort != 8443 {
		t.Errorf("ListenPort=%d", s2.ListenPort)
	}
	if s2.Endpoint != "wg.example.net" {
		t.Errorf("Endpoint=%q", s2.Endpoint)
	}
	if !s2.MTUSet || s2.MTU != 1280 {
		t.Errorf("MTU=%d set=%t", s2.MTU, s2.MTUSet)
	}
	if len(s2.Peers) != 3 {
		t.Fatalf("peer 数=%d", len(s2.Peers))
	}
	tp, ok := s2.findPeer("tablet")
	if !ok {
		t.Fatal("tablet 丢失")
	}
	if tp.IPv4Octet() != 9 || !tp.DNSKnown || tp.DNS[0] != "183.60.83.19" || tp.PublicKey != kPub2 {
		t.Errorf("tablet 内容不符: %+v", tp)
	}
}

func TestReplacePeerKeyOnlyTouchesTarget(t *testing.T) {
	s := mustParse(t, fixture(t, "wg0-ipv6.conf"))
	laptopPSK := s.Peers[1].PresharedKey
	if err := s.ReplacePeerKey("phone", kPub2, kPsk2); err != nil {
		t.Fatal(err)
	}
	if s.Peers[0].PublicKey != kPub2 || s.Peers[0].PresharedKey != kPsk2 {
		t.Errorf("phone 密钥未更新: %+v", s.Peers[0])
	}
	if s.Peers[1].PresharedKey != laptopPSK {
		t.Error("laptop 的 PSK 被误改了")
	}
	// 行格式必须保持 "PublicKey = " 前缀
	if !strings.Contains(string(s.Marshal()), "PublicKey = "+kPub2) {
		t.Error("替换破坏了行格式")
	}
}

// 解析失败时不得留下任何"部分改好"的内容 —— 所有 mutator 都先校验再动 lines。
func TestInvalidMutationsLeaveBytesUntouched(t *testing.T) {
	in := fixture(t, "wg0-ipv6.conf")
	cases := []struct {
		name   string
		mutate func(*Server) error
	}{
		{"端口越界", func(s *Server) error { return s.SetListenPort(0) }},
		{"端口过大", func(s *Server) error { return s.SetListenPort(70000) }},
		{"MTU 过小", func(s *Server) error { return s.SetMTU(500) }},
		{"endpoint 非法", func(s *Server) error { return s.SetEndpoint("bad; host") }},
		{"删不存在的 peer", func(s *Server) error { return s.RemovePeer("ghost") }},
		{"加已存在的 peer", func(s *Server) error {
			return s.AddPeer("phone", kPub1, kPsk1, []string{"10.7.0.9/32"}, nil)
		}},
		{"peer 公钥非法", func(s *Server) error {
			return s.AddPeer("newone", "@@@", kPsk1, []string{"10.7.0.9/32"}, nil)
		}},
		{"AllowedIPs 为空", func(s *Server) error {
			return s.AddPeer("newone", kPub1, kPsk1, nil, nil)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := mustParse(t, in)
			if err := tc.mutate(s); err == nil {
				t.Fatal("本该返回错误")
			}
			if !sameBytes(s.Marshal(), in) {
				t.Errorf("校验失败但仍改动了内容:\n%q", s.Marshal())
			}
		})
	}
}

func BenchmarkParse(b *testing.B) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "fixtures", "wg0-ipv6.conf"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Parse(data); err != nil {
			b.Fatal(err)
		}
	}
}
