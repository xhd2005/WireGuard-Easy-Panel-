package status

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadFixture(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", "fixtures", name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("load fixture %s failed: %v", p, err)
	}
	return string(b)
}

func TestParseShowSinglePeer(t *testing.T) {
	raw := loadFixture(t, "wg-show-single-peer.txt")
	st, err := ParseShow(raw)
	if err != nil {
		t.Fatalf("ParseShow failed: %v", err)
	}

	if st.Interface != "wg0" {
		t.Errorf("expected iface wg0, got %q", st.Interface)
	}
	if st.ListenPort != 53 {
		t.Errorf("expected port 53, got %d", st.ListenPort)
	}
	if len(st.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(st.Peers))
	}

	p := st.Peers[0]
	if p.Endpoint != "198.51.100.77:2247" {
		t.Errorf("unexpected endpoint: %q", p.Endpoint)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.7.0.2/32" {
		t.Errorf("unexpected allowed IPs: %v", p.AllowedIPs)
	}
	if !p.HasHandshook {
		t.Error("expected peer to have handshook")
	}
	if st.AllNeverHandshake {
		t.Error("expected AllNeverHandshake=false")
	}
	if p.TransferRxBytes <= 0 || p.TransferTxBytes <= 0 {
		t.Errorf("expected non-zero transfer bytes: rx=%d tx=%d", p.TransferRxBytes, p.TransferTxBytes)
	}
}

func TestParseShowNeverHandshook(t *testing.T) {
	raw := loadFixture(t, "wg-show-never-handshook.txt")
	st, err := ParseShow(raw)
	if err != nil {
		t.Fatalf("ParseShow failed: %v", err)
	}

	if len(st.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(st.Peers))
	}
	if st.Peers[0].HasHandshook {
		t.Error("expected peer HasHandshook=false")
	}
	if !st.AllNeverHandshake {
		t.Error("expected AllNeverHandshake=true (triggers 4.2 firewall banner)")
	}
}

func TestParseShowIPv6Endpoint(t *testing.T) {
	raw := loadFixture(t, "wg-show-ipv6-endpoint.txt")
	st, err := ParseShow(raw)
	if err != nil {
		t.Fatalf("ParseShow failed: %v", err)
	}

	if len(st.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(st.Peers))
	}
	if st.Peers[0].Endpoint != "[2001:db8::1]:51820" {
		t.Errorf("expected IPv6 endpoint, got %q", st.Peers[0].Endpoint)
	}
	if len(st.Peers[0].AllowedIPs) != 2 {
		t.Errorf("expected 2 allowed IPs, got %v", st.Peers[0].AllowedIPs)
	}
}

func TestParseShowEmpty(t *testing.T) {
	raw := loadFixture(t, "wg-show-empty.txt")
	st, err := ParseShow(raw)
	if err != nil {
		t.Fatalf("ParseShow failed: %v", err)
	}
	if len(st.Peers) != 0 {
		t.Errorf("expected 0 peers, got %d", len(st.Peers))
	}
	if !st.AllNeverHandshake {
		t.Error("expected AllNeverHandshake=true when empty")
	}
}

// ⚠️ 核心安全断言（spec 10 / 13.1）：
// 验证喂入 wg show dump 制式的输入（含明文私钥与 PSK）后，
// 解析结构体、JSON 序列化结果、以及 String() 输出中绝不出现私钥或 PSK 字符！
func TestParseDumpStripsPrivateKeysStrictly(t *testing.T) {
	rawDump := loadFixture(t, "wg-show-dump-sample.txt")

	const (
		leakedPrivKey = "2OEleOKw02Et7uhOiM2AnLaSKqBZt1V+7JiR6docFms="
		leakedPSK     = "8JOCQ2U1aTKDCcNxLMyUMv4LuRP1dsncnv1Ct0MtKoA="
	)

	// 首先确认输入样本中确实包含这俩字符串，保证测试靶标真实存在
	if !strings.Contains(rawDump, leakedPrivKey) || !strings.Contains(rawDump, leakedPSK) {
		t.Fatal("测试 fixture 异常：未包含预期的靶标密钥")
	}

	st, err := ParseShow(rawDump)
	if err != nil {
		t.Fatalf("ParseShow(dump) failed: %v", err)
	}

	if st.Interface != "wg0" || st.ListenPort != 53 {
		t.Errorf("unexpected dump interface/port: %s / %d", st.Interface, st.ListenPort)
	}
	if len(st.Peers) != 1 {
		t.Fatalf("expected 1 peer from dump, got %d", len(st.Peers))
	}
	if !st.Peers[0].HasHandshook {
		t.Error("expected handshook peer in dump sample")
	}

	// 1. JSON 序列化输出中不得包含私钥或 PSK
	jsonBytes, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	jsonStr := string(jsonBytes)
	if strings.Contains(jsonStr, leakedPrivKey) {
		t.Errorf("🔥 严重安全漏洞：私钥泄漏在 JSON 序列化中: %s", jsonStr)
	}
	if strings.Contains(jsonStr, leakedPSK) {
		t.Errorf("🔥 严重安全漏洞：PSK 泄漏在 JSON 序列化中: %s", jsonStr)
	}

	// 2. String() 调试方法中不得包含私钥或 PSK
	strOut := st.String() + " " + st.Peers[0].String()
	if strings.Contains(strOut, leakedPrivKey) || strings.Contains(strOut, leakedPSK) {
		t.Errorf("🔥 调试 String() 泄漏了密钥: %s", strOut)
	}
}
