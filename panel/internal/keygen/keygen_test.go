package keygen

import (
	"encoding/base64"
	"testing"
)

func TestGenerateKeysAndValidate(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey failed: %v", err)
	}
	if len(priv) != 44 {
		t.Errorf("expected 44-char base64, got %d chars: %s", len(priv), priv)
	}
	if err := ValidateKey(priv); err != nil {
		t.Errorf("validate private key failed: %v", err)
	}

	pub, err := PublicKey(priv)
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	if len(pub) != 44 {
		t.Errorf("expected 44-char base64, got %d chars: %s", len(pub), pub)
	}
	if err := ValidateKey(pub); err != nil {
		t.Errorf("validate public key failed: %v", err)
	}

	psk, err := GeneratePresharedKey()
	if err != nil {
		t.Fatalf("GeneratePresharedKey failed: %v", err)
	}
	if err := ValidateKey(psk); err != nil {
		t.Errorf("validate PSK failed: %v", err)
	}
}

// 验证与 WireGuard 官方 wg 命令产物的 100% 互操作性
// 该测试向量来自目标机器真实运行 wg genkey / wg pubkey 产生的值。
func TestPublicKeyMatchesWgCommandOutput(t *testing.T) {
	const (
		wgPriv = "wFxSCo8a5+PoZcKx8Q+LoS31VBMGOmztUUTcqi5hl0c="
		wgPub  = "rXMT3K0AM9I5B7D/S5f/HaLaUP7yVyZdQRFfRuenlRE="
	)

	derivedPub, err := PublicKey(wgPriv)
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	if derivedPub != wgPub {
		t.Errorf("公钥推导不符！期望 %q 实得 %q", wgPub, derivedPub)
	}
}

func TestClampingBits(t *testing.T) {
	privBase64, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := base64.StdEncoding.DecodeString(privBase64)
	if b[0]&7 != 0 {
		t.Errorf("lowest 3 bits must be 0, got %08b", b[0])
	}
	if b[31]&128 != 0 {
		t.Errorf("highest bit of last byte must be 0, got %08b", b[31])
	}
	if b[31]&64 == 0 {
		t.Errorf("second highest bit of last byte must be 1, got %08b", b[31])
	}
}
