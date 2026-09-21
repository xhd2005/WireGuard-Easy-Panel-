package qr

import (
	"bytes"
	"testing"
)

func TestGeneratePNG(t *testing.T) {
	png, err := GeneratePNG("[Interface]\nPrivateKey = ...", 256)
	if err != nil {
		t.Fatalf("GeneratePNG failed: %v", err)
	}
	if len(png) == 0 {
		t.Fatal("empty PNG output")
	}

	// 验证 PNG 魔数: 89 50 4E 47 0D 0A 1A 0A
	pngHeader := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	if !bytes.HasPrefix(png, pngHeader) {
		t.Errorf("expected PNG header, got %x", png[:8])
	}
}
