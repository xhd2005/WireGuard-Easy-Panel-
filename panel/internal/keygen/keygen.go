package keygen

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// GeneratePrivateKey 生成符合 WireGuard 规范的 Curve25519 私钥（带位钳位）。
func GeneratePrivateKey() (string, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", fmt.Errorf("keygen: 生成随机数失败: %w", err)
	}
	// WireGuard Curve25519 标量钳位 (clamping)
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

// PublicKey 从 WireGuard 私钥推导对应的公钥。
func PublicKey(privKeyBase64 string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(privKeyBase64)
	if err != nil {
		return "", fmt.Errorf("keygen: 私钥 Base64 解码失败: %w", err)
	}
	if len(b) != 32 {
		return "", fmt.Errorf("keygen: 私钥长度必须为 32 字节，实为 %d", len(b))
	}
	var priv [32]byte
	copy(priv[:], b)

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("keygen: 计算公钥失败: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// GeneratePresharedKey 生成 32 字节高熵预共享密钥（PSK）。
func GeneratePresharedKey() (string, error) {
	var psk [32]byte
	if _, err := rand.Read(psk[:]); err != nil {
		return "", fmt.Errorf("keygen: 生成 PSK 失败: %w", err)
	}
	return base64.StdEncoding.EncodeToString(psk[:]), nil
}

// ValidateKey 检查密钥是否为合法的 32 字节 Base64 字符串。
func ValidateKey(key string) error {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return errors.New("不是合法的 Base64 字符串")
	}
	if len(b) != 32 {
		return fmt.Errorf("解码后长度必须为 32 字节，实为 %d", len(b))
	}
	return nil
}
