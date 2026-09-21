package qr

import (
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

// GeneratePNG 生成指定内容的 PNG 格式二维码。
func GeneratePNG(content string, size int) ([]byte, error) {
	if size <= 0 {
		size = 256
	}
	png, err := qrcode.Encode(content, qrcode.Medium, size)
	if err != nil {
		return nil, fmt.Errorf("qr: 生成二维码失败: %w", err)
	}
	return png, nil
}
