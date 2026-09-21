package clientconf

import (
	"strings"
	"testing"
)

func TestGenerateFullTunnel(t *testing.T) {
	p := Params{
		ClientName:       "windows-pc",
		ClientPrivateKey: "wFxSCo8a5+PoZcKx8Q+LoS31VBMGOmztUUTcqi5hl0c=",
		ClientIPv4:       "10.7.0.2/24",
		ClientIPv6:       "fddd:2c4:2c4:2c4::2/64",
		DNS:              []string{"223.5.5.5", "119.29.29.29"},
		ServerPublicKey:  "rXMT3K0AM9I5B7D/S5f/HaLaUP7yVyZdQRFfRuenlRE=",
		PresharedKey:     "zDcuEpcFz1DNPyoVVBWItbOOzqHDrW4smBn/IKam1xM=",
		ServerEndpoint:   "198.51.100.1:51820",
		MTU:              1420,
		RouteMode:        RouteModeFull,
	}

	conf := Generate(p)

	if !strings.Contains(conf, "Address = 10.7.0.2/24, fddd:2c4:2c4:2c4::2/64") {
		t.Errorf("Address missing or wrong: %s", conf)
	}
	if !strings.Contains(conf, "DNS = 223.5.5.5, 119.29.29.29") {
		t.Errorf("DNS missing or wrong: %s", conf)
	}
	if !strings.Contains(conf, "PrivateKey = wFxSCo8a5+PoZcKx8Q+LoS31VBMGOmztUUTcqi5hl0c=") {
		t.Errorf("PrivateKey missing: %s", conf)
	}
	if !strings.Contains(conf, "Endpoint = 198.51.100.1:51820") {
		t.Errorf("Endpoint missing: %s", conf)
	}
	if !strings.Contains(conf, "AllowedIPs = 0.0.0.0/0, ::/0") {
		t.Errorf("AllowedIPs should be full tunnel: %s", conf)
	}
}

func TestGenerateSplitTunnel(t *testing.T) {
	p := Params{
		ClientName:       "phone",
		ClientPrivateKey: "wFxSCo8a5+PoZcKx8Q+LoS31VBMGOmztUUTcqi5hl0c=",
		ClientIPv4:       "10.7.0.5/24",
		ServerPublicKey:  "rXMT3K0AM9I5B7D/S5f/HaLaUP7yVyZdQRFfRuenlRE=",
		PresharedKey:     "zDcuEpcFz1DNPyoVVBWItbOOzqHDrW4smBn/IKam1xM=",
		ServerEndpoint:   "vpn.example.com:51820",
		ServerSubnetV4:   "10.7.0.0/24",
		RouteMode:        RouteModeSplit,
	}

	conf := Generate(p)

	// 分流模式下 AllowedIPs 应仅为虚拟子网，绝不是 0.0.0.0/0
	if !strings.Contains(conf, "AllowedIPs = 10.7.0.0/24") {
		t.Errorf("AllowedIPs should be 10.7.0.0/24 in split mode: %s", conf)
	}
	if strings.Contains(conf, "0.0.0.0/0") {
		t.Errorf("split mode should not contain 0.0.0.0/0: %s", conf)
	}
	// 未指定 DNS 时应回退到 DefaultPublicDNS
	if !strings.Contains(conf, "DNS = 1.1.1.1, 8.8.8.8") {
		t.Errorf("expected DefaultPublicDNS fallback: %s", conf)
	}
}
