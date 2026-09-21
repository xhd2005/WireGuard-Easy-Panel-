package clientconf

import (
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	p := Params{
		ClientName:       "windows-pc",
		ClientPrivateKey: "wFxSCo8a5+PoZcKx8Q+LoS31VBMGOmztUUTcqi5hl0c=",
		ClientIPv4:       "10.7.0.2/24",
		ClientIPv6:       "fddd:2c4:2c4:2c4::2/64",
		DNS:              []string{"183.60.83.19", "183.60.82.98"},
		ServerPublicKey:  "rXMT3K0AM9I5B7D/S5f/HaLaUP7yVyZdQRFfRuenlRE=",
		PresharedKey:     "zDcuEpcFz1DNPyoVVBWItbOOzqHDrW4smBn/IKam1xM=",
		ServerEndpoint:   "49.233.166.212:53",
		MTU:              1420,
	}

	conf := Generate(p)

	if !strings.Contains(conf, "Address = 10.7.0.2/24, fddd:2c4:2c4:2c4::2/64") {
		t.Errorf("Address missing or wrong: %s", conf)
	}
	if !strings.Contains(conf, "DNS = 183.60.83.19, 183.60.82.98") {
		t.Errorf("DNS missing or wrong: %s", conf)
	}
	if !strings.Contains(conf, "PrivateKey = wFxSCo8a5+PoZcKx8Q+LoS31VBMGOmztUUTcqi5hl0c=") {
		t.Errorf("PrivateKey missing: %s", conf)
	}
	if !strings.Contains(conf, "Endpoint = 49.233.166.212:53") {
		t.Errorf("Endpoint missing: %s", conf)
	}
	if !strings.Contains(conf, "MTU = 1420") {
		t.Errorf("MTU missing: %s", conf)
	}
}
