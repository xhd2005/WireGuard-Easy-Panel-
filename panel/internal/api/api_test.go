package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xaxanb/wg/panel/internal/auth"
	"github.com/xaxanb/wg/panel/internal/config"
)

type mockReader struct {
	confData []byte
	confErr  error
	showData string
	showErr  error
	backend  string
}

func (m *mockReader) ReadWGConf() ([]byte, error) {
	return m.confData, m.confErr
}

func (m *mockReader) ReadWGShow() (string, error) {
	return m.showData, m.showErr
}

func (m *mockReader) DetectFirewallBackend() string {
	if m.backend != "" {
		return m.backend
	}
	return "iptables-nft + ufw + 1Panel + Docker"
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	p := filepath.Join("..", "..", "..", "fixtures", name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("load fixture %s failed: %v", p, err)
	}
	return b
}

func setupTestServer(t *testing.T, reader SystemReader) (*Server, string) {
	t.Helper()
	credPath := filepath.Join(t.TempDir(), "credentials.json")
	authMgr, initPass, err := auth.NewManager(credPath, time.Hour)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	cfg := config.Default()
	cfg.CredentialsPath = credPath
	srv := NewServer(cfg, authMgr, reader, nil)
	return srv, initPass
}

func TestLoginLogoutAndSession(t *testing.T) {
	srv, initPass := setupTestServer(t, &mockReader{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := ts.Client()

	// 1. 无 CSRF 头的登录应被 403 拒绝
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": initPass})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/login", bytes.NewReader(body))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 without CSRF header, got %d", resp.StatusCode)
	}

	// 2. 错误密码登录应被 401 拒绝
	badBody, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrong-password"})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/login", bytes.NewReader(badBody))
	req.Header.Set(HeaderCSRF, CSRFValue)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 on wrong password, got %d", resp.StatusCode)
	}

	// 3. 正确密码登录应成功，并返回 Cookie
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/login", bytes.NewReader(body))
	req.Header.Set(HeaderCSRF, CSRFValue)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on login, got %d", resp.StatusCode)
	}

	var sessionCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == auth.DefaultSessionCookie {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("login response missing session cookie")
	}

	// 4. 查询当前 Session
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/session", nil)
	req.AddCookie(sessionCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var sessData struct {
		Authenticated      bool   `json:"authenticated"`
		Username           string `json:"username"`
		MustChangePassword bool   `json:"mustChangePassword"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&sessData)
	if !sessData.Authenticated || sessData.Username != "admin" || !sessData.MustChangePassword {
		t.Errorf("unexpected session data: %+v", sessData)
	}

	// 5. 登出
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/logout", nil)
	req.Header.Set(HeaderCSRF, CSRFValue)
	req.AddCookie(sessionCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 on logout, got %d", resp.StatusCode)
	}

	// 6. 登出后再查 session 应为未认证
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/session", nil)
	req.AddCookie(sessionCookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var sessData2 struct {
		Authenticated bool `json:"authenticated"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&sessData2)
	if sessData2.Authenticated {
		t.Error("session should be invalid after logout")
	}
}

func TestForcedPasswordChangeGating(t *testing.T) {
	srv, initPass := setupTestServer(t, &mockReader{confData: loadFixture(t, "wg0-ipv6.conf")})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := ts.Client()

	// 登录拿到 session（处于 MustChangePassword 状态）
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": initPass})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/login", bytes.NewReader(body))
	req.Header.Set(HeaderCSRF, CSRFValue)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cookie := resp.Cookies()[0]

	// 1. 尝试访问常规业务接口 /api/server，应被 403 阻断（强制改密门禁）
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/server", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 when MustChangePassword=true, got %d", resp.StatusCode)
	}

	// 2. 访问 /api/password 修改密码
	pwdBody, _ := json.Marshal(map[string]string{
		"oldPassword": initPass,
		"newPassword": "newSafePassword123",
	})
	req, _ = http.NewRequest(http.MethodPut, ts.URL+"/api/password", bytes.NewReader(pwdBody))
	req.Header.Set(HeaderCSRF, CSRFValue)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on password change, got %d", resp.StatusCode)
	}

	// 3. 改密后再次访问 /api/server，应顺利通过 200
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/server", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 on /api/server after password change, got %d", resp.StatusCode)
	}
}

func TestServerAndClientsListReadOnly(t *testing.T) {
	fixtureData := loadFixture(t, "wg0-ipv6.conf")
	srv, initPass := setupTestServer(t, &mockReader{
		confData: fixtureData,
		backend:  "iptables-nft + ufw + 1Panel + Docker",
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := ts.Client()

	// 登录并修改初始密码
	cookie := loginAndClearMustChange(t, ts, client, initPass)

	// 测试 GET /api/server
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/server", nil)
	req.AddCookie(cookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var srvInfo struct {
		Installed       bool   `json:"installed"`
		Endpoint        string `json:"endpoint"`
		ListenPort      int    `json:"listenPort"`
		SubnetV4        string `json:"subnetV4"`
		SubnetV6        string `json:"subnetV6"`
		PeersTotal      int    `json:"peersTotal"`
		FirewallBackend string `json:"firewallBackend"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&srvInfo)
	if !srvInfo.Installed || srvInfo.Endpoint != "203.0.51.10" || srvInfo.ListenPort != 53 {
		t.Errorf("unexpected server info: %+v", srvInfo)
	}
	if srvInfo.PeersTotal != 2 {
		t.Errorf("expected 2 peers, got %d", srvInfo.PeersTotal)
	}
	if srvInfo.FirewallBackend != "iptables-nft + ufw + 1Panel + Docker" {
		t.Errorf("unexpected firewall backend: %s", srvInfo.FirewallBackend)
	}

	// 测试 GET /api/clients
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/clients", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var clients []struct {
		Name      string   `json:"name"`
		IPv4      string   `json:"ipV4"`
		IPv6      string   `json:"ipV6"`
		PublicKey string   `json:"publicKey"`
		DNSKnown  bool     `json:"dnsKnown"`
		DNS       []string `json:"dns"`
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	rawResp := buf.String()

	if err := json.Unmarshal([]byte(rawResp), &clients); err != nil {
		t.Fatalf("unmarshal clients failed: %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("expected 2 clients, got %d", len(clients))
	}
	if clients[0].Name != "phone" || clients[1].Name != "laptop" {
		t.Errorf("unexpected client names: %v, %v", clients[0].Name, clients[1].Name)
	}
	if clients[0].DNSKnown || !clients[1].DNSKnown {
		t.Errorf("unexpected dnsKnown values: phone=%t laptop=%t", clients[0].DNSKnown, clients[1].DNSKnown)
	}

	// ⚠️ 极其关键的安全测试（spec 10 / 16.14）：
	// /api/clients 的响应体绝对不得包含任何 PrivateKey 或 PresharedKey 字符串！
	if strings.Contains(strings.ToLower(rawResp), "privatekey") {
		t.Errorf("🔥 敏感信息泄露：/api/clients 响应体中包含 privatekey: %s", rawResp)
	}
	if strings.Contains(strings.ToLower(rawResp), "presharedkey") {
		t.Errorf("🔥 敏感信息泄露：/api/clients 响应体中包含 presharedkey: %s", rawResp)
	}
}

func TestStatusEndpoint(t *testing.T) {
	showRaw := loadFixture(t, "wg-show-single-peer.txt")
	srv, initPass := setupTestServer(t, &mockReader{showData: string(showRaw)})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := ts.Client()

	cookie := loginAndClearMustChange(t, ts, client, initPass)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/status", nil)
	req.AddCookie(cookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /api/status, got %d", resp.StatusCode)
	}

	var st struct {
		Interface  string `json:"interface"`
		ListenPort int    `json:"listenPort"`
		Peers      []struct {
			PublicKey string `json:"publicKey"`
			Endpoint  string `json:"endpoint"`
		} `json:"peers"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&st)
	if st.Interface != "wg0" || st.ListenPort != 53 || len(st.Peers) != 1 {
		t.Errorf("unexpected status response: %+v", st)
	}
}

func TestConfigUnparseableFallback(t *testing.T) {
	srv, initPass := setupTestServer(t, &mockReader{
		confData: []byte("broken config without interface section"),
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := ts.Client()

	cookie := loginAndClearMustChange(t, ts, client, initPass)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/server", nil)
	req.AddCookie(cookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409 config_unparseable, got %d", resp.StatusCode)
	}
}

func TestVersionEndpoint(t *testing.T) {
	srv, _ := setupTestServer(t, &mockReader{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/api/version")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	var ver map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&ver)
	if ver["version"] == "" {
		t.Errorf("empty version response: %v", ver)
	}
}

func loginAndClearMustChange(t *testing.T, ts *httptest.Server, client *http.Client, initPass string) *http.Cookie {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": initPass})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/login", bytes.NewReader(body))
	req.Header.Set(HeaderCSRF, CSRFValue)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cookie := resp.Cookies()[0]

	pwdBody, _ := json.Marshal(map[string]string{"oldPassword": initPass, "newPassword": "newSafePassword123"})
	req, _ = http.NewRequest(http.MethodPut, ts.URL+"/api/password", bytes.NewReader(pwdBody))
	req.Header.Set(HeaderCSRF, CSRFValue)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clear mustChangePassword failed with status %d", resp.StatusCode)
	}
	return cookie
}
