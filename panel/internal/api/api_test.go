package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xaxanb/wg/panel/internal/apply"
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

type testApplier struct {
	mu        sync.Mutex
	reader    *mockReader
	backups   []string
	confs     map[string]string
	restarted []string
}

func newTestApplier(reader *mockReader) *testApplier {
	return &testApplier{
		reader: reader,
		confs:  make(map[string]string),
	}
}

func (a *testApplier) WithLock(fn func() error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return fn()
}

func (a *testApplier) Backup() (string, error) {
	bak := fmt.Sprintf("backup-%d.bak", len(a.backups))
	a.backups = append(a.backups, bak)
	return bak, nil
}

func (a *testApplier) ListBackups() ([]apply.BackupInfo, error) {
	var list []apply.BackupInfo
	for _, b := range a.backups {
		list = append(list, apply.BackupInfo{Filename: b, CreatedAt: time.Now(), Size: 100})
	}
	return list, nil
}

func (a *testApplier) GetBackup(filename string) ([]byte, error) {
	return a.reader.confData, nil
}

func (a *testApplier) RestoreBackup(filename string) error {
	return nil
}

func (a *testApplier) WriteAtomic(data []byte) error {
	a.reader.confData = data
	return nil
}

func (a *testApplier) SyncConf() error {
	return nil
}

func (a *testApplier) RestartService(name string) error {
	a.restarted = append(a.restarted, name)
	return nil
}

func (a *testApplier) SaveClientConf(name, content string) error {
	a.confs[name] = content
	return nil
}

func (a *testApplier) DeleteClientConf(name string) (string, error) {
	delete(a.confs, name)
	return "提示：请检查家目录遗留配置", nil
}

func (a *testApplier) ReadClientConf(name string) (string, error) {
	c, ok := a.confs[name]
	if !ok {
		return "", fmt.Errorf("client %s not found", name)
	}
	return c, nil
}

func (a *testApplier) ListClientConfs() (map[string]string, error) {
	res := make(map[string]string)
	for k, v := range a.confs {
		res[k] = v
	}
	return res, nil
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

func setupTestServer(t *testing.T, reader SystemReader, applier apply.Applier) (*Server, string) {
	t.Helper()
	credPath := filepath.Join(t.TempDir(), "credentials.json")
	authMgr, initPass, err := auth.NewManager(credPath, time.Hour)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	cfg := config.Default()
	cfg.CredentialsPath = credPath
	cfg.StatePath = filepath.Join(t.TempDir(), "state.json")
	srv := NewServer(cfg, authMgr, reader, applier, nil)
	return srv, initPass
}

func TestLoginLogoutAndSession(t *testing.T) {
	srv, initPass := setupTestServer(t, &mockReader{}, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := ts.Client()

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": initPass})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/login", bytes.NewReader(body))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 without CSRF header, got %d", resp.StatusCode)
	}

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
}

func TestForcedPasswordChangeGating(t *testing.T) {
	srv, initPass := setupTestServer(t, &mockReader{confData: loadFixture(t, "wg0-ipv6.conf")}, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := ts.Client()

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": initPass})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/login", bytes.NewReader(body))
	req.Header.Set(HeaderCSRF, CSRFValue)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cookie := resp.Cookies()[0]

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/server", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 when MustChangePassword=true, got %d", resp.StatusCode)
	}

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
	}, nil)
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/clients", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	rawResp := buf.String()

	if strings.Contains(strings.ToLower(rawResp), "privatekey") {
		t.Errorf("🔥 敏感信息泄露：/api/clients 响应体中包含 privatekey: %s", rawResp)
	}
	if strings.Contains(strings.ToLower(rawResp), "presharedkey") {
		t.Errorf("🔥 敏感信息泄露：/api/clients 响应体中包含 presharedkey: %s", rawResp)
	}
}

func TestPhase4AddClientDownloadConfigAndQR(t *testing.T) {
	fixtureData := loadFixture(t, "wg0-ipv6.conf")
	reader := &mockReader{confData: fixtureData}
	applier := newTestApplier(reader)
	srv, initPass := setupTestServer(t, reader, applier)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := ts.Client()
	cookie := loginAndClearMustChange(t, ts, client, initPass)

	// 1. POST /api/clients (添加 windows-pc)
	addReq, _ := json.Marshal(map[string]any{
		"name": "windows-pc",
		"dns":  []string{"183.60.83.19", "183.60.82.98"},
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/clients", bytes.NewReader(addReq))
	req.Header.Set(HeaderCSRF, CSRFValue)
	req.AddCookie(cookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on add client, got %d", resp.StatusCode)
	}

	var added struct {
		Name   string `json:"name"`
		IPv4   string `json:"ipV4"`
		Config string `json:"config"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&added)
	if added.Name != "windows-pc" || added.IPv4 != "10.7.0.4/32" {
		t.Errorf("unexpected added client: %+v", added)
	}
	if !strings.Contains(added.Config, "[Interface]") || !strings.Contains(added.Config, "Address = 10.7.0.4/24") {
		t.Errorf("unexpected config text: %s", added.Config)
	}

	// 2. GET /api/clients/windows-pc/config
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/clients/windows-pc/config", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on get config, got %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Disposition"), "windows-pc.conf") {
		t.Errorf("wrong disposition: %s", resp.Header.Get("Content-Disposition"))
	}

	// 测试传入自定义端口 ?port=8443
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/clients/windows-pc/config?port=8443", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	bufConf := new(bytes.Buffer)
	_, _ = bufConf.ReadFrom(resp.Body)
	if !strings.Contains(bufConf.String(), ":8443") {
		t.Errorf("expected :8443 in config, got %s", bufConf.String())
	}

	// 3. GET /api/clients/windows-pc/qr.png
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/clients/windows-pc/qr.png", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on get qr, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "image/png" {
		t.Errorf("expected image/png, got %s", resp.Header.Get("Content-Type"))
	}

	// 4. POST /api/clients/windows-pc/rotate-key
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/clients/windows-pc/rotate-key", nil)
	req.Header.Set(HeaderCSRF, CSRFValue)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on rotate-key, got %d", resp.StatusCode)
	}

	// 5. DELETE /api/clients/windows-pc
	req, _ = http.NewRequest(http.MethodDelete, ts.URL+"/api/clients/windows-pc", nil)
	req.Header.Set(HeaderCSRF, CSRFValue)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on delete, got %d", resp.StatusCode)
	}

	// 再次获取应 404
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/clients/windows-pc/config", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 after delete, got %d", resp.StatusCode)
	}
}

func TestPhase2NewEndpoints(t *testing.T) {
	fixtureData := loadFixture(t, "wg0-ipv6.conf")
	reader := &mockReader{confData: fixtureData}
	applier := newTestApplier(reader)
	srv, initPass := setupTestServer(t, reader, applier)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := ts.Client()
	cookie := loginAndClearMustChange(t, ts, client, initPass)

	// 1. GET /api/system/stats
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/system/stats", nil)
	req.AddCookie(cookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /api/system/stats, got %d", resp.StatusCode)
	}

	// 2. PUT /api/clients/phone/disable
	req, _ = http.NewRequest(http.MethodPut, ts.URL+"/api/clients/phone/disable", nil)
	req.Header.Set(HeaderCSRF, CSRFValue)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on disable, got %d", resp.StatusCode)
	}

	// 验证 /api/clients 显示 disabled=true
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/clients", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var clients []struct {
		Name     string `json:"name"`
		Disabled bool   `json:"disabled"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&clients)
	if len(clients) < 1 || !clients[0].Disabled {
		t.Errorf("expected phone to be disabled: %+v", clients)
	}

	// 3. PUT /api/clients/phone/enable
	req, _ = http.NewRequest(http.MethodPut, ts.URL+"/api/clients/phone/enable", nil)
	req.Header.Set(HeaderCSRF, CSRFValue)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on enable, got %d", resp.StatusCode)
	}

	// 4. GET /api/clients/phone/config?mode=split (测试分流 AllowedIPs)
	_ = applier.SaveClientConf("phone", "[Interface]\nAddress = 10.7.0.2/24\nPrivateKey = test\n\n[Peer]\nAllowedIPs = 0.0.0.0/0, ::/0\n")
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/clients/phone/config?mode=split", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	if !strings.Contains(buf.String(), "AllowedIPs = 10.7.0.0/24") {
		t.Errorf("split mode should use 10.7.0.0/24: %s", buf.String())
	}

	// 5. 备份管理端点测试
	// POST /api/backups (创建即时快照)
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/backups", nil)
	req.Header.Set(HeaderCSRF, CSRFValue)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on create backup, got %d", resp.StatusCode)
	}

	// GET /api/backups (获取备份列表)
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/backups", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on list backups, got %d", resp.StatusCode)
	}
	var backups []struct {
		Filename string `json:"filename"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&backups)
	if len(backups) == 0 {
		t.Fatal("expected at least 1 backup in list")
	}

	// POST /api/backups/{filename}/restore (测试恢复)
	restoreURL := fmt.Sprintf("%s/api/backups/%s/restore", ts.URL, backups[0].Filename)
	req, _ = http.NewRequest(http.MethodPost, restoreURL, nil)
	req.Header.Set(HeaderCSRF, CSRFValue)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on restore backup, got %d", resp.StatusCode)
	}
}

func TestPhase5ExportZipAndUpdateEndpoint(t *testing.T) {
	fixtureData := loadFixture(t, "wg0-ipv6.conf")
	reader := &mockReader{confData: fixtureData}
	applier := newTestApplier(reader)
	srv, initPass := setupTestServer(t, reader, applier)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := ts.Client()
	cookie := loginAndClearMustChange(t, ts, client, initPass)

	_ = applier.SaveClientConf("laptop", "[Interface]\nAddress=10.7.0.3/24\nPrivateKey=test\n")

	// 1. GET /api/clients/export.zip
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/clients/export.zip", nil)
	req.AddCookie(cookie)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on export.zip, got %d", resp.StatusCode)
	}
	zipBytes := new(bytes.Buffer)
	_, _ = zipBytes.ReadFrom(resp.Body)
	zr, err := zip.NewReader(bytes.NewReader(zipBytes.Bytes()), int64(zipBytes.Len()))
	if err != nil {
		t.Fatalf("invalid zip: %v", err)
	}
	if len(zr.File) != 1 || zr.File[0].Name != "laptop.conf" {
		t.Errorf("unexpected zip files: %v", zr.File)
	}

	// 2. PUT /api/server/endpoint
	epReq, _ := json.Marshal(map[string]any{
		"endpoint": "wg.example.org",
		"mtu":      1360,
	})
	req, _ = http.NewRequest(http.MethodPut, ts.URL+"/api/server/endpoint", bytes.NewReader(epReq))
	req.Header.Set(HeaderCSRF, CSRFValue)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on update endpoint, got %d", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/server", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var srvInfo struct {
		Endpoint string `json:"endpoint"`
		MTU      int    `json:"mtu"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&srvInfo)
	if srvInfo.Endpoint != "wg.example.org" || srvInfo.MTU != 1360 {
		t.Errorf("endpoint or mtu not updated: %+v", srvInfo)
	}

	// 3. GET /api/redistribution
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/api/redistribution", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /api/redistribution, got %d", resp.StatusCode)
	}
	var redist struct {
		Needed bool `json:"needed"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&redist)
	if !redist.Needed {
		t.Error("expected redistribution.needed = true after endpoint change")
	}
}

func TestStatusEndpoint(t *testing.T) {
	showRaw := loadFixture(t, "wg-show-single-peer.txt")
	srv, initPass := setupTestServer(t, &mockReader{showData: string(showRaw)}, nil)
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
	}, nil)
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
	srv, _ := setupTestServer(t, &mockReader{}, nil)
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
