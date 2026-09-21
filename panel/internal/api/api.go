package api

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/xaxanb/wg/panel/internal/apply"
	"github.com/xaxanb/wg/panel/internal/auth"
	"github.com/xaxanb/wg/panel/internal/clientconf"
	"github.com/xaxanb/wg/panel/internal/config"
	"github.com/xaxanb/wg/panel/internal/keygen"
	"github.com/xaxanb/wg/panel/internal/qr"
	"github.com/xaxanb/wg/panel/internal/status"
	"github.com/xaxanb/wg/panel/internal/wgconf"
)

const (
	HeaderCSRF = "X-Requested-With"
	CSRFValue  = "wg-panel"
)

var reClientName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,15}$`)

// SystemReader 抽象系统读操作，使单元测试与生产实现解耦。
type SystemReader interface {
	ReadWGConf() ([]byte, error)
	ReadWGShow() (string, error)
	DetectFirewallBackend() string
}

// DefaultReader 生产环境真实读取实现。
type DefaultReader struct {
	ConfPath string
	Iface    string
}

func (r *DefaultReader) ReadWGConf() ([]byte, error) {
	return os.ReadFile(r.ConfPath)
}

func (r *DefaultReader) ReadWGShow() (string, error) {
	out, err := exec.Command("wg", "show", r.Iface).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("wg show %s: %w (%s)", r.Iface, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (r *DefaultReader) DetectFirewallBackend() string {
	var backends []string
	if out, err := exec.Command("ufw", "status").Output(); err == nil && strings.Contains(string(out), "active") {
		backends = append(backends, "ufw")
	}
	if err := exec.Command("systemctl", "is-active", "--quiet", "firewalld.service").Run(); err == nil {
		backends = append(backends, "firewalld")
	}
	if out, err := exec.Command("iptables", "-S", "INPUT").Output(); err == nil && strings.Contains(string(out), "YJ-FIREWALL-INPUT") {
		backends = append(backends, "1Panel(YJ-FIREWALL)")
	}
	if out, err := exec.Command("iptables", "-S", "FORWARD").Output(); err == nil && strings.Contains(string(out), "DOCKER") {
		backends = append(backends, "Docker")
	}
	if len(backends) == 0 {
		return "iptables"
	}
	return strings.Join(backends, " + ")
}

// Server 是面板的 HTTP API 服务。
type Server struct {
	cfg     *config.Config
	auth    *auth.Manager
	reader  SystemReader
	applier apply.Applier
	webFS   fs.FS
	mux     *http.ServeMux
}

// NewServer 构建并注册所有路由与中间件。
func NewServer(cfg *config.Config, authMgr *auth.Manager, reader SystemReader, applier apply.Applier, webFS fs.FS) *Server {
	if reader == nil {
		reader = &DefaultReader{ConfPath: cfg.WGConfPath, Iface: cfg.WGInterface}
	}
	if applier == nil {
		applier = apply.NewRealApplier(cfg.WGConfPath, cfg.WGInterface, cfg.BackupDir, filepath.Dir(cfg.StatePath))
	}
	s := &Server{
		cfg:     cfg,
		auth:    authMgr,
		reader:  reader,
		applier: applier,
		webFS:   webFS,
		mux:     http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) registerRoutes() {
	// 公开端点（登录、静态前端）
	s.mux.HandleFunc("POST /api/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/logout", s.handleLogout)
	s.mux.HandleFunc("GET /api/session", s.handleSession)
	s.mux.HandleFunc("GET /api/version", s.handleVersion)

	// 密码修改
	s.mux.HandleFunc("PUT /api/password", s.withAuth(s.handlePassword))

	// 只读业务端点
	s.mux.HandleFunc("GET /api/server", s.withAuth(s.handleServerInfo))
	s.mux.HandleFunc("GET /api/clients", s.withAuth(s.handleClientsList))
	s.mux.HandleFunc("GET /api/status", s.withAuth(s.handleStatus))
	s.mux.HandleFunc("GET /api/redistribution", s.withAuth(s.handleRedistributionStatus))

	// 阶段 4：写操作端点
	s.mux.HandleFunc("POST /api/clients", s.withAuth(s.handleAddClient))
	s.mux.HandleFunc("DELETE /api/clients/{name}", s.withAuth(s.handleDeleteClient))
	s.mux.HandleFunc("POST /api/clients/{name}/rotate-key", s.withAuth(s.handleRotateKey))
	s.mux.HandleFunc("GET /api/clients/{name}/config", s.withAuth(s.handleGetClientConfig))
	s.mux.HandleFunc("GET /api/clients/{name}/qr.png", s.withAuth(s.handleGetClientQR))

	// 阶段 5：变更与批量导出
	s.mux.HandleFunc("PUT /api/server/endpoint", s.withAuth(s.handleUpdateEndpoint))
	s.mux.HandleFunc("GET /api/clients/export.zip", s.withAuth(s.handleExportZip))

	// 嵌入静态前端资源
	if s.webFS != nil {
		fileServer := http.FileServer(http.FS(s.webFS))
		s.mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				s.jsonError(w, http.StatusNotFound, "not_found", "API 端点不存在")
				return
			}
			fileServer.ServeHTTP(w, r)
		})
	}
}

// withAuth 校验登录 Session 及 CSRF 头，并在强制改密期间限制访问范围。
func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			hdr := r.Header.Get(HeaderCSRF)
			if hdr != CSRFValue {
				s.jsonError(w, http.StatusForbidden, "csrf_rejected", "缺少合法的 X-Requested-With 头")
				return
			}
		}

		cookie, err := r.Cookie(auth.DefaultSessionCookie)
		if err != nil || cookie.Value == "" {
			s.jsonError(w, http.StatusUnauthorized, "unauthorized", "请先登录")
			return
		}

		sess, ok := s.auth.ValidateSession(cookie.Value)
		if !ok {
			s.jsonError(w, http.StatusUnauthorized, "session_expired", "登录会话已过期，请重新登录")
			return
		}

		if sess.MustChangePassword && r.URL.Path != "/api/password" && r.URL.Path != "/api/logout" && r.URL.Path != "/api/session" {
			s.jsonError(w, http.StatusForbidden, "password_change_required", "首次登录必须修改初始密码")
			return
		}

		next(w, r)
	}
}

// ----------------------------------------------------------- Auth Handlers

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(HeaderCSRF) != CSRFValue {
		s.jsonError(w, http.StatusForbidden, "csrf_rejected", "缺少合法的 X-Requested-With 头")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}

	token, sess, err := s.auth.Authenticate(req.Username, req.Password, r.RemoteAddr)
	if err != nil {
		s.jsonError(w, http.StatusUnauthorized, "login_failed", err.Error())
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     auth.DefaultSessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   !s.cfg.AllowInsecure,
	})

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"status":             "ok",
		"username":           sess.Username,
		"mustChangePassword": sess.MustChangePassword,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(auth.DefaultSessionCookie); err == nil && cookie.Value != "" {
		s.auth.DestroySession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.DefaultSessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	s.jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(auth.DefaultSessionCookie)
	if err != nil || cookie.Value == "" {
		s.jsonResponse(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	sess, ok := s.auth.ValidateSession(cookie.Value)
	if !ok {
		s.jsonResponse(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]any{
		"authenticated":      true,
		"username":           sess.Username,
		"mustChangePassword": sess.MustChangePassword,
	})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}
	cookie, _ := r.Cookie(auth.DefaultSessionCookie)
	sess, _ := s.auth.ValidateSession(cookie.Value)

	if err := s.auth.ChangePassword(sess.Username, req.OldPassword, req.NewPassword); err != nil {
		s.jsonError(w, http.StatusBadRequest, "change_password_failed", err.Error())
		return
	}
	s.jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ----------------------------------------------------------- Read-only Handlers

func (s *Server) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	data, err := s.reader.ReadWGConf()
	if errors.Is(err, os.ErrNotExist) {
		s.jsonResponse(w, http.StatusServiceUnavailable, map[string]any{
			"installed": false,
			"message":   "未检测到 WireGuard 配置文件，请先运行 wg.sh 安装脚本",
		})
		return
	}
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "read_conf_failed", err.Error())
		return
	}

	srv, err := wgconf.Parse(data)
	if err != nil {
		s.jsonError(w, http.StatusConflict, "config_unparseable", fmt.Sprintf("配置文件无法解析（只读降级模式）: %v", err))
		return
	}

	subnetV4, subnetV6 := "", ""
	for _, addr := range srv.Address {
		if strings.Contains(addr, ".") && subnetV4 == "" {
			subnetV4 = addr
		} else if strings.Contains(addr, ":") && subnetV6 == "" {
			subnetV6 = addr
		}
	}

	backend := s.reader.DetectFirewallBackend()

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"installed":       true,
		"endpoint":        srv.Endpoint,
		"listenPort":      srv.ListenPort,
		"mtu":             srv.MTU,
		"subnetV4":        subnetV4,
		"subnetV6":        subnetV6,
		"peersTotal":      len(srv.Peers),
		"firewallBackend": backend,
	})
}

func (s *Server) handleClientsList(w http.ResponseWriter, r *http.Request) {
	data, err := s.reader.ReadWGConf()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.jsonError(w, http.StatusServiceUnavailable, "not_installed", "配置文件不存在")
			return
		}
		s.jsonError(w, http.StatusInternalServerError, "read_conf_failed", err.Error())
		return
	}

	srv, err := wgconf.Parse(data)
	if err != nil {
		s.jsonError(w, http.StatusConflict, "config_unparseable", err.Error())
		return
	}

	type clientItem struct {
		Name      string   `json:"name"`
		IPv4      string   `json:"ipV4"`
		IPv6      string   `json:"ipV6"`
		PublicKey string   `json:"publicKey"`
		DNSKnown  bool     `json:"dnsKnown"`
		DNS       []string `json:"dns"`
	}

	list := make([]clientItem, 0, len(srv.Peers))
	for _, p := range srv.Peers {
		v4, v6 := "", ""
		for _, ip := range p.AllowedIPs {
			if strings.Contains(ip, ".") && v4 == "" {
				v4 = ip
			} else if strings.Contains(ip, ":") && v6 == "" {
				v6 = ip
			}
		}
		list = append(list, clientItem{
			Name:      p.Name,
			IPv4:      v4,
			IPv6:      v6,
			PublicKey: p.PublicKey,
			DNSKnown:  p.DNSKnown,
			DNS:       p.DNS,
		})
	}

	s.jsonResponse(w, http.StatusOK, list)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	raw, err := s.reader.ReadWGShow()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "wg_show_failed", err.Error())
		return
	}

	st, err := status.ParseShow(raw)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "parse_status_failed", err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, st)
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, http.StatusOK, map[string]string{
		"version":   s.cfg.Version,
		"commit":    s.cfg.Commit,
		"buildTime": s.cfg.BuildTime,
	})
}

// ----------------------------------------------------------- Phase 4: Write Handlers

func (s *Server) handleAddClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string   `json:"name"`
		DNS  []string `json:"dns"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "bad_request", "请求格式错误")
		return
	}

	name := strings.TrimSpace(req.Name)
	if !reClientName.MatchString(name) {
		s.jsonError(w, http.StatusBadRequest, "invalid_name", "客户端名称必须为 1-15 位的字母、数字、下划线或短横线")
		return
	}

	var generatedConf string
	var allocatedV4 string

	err := s.applier.WithLock(func() error {
		data, err := s.reader.ReadWGConf()
		if err != nil {
			return fmt.Errorf("读取配置失败: %w", err)
		}
		srv, err := wgconf.Parse(data)
		if err != nil {
			return fmt.Errorf("配置无法解析: %w", err)
		}
		if srv.HasPeer(name) {
			return errors.New("peer_exists")
		}

		octet, err := srv.AllocateOctet()
		if err != nil {
			return err
		}

		clientPriv, err := keygen.GeneratePrivateKey()
		if err != nil {
			return err
		}
		clientPub, err := keygen.PublicKey(clientPriv)
		if err != nil {
			return err
		}
		psk, err := keygen.GeneratePresharedKey()
		if err != nil {
			return err
		}
		srvPub, err := keygen.PublicKey(srv.PrivateKey)
		if err != nil {
			return err
		}

		v4 := fmt.Sprintf("10.7.0.%d/32", octet)
		allocatedV4 = v4
		allowedIPs := []string{v4}

		// 如果服务端配置了 IPv6，客户端同样分配同末段的 IPv6 地址
		clientV6 := ""
		for _, addr := range srv.Address {
			if strings.Contains(addr, ":") {
				prefix := strings.TrimSuffix(strings.Split(addr, "/")[0], "1")
				v6Sub := fmt.Sprintf("%s%d/128", prefix, octet)
				allowedIPs = append(allowedIPs, v6Sub)
				clientV6 = fmt.Sprintf("%s%d/64", prefix, octet)
				break
			}
		}

		if err := srv.AddPeer(name, clientPub, psk, allowedIPs, req.DNS); err != nil {
			return err
		}

		endpointStr := fmt.Sprintf("%s:%d", srv.Endpoint, srv.ListenPort)
		clientConfText := clientconf.Generate(clientconf.Params{
			ClientName:       name,
			ClientPrivateKey: clientPriv,
			ClientIPv4:       fmt.Sprintf("10.7.0.%d/24", octet),
			ClientIPv6:       clientV6,
			DNS:              req.DNS,
			ServerPublicKey:  srvPub,
			PresharedKey:     psk,
			ServerEndpoint:   endpointStr,
			MTU:              srv.MTU,
		})

		if _, err := s.applier.Backup(); err != nil {
			return err
		}
		if err := s.applier.WriteAtomic(srv.Marshal()); err != nil {
			return err
		}
		if err := s.applier.SyncConf(); err != nil {
			return err
		}
		if err := s.applier.SaveClientConf(name, clientConfText); err != nil {
			return err
		}

		generatedConf = clientConfText
		return nil
	})

	if err != nil {
		if err.Error() == "peer_exists" {
			s.jsonError(w, http.StatusConflict, "peer_exists", fmt.Sprintf("客户端 %s 已存在", name))
			return
		}
		s.jsonError(w, http.StatusInternalServerError, "add_client_failed", err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"name":   name,
		"ipV4":   allocatedV4,
		"config": generatedConf,
	})
}

func (s *Server) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		s.jsonError(w, http.StatusBadRequest, "bad_request", "缺少客户端名称")
		return
	}

	var orphanNotice string
	err := s.applier.WithLock(func() error {
		data, err := s.reader.ReadWGConf()
		if err != nil {
			return err
		}
		srv, err := wgconf.Parse(data)
		if err != nil {
			return err
		}
		if !srv.HasPeer(name) {
			return errors.New("not_found")
		}

		if err := srv.RemovePeer(name); err != nil {
			return err
		}

		if _, err := s.applier.Backup(); err != nil {
			return err
		}
		if err := s.applier.WriteAtomic(srv.Marshal()); err != nil {
			return err
		}
		if err := s.applier.SyncConf(); err != nil {
			return err
		}
		orphanNotice, _ = s.applier.DeleteClientConf(name)
		return nil
	})

	if err != nil {
		if err.Error() == "not_found" {
			s.jsonError(w, http.StatusNotFound, "not_found", fmt.Sprintf("客户端 %s 不存在", name))
			return
		}
		s.jsonError(w, http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"orphanNotice": orphanNotice,
	})
}

func (s *Server) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		s.jsonError(w, http.StatusBadRequest, "bad_request", "缺少客户端名称")
		return
	}

	var newConfText string
	err := s.applier.WithLock(func() error {
		data, err := s.reader.ReadWGConf()
		if err != nil {
			return err
		}
		srv, err := wgconf.Parse(data)
		if err != nil {
			return err
		}
		if !srv.HasPeer(name) {
			return errors.New("not_found")
		}

		newClientPriv, err := keygen.GeneratePrivateKey()
		if err != nil {
			return err
		}
		newClientPub, err := keygen.PublicKey(newClientPriv)
		if err != nil {
			return err
		}
		newPsk, err := keygen.GeneratePresharedKey()
		if err != nil {
			return err
		}
		srvPub, err := keygen.PublicKey(srv.PrivateKey)
		if err != nil {
			return err
		}

		if err := srv.ReplacePeerKey(name, newClientPub, newPsk); err != nil {
			return err
		}

		var p wgconf.Peer
		for _, peer := range srv.Peers {
			if peer.Name == name {
				p = peer
				break
			}
		}

		v4, v6 := "", ""
		for _, ip := range p.AllowedIPs {
			if strings.Contains(ip, ".") && v4 == "" {
				v4 = fmt.Sprintf("10.7.0.%d/24", p.IPv4Octet())
			} else if strings.Contains(ip, ":") && v6 == "" {
				v6 = fmt.Sprintf("fddd:2c4:2c4:2c4::%d/64", p.IPv4Octet())
			}
		}

		newConfText = clientconf.Generate(clientconf.Params{
			ClientName:       name,
			ClientPrivateKey: newClientPriv,
			ClientIPv4:       v4,
			ClientIPv6:       v6,
			DNS:              p.DNS,
			ServerPublicKey:  srvPub,
			PresharedKey:     newPsk,
			ServerEndpoint:   fmt.Sprintf("%s:%d", srv.Endpoint, srv.ListenPort),
			MTU:              srv.MTU,
		})

		if _, err := s.applier.Backup(); err != nil {
			return err
		}
		if err := s.applier.WriteAtomic(srv.Marshal()); err != nil {
			return err
		}
		if err := s.applier.SyncConf(); err != nil {
			return err
		}
		return s.applier.SaveClientConf(name, newConfText)
	})

	if err != nil {
		if err.Error() == "not_found" {
			s.jsonError(w, http.StatusNotFound, "not_found", fmt.Sprintf("客户端 %s 不存在", name))
			return
		}
		s.jsonError(w, http.StatusInternalServerError, "rotate_key_failed", err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"name":   name,
		"config": newConfText,
	})
}

func (s *Server) handleGetClientConfig(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	conf, err := s.applier.ReadClientConf(name)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+".conf"))
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(conf))
}

func (s *Server) handleGetClientQR(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	conf, err := s.applier.ReadClientConf(name)
	if err != nil {
		s.jsonError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}

	png, err := qr.GeneratePNG(conf, 320)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "qr_failed", err.Error())
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

// ----------------------------------------------------------- Phase 5: Mutation & Batch Handlers

func (s *Server) handleUpdateEndpoint(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ListenPort int    `json:"listenPort"`
		Endpoint   string `json:"endpoint"`
		MTU        int    `json:"mtu"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, http.StatusBadRequest, "bad_request", "请求体格式错误")
		return
	}

	err := s.applier.WithLock(func() error {
		data, err := s.reader.ReadWGConf()
		if err != nil {
			return err
		}
		srv, err := wgconf.Parse(data)
		if err != nil {
			return err
		}

		portChanged := req.ListenPort > 0 && req.ListenPort != srv.ListenPort
		endpointChanged := req.Endpoint != "" && req.Endpoint != srv.Endpoint
		mtuChanged := req.MTU > 0 && req.MTU != srv.MTU

		if !portChanged && !endpointChanged && !mtuChanged {
			return nil
		}

		if portChanged {
			if ln, err := net.Listen("udp", fmt.Sprintf(":%d", req.ListenPort)); err != nil {
				return fmt.Errorf("目标端口 %d 已被占用: %w", req.ListenPort, err)
			} else {
				_ = ln.Close()
			}
			if err := srv.SetListenPort(req.ListenPort); err != nil {
				return err
			}
		}

		if endpointChanged {
			if err := srv.SetEndpoint(req.Endpoint); err != nil {
				return err
			}
		}

		if mtuChanged {
			if err := srv.SetMTU(req.MTU); err != nil {
				return err
			}
		}

		if _, err := s.applier.Backup(); err != nil {
			return err
		}
		if err := s.applier.WriteAtomic(srv.Marshal()); err != nil {
			return err
		}

		if portChanged {
			if strings.Contains(s.reader.DetectFirewallBackend(), "firewalld") {
				_ = exec.Command("firewall-cmd", "-q", fmt.Sprintf("--remove-port=%d/udp", srv.ListenPort)).Run()
				_ = exec.Command("firewall-cmd", "-q", "--permanent", fmt.Sprintf("--remove-port=%d/udp", srv.ListenPort)).Run()
				_ = exec.Command("firewall-cmd", "-q", fmt.Sprintf("--add-port=%d/udp", req.ListenPort)).Run()
				_ = exec.Command("firewall-cmd", "-q", "--permanent", fmt.Sprintf("--add-port=%d/udp", req.ListenPort)).Run()
			} else {
				_ = s.applier.RestartService("wg-iptables.service")
			}
		}

		if err := s.applier.RestartService(fmt.Sprintf("wg-quick@%s.service", s.cfg.WGInterface)); err != nil {
			return err
		}

		srvPub, _ := keygen.PublicKey(srv.PrivateKey)
		endpointStr := fmt.Sprintf("%s:%d", srv.Endpoint, srv.ListenPort)
		oldConfs, _ := s.applier.ListClientConfs()

		for _, p := range srv.Peers {
			oldText := oldConfs[p.Name]
			clientPriv := extractClientPrivateKey(oldText)
			if clientPriv == "" {
				continue
			}

			v4, v6 := "", ""
			for _, ip := range p.AllowedIPs {
				if strings.Contains(ip, ".") && v4 == "" {
					v4 = fmt.Sprintf("10.7.0.%d/24", p.IPv4Octet())
				} else if strings.Contains(ip, ":") && v6 == "" {
					v6 = fmt.Sprintf("fddd:2c4:2c4:2c4::%d/64", p.IPv4Octet())
				}
			}

			updatedConf := clientconf.Generate(clientconf.Params{
				ClientName:       p.Name,
				ClientPrivateKey: clientPriv,
				ClientIPv4:       v4,
				ClientIPv6:       v6,
				DNS:              p.DNS,
				ServerPublicKey:  srvPub,
				PresharedKey:     p.PresharedKey,
				ServerEndpoint:   endpointStr,
				MTU:              srv.MTU,
			})
			_ = s.applier.SaveClientConf(p.Name, updatedConf)
		}

		s.saveRedistributionState(time.Now().Unix(), len(srv.Peers))
		return nil
	})

	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "update_endpoint_failed", err.Error())
		return
	}

	s.jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleExportZip(w http.ResponseWriter, r *http.Request) {
	confs, err := s.applier.ListClientConfs()
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, "list_confs_failed", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\"wireguard-clients.zip\"")
	w.Header().Set("Cache-Control", "no-store")

	zw := zip.NewWriter(w)
	defer zw.Close()

	for name, content := range confs {
		fw, err := zw.Create(name + ".conf")
		if err != nil {
			continue
		}
		_, _ = fw.Write([]byte(content))
	}
}

func (s *Server) handleRedistributionStatus(w http.ResponseWriter, r *http.Request) {
	type State struct {
		Needed    bool  `json:"needed"`
		ChangedAt int64 `json:"changedAt"`
	}
	var state State
	b, err := os.ReadFile(s.cfg.StatePath)
	if err == nil {
		_ = json.Unmarshal(b, &state)
	}

	pending := []string{}
	if state.Needed {
		if raw, err := s.reader.ReadWGShow(); err == nil {
			if st, err := status.ParseShow(raw); err == nil {
				for _, p := range st.Peers {
					if p.HandshakeTime < state.ChangedAt {
						pending = append(pending, p.PublicKey)
					}
				}
				if len(pending) == 0 && len(st.Peers) > 0 {
					state.Needed = false
					s.saveRedistributionState(0, 0)
				}
			}
		}
	}

	s.jsonResponse(w, http.StatusOK, map[string]any{
		"needed":       state.Needed,
		"changedAt":    state.ChangedAt,
		"pendingPeers": pending,
	})
}

func (s *Server) saveRedistributionState(changedAt int64, peerCount int) {
	_ = os.MkdirAll(filepath.Dir(s.cfg.StatePath), 0700)
	state := map[string]any{
		"needed":    changedAt > 0,
		"changedAt": changedAt,
		"peerCount": peerCount,
	}
	b, _ := json.Marshal(state)
	_ = os.WriteFile(s.cfg.StatePath, b, 0600)
}

func extractClientPrivateKey(conf string) string {
	for _, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), "privatekey") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// ----------------------------------------------------------- Helpers

func (s *Server) jsonResponse(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) jsonError(w http.ResponseWriter, code int, errCode, msg string) {
	s.jsonResponse(w, code, map[string]any{
		"error": map[string]string{
			"code":    errCode,
			"message": msg,
		},
	})
}
