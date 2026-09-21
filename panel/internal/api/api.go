package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/xaxanb/wg/panel/internal/auth"
	"github.com/xaxanb/wg/panel/internal/config"
	"github.com/xaxanb/wg/panel/internal/status"
	"github.com/xaxanb/wg/panel/internal/wgconf"
)

const (
	HeaderCSRF = "X-Requested-With"
	CSRFValue  = "wg-panel"
)

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
	cfg    *config.Config
	auth   *auth.Manager
	reader SystemReader
	webFS  fs.FS
	mux    *http.ServeMux
}

// NewServer 构建并注册所有路由与中间件。
func NewServer(cfg *config.Config, authMgr *auth.Manager, reader SystemReader, webFS fs.FS) *Server {
	if reader == nil {
		reader = &DefaultReader{ConfPath: cfg.WGConfPath, Iface: cfg.WGInterface}
	}
	s := &Server{
		cfg:    cfg,
		auth:   authMgr,
		reader: reader,
		webFS:  webFS,
		mux:    http.NewServeMux(),
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

	// 密码修改（受 session 保护，但允许处于 mustChangePassword 状态的用户访问）
	s.mux.HandleFunc("PUT /api/password", s.withAuth(s.handlePassword))

	// 只读业务端点（要求已认证且不可处于 mustChangePassword 状态）
	s.mux.HandleFunc("GET /api/server", s.withAuth(s.handleServerInfo))
	s.mux.HandleFunc("GET /api/clients", s.withAuth(s.handleClientsList))
	s.mux.HandleFunc("GET /api/status", s.withAuth(s.handleStatus))

	// 嵌入静态前端资源
	if s.webFS != nil {
		fileServer := http.FileServer(http.FS(s.webFS))
		s.mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
			// 如果是 API 未匹配的路径，返回 404 JSON 而非 HTML
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
		// CSRF 保护：非 GET/HEAD/OPTIONS 必须带 X-Requested-With: wg-panel
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

		// 若用户处于强制改密状态，只允许访问改密与登出端点
		if sess.MustChangePassword && r.URL.Path != "/api/password" && r.URL.Path != "/api/logout" && r.URL.Path != "/api/session" {
			s.jsonError(w, http.StatusForbidden, "password_change_required", "首次登录必须修改初始密码")
			return
		}

		next(w, r)
	}
}

// ----------------------------------------------------------- Handlers

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// CSRF 检查
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

	// 写入 HttpOnly, SameSite=Strict Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     auth.DefaultSessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   !s.cfg.AllowInsecure, // 在允许非安全监听时允许明文，否则必须 Secure
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
