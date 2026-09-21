package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	defaultMemory      = 64 * 1024 // 64 MiB
	defaultIterations  = 3
	defaultParallelism = 2
	defaultKeyLen      = 32
	defaultSaltLen     = 16

	DefaultSessionCookie = "wgpanel_session"
	DefaultSessionTTL    = 12 * time.Hour
)

type ArgonParams struct {
	Memory      uint32 `json:"memory"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	KeyLen      uint32 `json:"keyLen"`
}

type Credentials struct {
	Username           string      `json:"username"`
	Salt               string      `json:"salt"` // base64
	Hash               string      `json:"hash"` // base64
	MustChangePassword bool        `json:"mustChangePassword"`
	Params             ArgonParams `json:"params"`
}

type Session struct {
	Token              string
	Username           string
	MustChangePassword bool
	ExpiresAt          time.Time
	CreatedAt          time.Time
}

type ipRateLimit struct {
	failedAttempts int
	lastFailed     time.Time
	blockedUntil   time.Time
}

type Manager struct {
	credPath   string
	sessionTTL time.Duration

	mu       sync.RWMutex
	creds    Credentials
	sessions map[string]*Session
	limits   map[string]*ipRateLimit
}

// NewManager 初始化凭据与鉴权管理器。若凭据文件不存在，自动生成 20 位初始随机密码。
// 返回管理器实例，以及（仅首次创建时）生成的明文初始密码。
func NewManager(credPath string, sessionTTL time.Duration) (*Manager, string, error) {
	if sessionTTL <= 0 {
		sessionTTL = DefaultSessionTTL
	}
	m := &Manager{
		credPath:   credPath,
		sessionTTL: sessionTTL,
		sessions:   make(map[string]*Session),
		limits:     make(map[string]*ipRateLimit),
	}

	var initPassword string
	if _, err := os.Stat(credPath); errors.Is(err, os.ErrNotExist) {
		initPassword = GenerateRandomPassword(20)
		if err := m.initCredentials("admin", initPassword); err != nil {
			return nil, "", fmt.Errorf("auth: 初始化凭据失败: %w", err)
		}
	} else if err != nil {
		return nil, "", fmt.Errorf("auth: 检查凭据文件失败: %w", err)
	} else {
		if err := m.loadCredentials(); err != nil {
			return nil, "", fmt.Errorf("auth: 加载凭据文件失败: %w", err)
		}
	}

	return m, initPassword, nil
}

func (m *Manager) initCredentials(username, password string) error {
	salt := make([]byte, defaultSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	params := ArgonParams{
		Memory:      defaultMemory,
		Iterations:  defaultIterations,
		Parallelism: defaultParallelism,
		KeyLen:      defaultKeyLen,
	}
	hash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLen)

	m.creds = Credentials{
		Username:           username,
		Salt:               base64.StdEncoding.EncodeToString(salt),
		Hash:               base64.StdEncoding.EncodeToString(hash),
		MustChangePassword: true,
		Params:             params,
	}
	return m.saveCredentials()
}

func (m *Manager) loadCredentials() error {
	b, err := os.ReadFile(m.credPath)
	if err != nil {
		return err
	}
	var creds Credentials
	if err := json.Unmarshal(b, &creds); err != nil {
		return err
	}
	if creds.Username == "" || creds.Salt == "" || creds.Hash == "" {
		return errors.New("auth: 凭据文件结构不完整")
	}
	m.creds = creds
	return nil
}

func (m *Manager) saveCredentials() error {
	if err := os.MkdirAll(filepath.Dir(m.credPath), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m.creds, "", "  ")
	if err != nil {
		return err
	}
	// 原子落盘：temp + rename，保住 0600 权限
	tmp := m.credPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, m.credPath)
}

// Authenticate 校验用户名口令，并防爆破。校验成功签发新 session token。
func (m *Manager) Authenticate(username, password, remoteAddr string) (string, *Session, error) {
	ip := extractIP(remoteAddr)

	m.mu.Lock()
	defer m.mu.Unlock()

	// 检查 IP 防爆破限速
	if lim, exists := m.limits[ip]; exists {
		if time.Now().Before(lim.blockedUntil) {
			remaining := time.Until(lim.blockedUntil).Round(time.Second)
			return "", nil, fmt.Errorf("auth: 尝试次数过多，请在 %v 后重试", remaining)
		}
	}

	// 校验口令
	if err := m.verifyPasswordLocked(username, password); err != nil {
		m.recordFailureLocked(ip)
		return "", nil, errors.New("auth: 用户名或密码错误")
	}

	// 登录成功，重置该 IP 失败计数
	delete(m.limits, ip)

	// 签发 session token（32 字节随机 hex/base64URL）
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	now := time.Now()
	sess := &Session{
		Token:              token,
		Username:           m.creds.Username,
		MustChangePassword: m.creds.MustChangePassword,
		ExpiresAt:          now.Add(m.sessionTTL),
		CreatedAt:          now,
	}
	m.sessions[token] = sess
	return token, sess, nil
}

func (m *Manager) verifyPasswordLocked(username, password string) error {
	if subtle.ConstantTimeCompare([]byte(username), []byte(m.creds.Username)) != 1 {
		return errors.New("mismatch")
	}
	salt, err := base64.StdEncoding.DecodeString(m.creds.Salt)
	if err != nil {
		return err
	}
	targetHash, err := base64.StdEncoding.DecodeString(m.creds.Hash)
	if err != nil {
		return err
	}
	params := m.creds.Params
	if params.Iterations == 0 {
		params = ArgonParams{Memory: defaultMemory, Iterations: defaultIterations, Parallelism: defaultParallelism, KeyLen: defaultKeyLen}
	}
	computed := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLen)
	if subtle.ConstantTimeCompare(computed, targetHash) != 1 {
		return errors.New("mismatch")
	}
	return nil
}

func (m *Manager) recordFailureLocked(ip string) {
	lim, ok := m.limits[ip]
	now := time.Now()
	if !ok || now.Sub(lim.lastFailed) > 15*time.Minute {
		lim = &ipRateLimit{failedAttempts: 0}
		m.limits[ip] = lim
	}
	lim.failedAttempts++
	lim.lastFailed = now

	// 连续 5 次失败后指数退避（5s -> 15s -> 60s -> 5min）
	switch {
	case lim.failedAttempts >= 8:
		lim.blockedUntil = now.Add(5 * time.Minute)
	case lim.failedAttempts >= 7:
		lim.blockedUntil = now.Add(60 * time.Second)
	case lim.failedAttempts >= 6:
		lim.blockedUntil = now.Add(15 * time.Second)
	case lim.failedAttempts >= 5:
		lim.blockedUntil = now.Add(5 * time.Second)
	}
}

// ValidateSession 检查 Session 是否有效，若有效则返回其信息。
func (m *Manager) ValidateSession(token string) (*Session, bool) {
	if token == "" {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	sess, ok := m.sessions[token]
	if !ok {
		return nil, false
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil, false
	}
	return sess, true
}

// DestroySession 销毁指定的 session（登出）。
func (m *Manager) DestroySession(token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, token)
}

// ChangePassword 修改用户密码，并解除 MustChangePassword。
func (m *Manager) ChangePassword(username, oldPassword, newPassword string) error {
	if len(newPassword) < 8 {
		return errors.New("auth: 新密码长度至少需 8 个字符")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.verifyPasswordLocked(username, oldPassword); err != nil {
		return errors.New("auth: 原密码错误")
	}

	salt := make([]byte, defaultSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	params := m.creds.Params
	if params.Iterations == 0 {
		params = ArgonParams{Memory: defaultMemory, Iterations: defaultIterations, Parallelism: defaultParallelism, KeyLen: defaultKeyLen}
	}
	hash := argon2.IDKey([]byte(newPassword), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLen)

	m.creds.Salt = base64.StdEncoding.EncodeToString(salt)
	m.creds.Hash = base64.StdEncoding.EncodeToString(hash)
	m.creds.MustChangePassword = false

	if err := m.saveCredentials(); err != nil {
		return err
	}

	// 更新所有活跃 session 的 MustChangePassword 状态
	for _, sess := range m.sessions {
		if sess.Username == username {
			sess.MustChangePassword = false
		}
	}
	return nil
}

// MustChangePassword 报告是否必须强制改密。
func (m *Manager) MustChangePassword() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.creds.MustChangePassword
}

// GenerateRandomPassword 生成安全随机密码（大小写字母 + 数字）。
func GenerateRandomPassword(length int) string {
	const charset = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, length)
	max := big.NewInt(int64(len(charset)))
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			b[i] = charset[i%len(charset)]
		} else {
			b[i] = charset[n.Int64()]
		}
	}
	return string(b)
}

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil && host != "" {
		return host
	}
	if addr == "" {
		return "unknown"
	}
	return addr
}
