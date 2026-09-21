package config

// Config 包含面板的运行时配置。
type Config struct {
	ListenAddr      string // 默认 "127.0.0.1:8734"
	AllowInsecure   bool   // 当监听非回环地址且无 TLS 时，必须显式开启
	TLSCert         string // 可选 TLS 证书路径
	TLSKey          string // 可选 TLS 私钥路径
	WGConfPath      string // WireGuard 服务端配置路径，默认 "/etc/wireguard/wg0.conf"
	WGInterface     string // WireGuard 接口名，默认 "wg0"
	CredentialsPath string // 登录凭据路径，默认 "/etc/wg-panel/credentials.json"
	StatePath       string // 运行时状态（如 endpointDirty），默认 "/var/lib/wg-panel/state.json"
	TrafficPath     string // 历史累计流量持久化存储路径，默认 "/var/lib/wg-panel/traffic.json"
	BackupDir       string // 每次改动配置前的备份目录，默认 "/var/backups/wg-panel"
	Version         string // 编译期注入的版本号
	Commit          string // 编译期注入的 Git Commit
	BuildTime       string // 编译期注入的构建时间
}

// Default 返回标准默认配置。
func Default() *Config {
	return &Config{
		ListenAddr:      "127.0.0.1:8734",
		AllowInsecure:   false,
		WGConfPath:      "/etc/wireguard/wg0.conf",
		WGInterface:     "wg0",
		CredentialsPath: "/etc/wg-panel/credentials.json",
		StatePath:       "/var/lib/wg-panel/state.json",
		TrafficPath:     "/var/lib/wg-panel/traffic.json",
		BackupDir:       "/var/backups/wg-panel",
		Version:         "0.1.0",
		Commit:          "dev",
		BuildTime:       "dev",
	}
}
