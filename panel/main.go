package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xaxanb/wg/panel/internal/api"
	"github.com/xaxanb/wg/panel/internal/auth"
	"github.com/xaxanb/wg/panel/internal/config"
)

var (
	version   = "0.1.0"
	commit    = "dev"
	buildTime = "dev"
)

func main() {
	cfg := config.Default()
	cfg.Version = version
	cfg.Commit = commit
	cfg.BuildTime = buildTime

	showVer := flag.Bool("version", false, "显示版本信息并退出")
	flag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "监听地址，默认 127.0.0.1:8734")
	flag.BoolVar(&cfg.AllowInsecure, "allow-insecure", cfg.AllowInsecure, "允许在公网地址上使用明文 HTTP（强烈不推荐）")
	flag.StringVar(&cfg.TLSCert, "tls-cert", "", "TLS 证书文件路径")
	flag.StringVar(&cfg.TLSKey, "tls-key", "", "TLS 私钥文件路径")
	flag.StringVar(&cfg.WGConfPath, "conf", cfg.WGConfPath, "WireGuard 服务端配置文件路径")
	flag.StringVar(&cfg.WGInterface, "iface", cfg.WGInterface, "WireGuard 网卡名")
	flag.StringVar(&cfg.CredentialsPath, "creds", cfg.CredentialsPath, "管理员凭据存储文件路径")
	flag.StringVar(&cfg.StatePath, "state", cfg.StatePath, "运行时状态存储文件路径")
	flag.StringVar(&cfg.BackupDir, "backup-dir", cfg.BackupDir, "配置文件修改前备份目录")
	flag.Parse()

	if *showVer {
		fmt.Printf("wg-panel v%s (commit: %s, built: %s)\n", version, commit, buildTime)
		os.Exit(0)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	// 安全门禁（spec 10 / 12.1）：如果监听非回环地址且无 TLS，必须显式加 --allow-insecure
	if err := checkListenSecurity(cfg.ListenAddr, cfg.TLSCert, cfg.TLSKey, cfg.AllowInsecure); err != nil {
		fmt.Fprintf(os.Stderr, "❌ 安全启动被拒绝: %v\n", err)
		fmt.Fprintln(os.Stderr, "💡 建议保持默认回环监听，并通过 SSH 端口转发访问：")
		fmt.Fprintf(os.Stderr, "   ssh -L 8734:127.0.0.1:8734 <服务器地址>\n")
		os.Exit(1)
	}

	// 初始化鉴权管理器
	authMgr, initPass, err := auth.NewManager(cfg.CredentialsPath, auth.DefaultSessionTTL)
	if err != nil {
		slog.Error("初始化凭据失败", "error", err)
		os.Exit(1)
	}

	if initPass != "" {
		fmt.Println("==================================================================")
		fmt.Println("🎉 wg-panel 首次启动成功！初始管理员凭据如下：")
		fmt.Println("   用户名: admin")
		fmt.Printf("   密  码: %s\n", initPass)
		fmt.Println("⚠️  该密码仅打印一次，首次登录后将被强制修改，请妥善保存！")
		fmt.Println("==================================================================")
	}

	// 探测端口可用性
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		slog.Error("端口监听失败", "listen", cfg.ListenAddr, "error", err)
		if strings.Contains(err.Error(), "address already in use") {
			fmt.Fprintf(os.Stderr, "❌ 端口 %s 已被占用，请使用 --listen 指定其他空闲端口。\n", cfg.ListenAddr)
		}
		os.Exit(1)
	}

	srv := api.NewServer(cfg, authMgr, nil, nil, WebAssets())
	httpSrv := &http.Server{
		Handler:      srv.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("wg-panel 正在启动", "listen", cfg.ListenAddr, "version", version)
		var srvErr error
		if cfg.TLSCert != "" && cfg.TLSKey != "" {
			srvErr = httpSrv.ServeTLS(ln, cfg.TLSCert, cfg.TLSKey)
		} else {
			srvErr = httpSrv.Serve(ln)
		}
		if srvErr != nil && !errors.Is(srvErr, http.ErrServerClosed) {
			slog.Error("HTTP 服务异常退出", "error", srvErr)
			os.Exit(1)
		}
	}()

	<-stopChan
	slog.Info("正在优雅停止 wg-panel...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		slog.Error("优雅退出超时", "error", err)
	}
	slog.Info("服务已停止")
}

func checkListenSecurity(listenAddr, cert, key string, allowInsecure bool) error {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		host = listenAddr
	}
	isLoopback := host == "127.0.0.1" || host == "localhost" || host == "::1"
	hasTLS := cert != "" && key != ""

	if !isLoopback && !hasTLS && !allowInsecure {
		return fmt.Errorf("当前配置监听非回环地址 (%s) 且未配置 TLS 证书。为了防止管理员密码在公网裸传被截获，必须配置 TLS 或显式增加 --allow-insecure 参数", listenAddr)
	}
	return nil
}
