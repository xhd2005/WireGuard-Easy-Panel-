package apply

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/xaxanb/wg/panel/internal/wgconf"
)

// BackupInfo 描述一份历史备份的信息。
type BackupInfo struct {
	Filename   string    `json:"filename"`
	CreatedAt  time.Time `json:"createdAt"`
	Size       int64     `json:"size"`
	PeersCount int       `json:"peersCount"`
}

// Applier 抽象服务端写与热加载操作，便于单测 mock。
type Applier interface {
	WithLock(fn func() error) error
	Backup() (string, error)
	ListBackups() ([]BackupInfo, error)
	GetBackup(filename string) ([]byte, error)
	RestoreBackup(filename string) error
	WriteAtomic(data []byte) error
	SyncConf() error
	RestartService(name string) error
	SaveClientConf(name, content string) error
	DeleteClientConf(name string) (string, error)
	ReadClientConf(name string) (string, error)
	ListClientConfs() (map[string]string, error)
}

type RealApplier struct {
	ConfPath    string
	Iface       string
	LockPath    string
	BackupDir   string
	ClientsDir  string
	HomePattern string
}

func NewRealApplier(confPath, iface, backupDir, stateDir string) *RealApplier {
	return &RealApplier{
		ConfPath:    confPath,
		Iface:       iface,
		LockPath:    confPath + ".lock",
		BackupDir:   backupDir,
		ClientsDir:  filepath.Join(stateDir, "clients"),
		HomePattern: "/home/*/*.conf",
	}
}

// WithLock 持有文件锁并在持锁状态下执行操作。
func (a *RealApplier) WithLock(fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(a.LockPath), 0755); err != nil {
		return fmt.Errorf("apply: 创建锁文件目录失败: %w", err)
	}
	f, err := os.OpenFile(a.LockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("apply: 打开锁文件失败: %w", err)
	}
	defer f.Close()

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("apply: 获取 flock 失败: %w", err)
	}
	defer func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}()

	return fn()
}

// Backup 在每次写入前备份当前配置文件，最多保留 20 份。
func (a *RealApplier) Backup() (string, error) {
	data, err := os.ReadFile(a.ConfPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil // 文件尚不存在则无需备份
	}
	if err != nil {
		return "", fmt.Errorf("apply: 读取待备份文件失败: %w", err)
	}

	if err := os.MkdirAll(a.BackupDir, 0700); err != nil {
		return "", fmt.Errorf("apply: 创建备份目录失败: %w", err)
	}

	ts := time.Now().UTC().Format("2006-01-02T15-04-05Z")
	dst := filepath.Join(a.BackupDir, fmt.Sprintf("wg0.conf.%s.bak", ts))
	if err := os.WriteFile(dst, data, 0600); err != nil {
		return "", fmt.Errorf("apply: 写入备份文件失败: %w", err)
	}

	a.cleanOldBackups(20)
	return dst, nil
}

func (a *RealApplier) cleanOldBackups(keep int) {
	entries, err := os.ReadDir(a.BackupDir)
	if err != nil || len(entries) <= keep {
		return
	}
	var baks []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "wg0.conf.") && strings.HasSuffix(e.Name(), ".bak") {
			baks = append(baks, filepath.Join(a.BackupDir, e.Name()))
		}
	}
	if len(baks) <= keep {
		return
	}
	sort.Strings(baks)
	for i := 0; i < len(baks)-keep; i++ {
		_ = os.Remove(baks[i])
	}
}

// ListBackups 列出当前现存的备份快照（按时间倒序排列）。
func (a *RealApplier) ListBackups() ([]BackupInfo, error) {
	entries, err := os.ReadDir(a.BackupDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var list []BackupInfo
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "wg0.conf.") && strings.HasSuffix(name, ".bak") {
			info, err := e.Info()
			if err != nil {
				continue
			}
			bInfo := BackupInfo{
				Filename:  name,
				CreatedAt: info.ModTime(),
				Size:      info.Size(),
			}
			// 提取 peer 数量
			if b, err := os.ReadFile(filepath.Join(a.BackupDir, name)); err == nil {
				if srv, err := wgconf.Parse(b); err == nil {
					bInfo.PeersCount = len(srv.Peers)
				}
			}
			list = append(list, bInfo)
		}
	}

	// 按时间倒序排序
	sort.Slice(list, func(i, j int) bool {
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})
	return list, nil
}

// GetBackup 读取特定备份文件的内容。
func (a *RealApplier) GetBackup(filename string) ([]byte, error) {
	clean := filepath.Base(filename)
	if !strings.HasPrefix(clean, "wg0.conf.") || !strings.HasSuffix(clean, ".bak") {
		return nil, errors.New("apply: 非法的备份文件名")
	}
	src := filepath.Join(a.BackupDir, clean)
	return os.ReadFile(src)
}

// RestoreBackup 将指定的历史备份文件校验并原子恢复到 wg0.conf，并触发热重载。
func (a *RealApplier) RestoreBackup(filename string) error {
	clean := filepath.Base(filename)
	if !strings.HasPrefix(clean, "wg0.conf.") || !strings.HasSuffix(clean, ".bak") {
		return errors.New("apply: 非法的备份文件名")
	}
	src := filepath.Join(a.BackupDir, clean)
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("apply: 读取备份失败: %w", err)
	}

	// 完整性校验：必须通过 wgconf 解析，绝不把坏配置恢复进系统
	if _, err := wgconf.Parse(data); err != nil {
		return fmt.Errorf("apply: 目标备份配置已损坏或不完整: %w", err)
	}

	// 恢复前先备份一份当前正在运行的配置
	_, _ = a.Backup()

	if err := a.WriteAtomic(data); err != nil {
		return err
	}
	return a.SyncConf()
}

// WriteAtomic 采用 temp + rename 原子写入，保证即使进程被杀也不会留下半截配置。
func (a *RealApplier) WriteAtomic(data []byte) error {
	dir := filepath.Dir(a.ConfPath)
	tmpFile, err := os.CreateTemp(dir, "wg0.conf.tmp.*")
	if err != nil {
		return fmt.Errorf("apply: 创建临时文件失败: %w", err)
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, a.ConfPath); err != nil {
		return fmt.Errorf("apply: 原子替换失败: %w", err)
	}
	return nil
}

// SyncConf 提取配置并调用 wg syncconf 热重载内核规则。
func (a *RealApplier) SyncConf() error {
	// 使用 wg-quick strip 剥离 Address/PostUp 等仅 wg-quick 理解的字段
	stripped, err := exec.Command("wg-quick", "strip", a.ConfPath).Output()
	if err != nil {
		return fmt.Errorf("apply: wg-quick strip 失败: %w", err)
	}

	// 写入临时配置交给 wg syncconf
	tmp, err := os.CreateTemp(filepath.Dir(a.ConfPath), "sync.*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_ = tmp.Chmod(0600)
	_, _ = tmp.Write(stripped)
	_ = tmp.Close()

	out, err := exec.Command("wg", "syncconf", a.Iface, tmp.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("apply: wg syncconf 失败: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func isContainerOrNoSystemd() bool {
	if os.Getenv("WG_PANEL_RUNTIME") == "docker" {
		return true
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return true
	}
	return false
}

func (a *RealApplier) RestartService(name string) error {
	// 如果处于容器或无 systemd 环境，优雅降级为直接内核/命令行操作，避免因缺 systemctl 崩溃
	if isContainerOrNoSystemd() {
		if strings.HasPrefix(name, "wg-quick@") {
			return a.SyncConf()
		}
		return nil
	}
	out, err := exec.Command("systemctl", "restart", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("apply: 重启服务 %s 失败: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SaveClientConf 将客户端完整配置保存在受保护的 stateDir/clients 目录下（0600 root:root）。
func (a *RealApplier) SaveClientConf(name, content string) error {
	if err := os.MkdirAll(a.ClientsDir, 0700); err != nil {
		return err
	}
	dst := filepath.Join(a.ClientsDir, name+".conf")
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// DeleteClientConf 删除客户端的配置文件。
func (a *RealApplier) DeleteClientConf(name string) (string, error) {
	dst := filepath.Join(a.ClientsDir, name+".conf")
	_ = os.Remove(dst)

	// 检查可能遗留在用户家目录下的孤儿文件（spec 9 / 12.2）
	orphanNotice := ""
	matches, _ := filepath.Glob(filepath.Join("/home", "*", name+".conf"))
	if len(matches) > 0 {
		orphanNotice = fmt.Sprintf("提示：由于 systemd 沙箱隔离，面板无法删除家目录文件，请在宿主机执行: sudo rm -f %s", strings.Join(matches, " "))
	}
	return orphanNotice, nil
}

func (a *RealApplier) ReadClientConf(name string) (string, error) {
	dst := filepath.Join(a.ClientsDir, name+".conf")
	b, err := os.ReadFile(dst)
	if err == nil {
		return string(b), nil
	}
	// 回退：若此前由 wg.sh 导出在用户家目录，尝试读取
	matches, _ := filepath.Glob(filepath.Join("/home", "*", name+".conf"))
	if len(matches) > 0 {
		if b2, err2 := os.ReadFile(matches[0]); err2 == nil {
			return string(b2), nil
		}
	}
	return "", fmt.Errorf("未找到客户端 %s 的配置文件", name)
}

func (a *RealApplier) ListClientConfs() (map[string]string, error) {
	res := make(map[string]string)
	entries, err := os.ReadDir(a.ClientsDir)
	if err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".conf") {
				name := strings.TrimSuffix(e.Name(), ".conf")
				if b, err := os.ReadFile(filepath.Join(a.ClientsDir, e.Name())); err == nil {
					res[name] = string(b)
				}
			}
		}
	}
	// 家目录也扫描补充（仅在存在真实 WireGuard 客户端配置标志时纳入）
	if a.HomePattern != "" {
		matches, _ := filepath.Glob(a.HomePattern)
		for _, m := range matches {
			name := strings.TrimSuffix(filepath.Base(m), ".conf")
			if _, exists := res[name]; !exists {
				if b, err := os.ReadFile(m); err == nil {
					content := string(b)
					if strings.Contains(content, "[Interface]") && strings.Contains(strings.ToLower(content), "privatekey") {
						res[name] = content
					}
				}
			}
		}
	}
	return res, nil
}
