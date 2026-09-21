package apply

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomicAndBackup(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "wg0.conf")
	backupDir := filepath.Join(dir, "backups")
	stateDir := filepath.Join(dir, "state")

	a := NewRealApplier(confPath, "wg0", backupDir, stateDir)

	// 首次写入
	data1 := []byte("[Interface]\nListenPort = 53\n")
	if err := a.WriteAtomic(data1); err != nil {
		t.Fatalf("WriteAtomic 1 失败: %v", err)
	}

	read1, err := os.ReadFile(confPath)
	if err != nil || string(read1) != string(data1) {
		t.Fatalf("读取写入数据不符: %s", string(read1))
	}

	// 备份
	bakPath, err := a.Backup()
	if err != nil {
		t.Fatalf("Backup 失败: %v", err)
	}
	if bakPath == "" {
		t.Fatal("bakPath 应该非空")
	}

	bakData, err := os.ReadFile(bakPath)
	if err != nil || string(bakData) != string(data1) {
		t.Fatalf("备份数据不符: %s", string(bakData))
	}

	// 锁测试
	executed := false
	err = a.WithLock(func() error {
		executed = true
		return nil
	})
	if err != nil || !executed {
		t.Fatalf("WithLock 失败: %v", err)
	}
}

func TestClientConfStorage(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "wg0.conf")
	backupDir := filepath.Join(dir, "backups")
	stateDir := filepath.Join(dir, "state")

	a := NewRealApplier(confPath, "wg0", backupDir, stateDir)
	a.HomePattern = ""

	content := "[Interface]\nPrivateKey = test\n"
	if err := a.SaveClientConf("windows-pc", content); err != nil {
		t.Fatalf("SaveClientConf 失败: %v", err)
	}

	readBack, err := a.ReadClientConf("windows-pc")
	if err != nil || readBack != content {
		t.Fatalf("ReadClientConf 失败: %v", err)
	}

	list, err := a.ListClientConfs()
	if err != nil || len(list) != 1 || list["windows-pc"] != content {
		t.Fatalf("ListClientConfs 失败: %v", list)
	}

	_, err = a.DeleteClientConf("windows-pc")
	if err != nil {
		t.Fatalf("DeleteClientConf 失败: %v", err)
	}

	_, err = a.ReadClientConf("windows-pc")
	if err == nil {
		t.Fatal("删除后读取应该报错")
	}
}

func TestBackupListAndRestore(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "wg0.conf")
	backupDir := filepath.Join(dir, "backups")
	stateDir := filepath.Join(dir, "state")

	a := NewRealApplier(confPath, "wg0", backupDir, stateDir)

	validConf := "[Interface]\nPrivateKey = wFxSCo8a5+PoZcKx8Q+LoS31VBMGOmztUUTcqi5hl0c=\nListenPort = 53\n"
	_ = a.WriteAtomic([]byte(validConf))
	bakPath, err := a.Backup()
	if err != nil {
		t.Fatal(err)
	}

	baks, err := a.ListBackups()
	if err != nil || len(baks) != 1 {
		t.Fatalf("expected 1 backup, got %d (err: %v)", len(baks), err)
	}

	content, err := a.GetBackup(filepath.Base(bakPath))
	if err != nil || string(content) != validConf {
		t.Fatalf("unexpected backup content: %s", string(content))
	}

	// 路径穿越攻击防御测试
	if _, err := a.GetBackup("../../../etc/passwd"); err == nil {
		t.Error("path traversal should be blocked")
	}

	// 恢复损坏的备份应当报错
	brokenBak := filepath.Join(backupDir, "wg0.conf.broken.bak")
	_ = os.WriteFile(brokenBak, []byte("broken content"), 0600)
	if err := a.RestoreBackup("wg0.conf.broken.bak"); err == nil {
		t.Error("restoring broken config must fail")
	}
}
