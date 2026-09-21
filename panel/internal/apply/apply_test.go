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
