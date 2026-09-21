package traffic

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xaxanb/wg/panel/internal/status"
)

// PeerRecord 记录单个 peer 的历史累计流量和瞬时速率统计。
type PeerRecord struct {
	PublicKey      string    `json:"publicKey"`
	AccumulatedRx  int64     `json:"accumulatedRx"`  // 历史累计下行字节
	AccumulatedTx  int64     `json:"accumulatedTx"`  // 历史累计上行字节
	LastKernelRx   int64     `json:"lastKernelRx"`   // 上次观测到的内核原始 Rx
	LastKernelTx   int64     `json:"lastKernelTx"`   // 上次观测到的内核原始 Tx
	LastUpdatedAt  time.Time `json:"lastUpdatedAt"`  // 上次采样时间
	RxSpeedBytes   int64     `json:"rxSpeedBytes"`   // 当前瞬时下行速率 (Bytes/s)
	TxSpeedBytes   int64     `json:"txSpeedBytes"`   // 当前瞬时上行速率 (Bytes/s)
}

// Storage 存储格式。
type Storage struct {
	Version   int                    `json:"version"`
	Peers     map[string]*PeerRecord `json:"peers"`
	UpdatedAt time.Time              `json:"updatedAt"`
}

// Tracker 负责在内存中追踪流量差值，并定期持久化到磁盘。
type Tracker struct {
	mu         sync.RWMutex
	filePath   string
	records    map[string]*PeerRecord
	dirty      bool
	lastSaveAt time.Time
}

// NewTracker 创建流量统计追踪器。若存在存储文件则恢复累计历史。
func NewTracker(filePath string) *Tracker {
	t := &Tracker{
		filePath: filePath,
		records:  make(map[string]*PeerRecord),
	}
	t.load()
	return t
}

// Record 输入最新一批 peer 状态，根据时间差与内核增量计算速率与累加流量。
func (t *Tracker) Record(peers []status.PeerStatus) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for _, p := range peers {
		if p.PublicKey == "" {
			continue
		}

		rec, exists := t.records[p.PublicKey]
		if !exists {
			t.records[p.PublicKey] = &PeerRecord{
				PublicKey:     p.PublicKey,
				AccumulatedRx: p.TransferRxBytes,
				AccumulatedTx: p.TransferTxBytes,
				LastKernelRx:  p.TransferRxBytes,
				LastKernelTx:  p.TransferTxBytes,
				LastUpdatedAt: now,
				RxSpeedBytes:  0,
				TxSpeedBytes:  0,
			}
			t.dirty = true
			continue
		}

		// 计算时间差
		dur := now.Sub(rec.LastUpdatedAt).Seconds()
		if dur < 0.2 {
			continue // 采样间隔过短，跳过速率重算
		}

		// 处理内核计数器重置（例如网卡重启）
		var deltaRx, deltaTx int64
		if p.TransferRxBytes < rec.LastKernelRx {
			deltaRx = p.TransferRxBytes
		} else {
			deltaRx = p.TransferRxBytes - rec.LastKernelRx
		}

		if p.TransferTxBytes < rec.LastKernelTx {
			deltaTx = p.TransferTxBytes
		} else {
			deltaTx = p.TransferTxBytes - rec.LastKernelTx
		}

		rec.AccumulatedRx += deltaRx
		rec.AccumulatedTx += deltaTx
		rec.LastKernelRx = p.TransferRxBytes
		rec.LastKernelTx = p.TransferTxBytes
		rec.LastUpdatedAt = now

		// 计算瞬时速率
		rec.RxSpeedBytes = int64(float64(deltaRx) / dur)
		rec.TxSpeedBytes = int64(float64(deltaTx) / dur)

		if deltaRx > 0 || deltaTx > 0 {
			t.dirty = true
		}
	}

	// 每 10 秒自动刷盘一次
	if t.dirty && now.Sub(t.lastSaveAt) >= 10*time.Second {
		t.saveLocked()
	}
}

// Enrich 将流量统计与速率注入到传入的 PeerStatus 列表中。
func (t *Tracker) Enrich(peers []status.PeerStatus) []status.PeerStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()

	res := make([]status.PeerStatus, len(peers))
	for i, p := range peers {
		res[i] = p
		rec, exists := t.records[p.PublicKey]
		if exists {
			res[i].RxSpeedBytes = rec.RxSpeedBytes
			res[i].TxSpeedBytes = rec.TxSpeedBytes
			res[i].RxSpeed = FormatSpeed(rec.RxSpeedBytes)
			res[i].TxSpeed = FormatSpeed(rec.TxSpeedBytes)
			res[i].TotalRxBytes = rec.AccumulatedRx
			res[i].TotalTxBytes = rec.AccumulatedTx
			res[i].TotalRx = FormatBytes(rec.AccumulatedRx)
			res[i].TotalTx = FormatBytes(rec.AccumulatedTx)
		} else {
			res[i].RxSpeed = "0 B/s"
			res[i].TxSpeed = "0 B/s"
			res[i].TotalRx = p.TransferRx
			res[i].TotalTx = p.TransferTx
			res[i].TotalRxBytes = p.TransferRxBytes
			res[i].TotalTxBytes = p.TransferTxBytes
		}
	}
	return res
}

// Save 将流量统计落盘。
func (t *Tracker) Save() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.saveLocked()
}

func (t *Tracker) saveLocked() error {
	if t.filePath == "" {
		return nil
	}
	_ = os.MkdirAll(filepath.Dir(t.filePath), 0700)

	s := Storage{
		Version:   1,
		Peers:     t.records,
		UpdatedAt: time.Now(),
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	tmp := fmt.Sprintf("%s.tmp.%d", t.filePath, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, t.filePath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	t.dirty = false
	t.lastSaveAt = time.Now()
	return nil
}

func (t *Tracker) load() {
	if t.filePath == "" {
		return
	}
	data, err := os.ReadFile(t.filePath)
	if err != nil {
		return
	}
	var s Storage
	if err := json.Unmarshal(data, &s); err == nil && s.Peers != nil {
		t.records = s.Peers
	}
}

// FormatBytes 将字节数转换为人类可读的字符串（B, KB, MB, GB, TB）。
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// FormatSpeed 将每秒字节数转换为可读速率。
func FormatSpeed(bps int64) string {
	if bps <= 0 {
		return "0 B/s"
	}
	return FormatBytes(bps) + "/s"
}
