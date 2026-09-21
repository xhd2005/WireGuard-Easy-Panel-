package traffic

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xaxanb/wg/panel/internal/status"
)

func TestTrackerRecordAndEnrich(t *testing.T) {
	tmpDir := t.TempDir()
	trafficPath := filepath.Join(tmpDir, "traffic.json")

	tracker := NewTracker(trafficPath)

	peers1 := []status.PeerStatus{
		{
			PublicKey:       "pub1",
			TransferRxBytes: 1000,
			TransferTxBytes: 2000,
		},
	}

	tracker.Record(peers1)
	enriched := tracker.Enrich(peers1)
	if len(enriched) != 1 {
		t.Fatalf("expected 1 enriched peer, got %d", len(enriched))
	}
	if enriched[0].TotalRxBytes != 1000 || enriched[0].TotalTxBytes != 2000 {
		t.Errorf("unexpected initial totals: rx=%d, tx=%d", enriched[0].TotalRxBytes, enriched[0].TotalTxBytes)
	}

	// 模拟第二次采样：下行增加了 5000 字节，上行增加 10000 字节
	time.Sleep(300 * time.Millisecond)
	peers2 := []status.PeerStatus{
		{
			PublicKey:       "pub1",
			TransferRxBytes: 6000,
			TransferTxBytes: 12000,
		},
	}
	tracker.Record(peers2)
	enriched2 := tracker.Enrich(peers2)
	if enriched2[0].TotalRxBytes != 6000 || enriched2[0].TotalTxBytes != 12000 {
		t.Errorf("unexpected updated totals: rx=%d, tx=%d", enriched2[0].TotalRxBytes, enriched2[0].TotalTxBytes)
	}
	if enriched2[0].RxSpeedBytes <= 0 || enriched2[0].TxSpeedBytes <= 0 {
		t.Errorf("expected positive speeds, got rx=%d, tx=%d", enriched2[0].RxSpeedBytes, enriched2[0].TxSpeedBytes)
	}

	// 模拟内核重启计数器清零（比如网卡重启后从 0 重新计数，变为 500 字节）
	time.Sleep(300 * time.Millisecond)
	peers3 := []status.PeerStatus{
		{
			PublicKey:       "pub1",
			TransferRxBytes: 500,
			TransferTxBytes: 500,
		},
	}
	tracker.Record(peers3)
	enriched3 := tracker.Enrich(peers3)
	// 累计流量应该是 6000 + 500 = 6500，不会因内核计数器归零而丢失
	if enriched3[0].TotalRxBytes != 6500 || enriched3[0].TotalTxBytes != 12500 {
		t.Errorf("unexpected totals after counter reset: rx=%d, tx=%d", enriched3[0].TotalRxBytes, enriched3[0].TotalTxBytes)
	}

	// 测试落盘和重新加载
	if err := tracker.Save(); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	tracker2 := NewTracker(trafficPath)
	enrichedLoaded := tracker2.Enrich(peers3)
	if enrichedLoaded[0].TotalRxBytes != 6500 {
		t.Errorf("expected loaded totalRx 6500, got %d", enrichedLoaded[0].TotalRxBytes)
	}

	_ = os.Remove(trafficPath)
}

func TestFormatBytesAndSpeed(t *testing.T) {
	if s := FormatBytes(500); s != "500 B" {
		t.Errorf("expected '500 B', got %s", s)
	}
	if s := FormatBytes(1024 * 1024 * 5); s != "5.00 MB" {
		t.Errorf("expected '5.00 MB', got %s", s)
	}
	if s := FormatSpeed(1024 * 250); s != "250.00 KB/s" {
		t.Errorf("expected '250.00 KB/s', got %s", s)
	}
	if s := FormatSpeed(0); s != "0 B/s" {
		t.Errorf("expected '0 B/s', got %s", s)
	}
}
