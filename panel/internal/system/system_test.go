package system

import (
	"testing"
)

func TestGetStats(t *testing.T) {
	st, err := GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if st.CPU.Cores <= 0 {
		t.Errorf("expected CPU cores > 0, got %d", st.CPU.Cores)
	}
	if st.Memory.TotalBytes <= 0 {
		t.Errorf("expected Memory.TotalBytes > 0, got %d", st.Memory.TotalBytes)
	}
	if st.Disk.TotalBytes <= 0 {
		t.Errorf("expected Disk.TotalBytes > 0, got %d", st.Disk.TotalBytes)
	}
}
