package system

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Stats 包含主机系统资源使用量及运行时间。
type Stats struct {
	CPU struct {
		UsagePercent float64 `json:"usagePercent"`
		Cores        int     `json:"cores"`
	} `json:"cpu"`
	Load struct {
		Load1  float64 `json:"load1"`
		Load5  float64 `json:"load5"`
		Load15 float64 `json:"load15"`
	} `json:"load"`
	Memory struct {
		TotalBytes   uint64  `json:"totalBytes"`
		UsedBytes    uint64  `json:"usedBytes"`
		FreeBytes    uint64  `json:"freeBytes"`
		UsagePercent float64 `json:"usagePercent"`
	} `json:"memory"`
	Disk struct {
		TotalBytes   uint64  `json:"totalBytes"`
		UsedBytes    uint64  `json:"usedBytes"`
		FreeBytes    uint64  `json:"freeBytes"`
		UsagePercent float64 `json:"usagePercent"`
	} `json:"disk"`
	Uptime struct {
		SystemSeconds uint64 `json:"systemSeconds"`
		PanelSeconds  uint64 `json:"panelSeconds"`
	} `json:"uptime"`
}

var startTime = time.Now()

// GetStats 采集当前主机的 CPU、负载、内存、磁盘和运行时间。
func GetStats() (*Stats, error) {
	s := &Stats{}
	s.CPU.Cores = runtime.NumCPU()
	s.Uptime.PanelSeconds = uint64(time.Since(startTime).Seconds())

	if runtime.GOOS != "linux" {
		// 跨平台开发时提供模拟数据
		s.CPU.UsagePercent = 12.5
		s.Load.Load1, s.Load.Load5, s.Load.Load15 = 0.5, 0.4, 0.3
		s.Memory.TotalBytes = 16 * 1024 * 1024 * 1024
		s.Memory.UsedBytes = 6 * 1024 * 1024 * 1024
		s.Memory.FreeBytes = 10 * 1024 * 1024 * 1024
		s.Memory.UsagePercent = 37.5
		s.Disk.TotalBytes = 100 * 1024 * 1024 * 1024
		s.Disk.UsedBytes = 40 * 1024 * 1024 * 1024
		s.Disk.FreeBytes = 60 * 1024 * 1024 * 1024
		s.Disk.UsagePercent = 40.0
		s.Uptime.SystemSeconds = 3600
		return s, nil
	}

	// 1. 读取 /proc/loadavg
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			s.Load.Load1, _ = strconv.ParseFloat(fields[0], 64)
			s.Load.Load5, _ = strconv.ParseFloat(fields[1], 64)
			s.Load.Load15, _ = strconv.ParseFloat(fields[2], 64)
		}
	}

	// 2. 读取 /proc/meminfo
	if f, err := os.Open("/proc/meminfo"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		var memTotal, memAvail uint64
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				switch parts[0] {
				case "MemTotal:":
					memTotal, _ = strconv.ParseUint(parts[1], 10, 64)
				case "MemAvailable:":
					memAvail, _ = strconv.ParseUint(parts[1], 10, 64)
				}
			}
		}
		if memTotal > 0 {
			s.Memory.TotalBytes = memTotal * 1024
			s.Memory.FreeBytes = memAvail * 1024
			s.Memory.UsedBytes = s.Memory.TotalBytes - s.Memory.FreeBytes
			s.Memory.UsagePercent = float64(s.Memory.UsedBytes) / float64(s.Memory.TotalBytes) * 100
		}
	}

	// 3. 读取根分区磁盘状态
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err == nil {
		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bfree * uint64(stat.Bsize)
		if total > 0 {
			s.Disk.TotalBytes = total
			s.Disk.FreeBytes = free
			s.Disk.UsedBytes = total - free
			s.Disk.UsagePercent = float64(s.Disk.UsedBytes) / float64(total) * 100
		}
	}

	// 4. 读取 /proc/uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 1 {
			up, _ := strconv.ParseFloat(fields[0], 64)
			s.Uptime.SystemSeconds = uint64(up)
		}
	}

	// 5. 计算 CPU 使用率 (基于系统负载或核心采样)
	if s.CPU.Cores > 0 {
		usage := (s.Load.Load1 / float64(s.CPU.Cores)) * 100
		if usage > 100 {
			usage = 100
		}
		s.CPU.UsagePercent = usage
	}

	return s, nil
}
