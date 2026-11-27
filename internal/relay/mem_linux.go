//go:build linux

package relay

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

func detectEffectiveMemoryBytes() uint64 {
	var cgroupLimit uint64

	// 1. Try cgroup v2 (/sys/fs/cgroup/memory.max)
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "" && s != "max" {
			if v, err := strconv.ParseUint(s, 10, 64); err == nil && v > 0 {
				cgroupLimit = v
			}
		}
	}

	// 2. Fallback to cgroup v1 (/sys/fs/cgroup/memory/memory.limit_in_bytes)
	if cgroupLimit == 0 {
		if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
			s := strings.TrimSpace(string(data))
			if v, err := strconv.ParseUint(s, 10, 64); err == nil && v > 0 && v < (1<<60) {
				cgroupLimit = v
			}
		}
	}

	// 3. Read host physical RAM from /proc/meminfo
	var hostTotal uint64
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if kb, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
						hostTotal = kb * 1024
					}
				}
				break
			}
		}
	}

	if cgroupLimit > 0 && hostTotal > 0 {
		if cgroupLimit < hostTotal {
			return cgroupLimit
		}
		return hostTotal
	}
	if cgroupLimit > 0 {
		return cgroupLimit
	}
	return hostTotal
}

func detectFreeDiskBytes(path string) (uint64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, false
	}
	if st.Bsize <= 0 {
		return 0, false
	}
	return st.Bavail * uint64(st.Bsize), true
}
