//go:build linux

package relay

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func readCgroupV2Max(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return ParseCgroupV2MaxBytes(string(data))
}

func readCgroupV1Limit(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(data))
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v == 0 || v >= (1<<60) {
		return 0
	}
	return v
}

func detectMemoryLimits() (hostTotal uint64, cgroupLimit uint64) {
	// Inspect /proc/self/cgroup first so systemd non-containerized MemoryMax slices are honored.
	var v2Rel, v1MemRel string
	if selfCg, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		v2Rel, v1MemRel = ParseProcSelfCgroupPaths(string(selfCg))
	}

	// 1. Try cgroup v2: walk from leaf slice up to /sys/fs/cgroup to find tightest memory.max
	// even when the leaf slice itself reports "max".
	cgroupLimit = WalkCgroupV2TightestMax("/sys/fs/cgroup", v2Rel, os.ReadFile)

	// 2. Fallback to cgroup v1 (process slice first, then root memory.limit_in_bytes)
	if cgroupLimit == 0 && v1MemRel != "" {
		cgroupLimit = readCgroupV1Limit(filepath.Join("/sys/fs/cgroup/memory", v1MemRel, "memory.limit_in_bytes"))
	}
	if cgroupLimit == 0 {
		cgroupLimit = readCgroupV1Limit("/sys/fs/cgroup/memory/memory.limit_in_bytes")
	}

	// 3. Read host physical RAM from /proc/meminfo
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

	return hostTotal, cgroupLimit
}

func detectEffectiveMemoryBytes() uint64 {
	hostTotal, cgroupLimit := detectMemoryLimits()
	return EffectiveMemoryBytes(hostTotal, cgroupLimit)
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
