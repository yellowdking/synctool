//go:build !linux

package relay

func detectMemoryLimits() (hostTotal uint64, cgroupLimit uint64) {
	return 0, 0
}

func detectEffectiveMemoryBytes() uint64 {
	return 0
}

func detectFreeDiskBytes(path string) (uint64, bool) {
	return 0, false
}
