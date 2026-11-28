package relay

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

const (
	ProtoVersion              = 1
	MinProtoVersion           = 1
	MaxProtoVersion           = 1
	CryptoPlaintextBlockBytes = 65536
	AEADTagBytes              = 16
	CryptoBlockBytes          = CryptoPlaintextBlockBytes + AEADTagBytes // 65552 B

	MaxControlBodyBytes        = 16384 // 16 KiB
	MaxHeaderBytes             = 8192  // 8 KiB HTTP header ceiling
	MaxAuthHeaderBytes         = 128
	MaxRoomMsgBytes            = 4096 // 4 KiB raw decoded
	MaxHandshakeFrames         = 8
	MaxControlRingSize         = 16
	MaxPartsPerItem            = 64    // part_id 0..63
	MaxChunksPerPart           = 65536 // >4 GiB at 64 KiB blocks; prevents Commit loop DoS
	MaxDepositTokensPerMailbox = 16
	SealedHeaderLen            = 208

	ClockSkewMaxSec      = 60
	NonceCacheMaxEntries = 65536
	NonceCacheTTL        = 125 * time.Second // Covers full ±60s window + boundary

	RendezvousTimeout        = 30 * time.Second
	StallTimeout             = 30 * time.Second
	MaxChunkTransferDuration = 5 * time.Minute
	TransferSemWait          = 5 * time.Second
	ControlDeadline          = 15 * time.Second
	ReadHeaderTimeout        = 5 * time.Second
	HTTPIdleTimeout          = 60 * time.Second
	SSEKeepaliveInterval     = 20 * time.Second
	SSEMaxDuration           = 90 * time.Second
	LongPollDefaultSec       = 20
	LongPollMaxSec           = 25
	RoomTTLMinSec            = 60
	RoomTTLMaxSec            = 600
	RoomTTLDefaultSec        = 300
	RoomTombstoneDuration    = 15 * time.Second
	UncommittedTTLSec        = 1800
	MaxManifestDownloads     = 16

	StrikeBanThreshold = 10
	StrikeBanDuration  = 15 * time.Minute
	StrikeDecayWindow  = 1 * time.Minute

	CertValidityDays   = 730
	CertRotateWarnDays = 30

	MinAutoDiskFreeBytes     = 256 << 20  // 256 MiB
	AutoProfileNanoMaxBytes  = 224 << 20  // < 224 MiB -> nano; >= 224 MiB (e.g. 256 MiB) -> standard
	AutoProfileMediaMinBytes = 1536 << 20 // >= 1536 MiB -> media
)

type ProfileName string

const (
	ProfileAuto     ProfileName = "auto"
	ProfileNano     ProfileName = "nano"
	ProfileStandard ProfileName = "standard"
	ProfileMedia    ProfileName = "media"
)

type SpoolBackend string

const (
	SpoolAuto   SpoolBackend = "auto"
	SpoolOff    SpoolBackend = "off"
	SpoolMemory SpoolBackend = "memory"
	SpoolDisk   SpoolBackend = "disk"
)

type TLSMode string

const (
	TLSSelfSigned TLSMode = "selfsigned"
	TLSCert       TLSMode = "cert"
	TLSOff        TLSMode = "off"
)

type ProfilePreset struct {
	Name                      ProfileName
	GoMemLimitBytes           int64
	GOGC                      int
	CopyBufBytes              int
	BlocksPerChunk            int
	MaxTransportChunkBytes    int64
	RecommendedParallelChunks int
	MaxParallelChunks         int
	MaxActiveRooms            int
	MaxConns                  int
	MaxConnsPerIP             int
	MaxTransferStreams        int
	MaxTransferStreamsPerIP   int
	DefaultSpool              SpoolBackend
	SpoolMaxTotalBytes        int64
	SpoolMaxMailboxBytes      int64
	SpoolMaxItemBytes         int64
	SpoolMaxItemsPerMailbox   int
	MaxMailboxes              int
	SpoolDefaultTTLSec        int64
	SpoolMaxTTLSec            int64
	MaxDownloadsPerChunk      int
	ControlRatePerMin         float64
	ControlBurst              int
	DataRatePerMin            float64
	DataBurst                 int
	MaxTrackedIPs             int
	MaxNonceEntries           int
}

func PresetFor(name ProfileName) (ProfilePreset, error) {
	switch name {
	case ProfileNano:
		return ProfilePreset{
			Name:                      ProfileNano,
			GoMemLimitBytes:           48 << 20,
			GOGC:                      50,
			CopyBufBytes:              32 << 10,
			BlocksPerChunk:            4,
			MaxTransportChunkBytes:    4 * CryptoBlockBytes, // 262,208 B
			RecommendedParallelChunks: 1,
			MaxParallelChunks:         2,
			MaxActiveRooms:            32,
			MaxConns:                  64,
			MaxConnsPerIP:             16,
			MaxTransferStreams:        2,
			MaxTransferStreamsPerIP:   1,
			DefaultSpool:              SpoolMemory,
			SpoolMaxTotalBytes:        16 << 20,
			SpoolMaxMailboxBytes:      8 << 20,
			SpoolMaxItemBytes:         4 << 20,
			SpoolMaxItemsPerMailbox:   16,
			MaxMailboxes:              256,
			SpoolDefaultTTLSec:        1800,
			SpoolMaxTTLSec:            7200,
			MaxDownloadsPerChunk:      3,
			ControlRatePerMin:         120,
			ControlBurst:              40,
			DataRatePerMin:            1800,
			DataBurst:                 240,
			MaxTrackedIPs:             2048,
			MaxNonceEntries:           16384,
		}, nil
	case ProfileStandard:
		return ProfilePreset{
			Name:                      ProfileStandard,
			GoMemLimitBytes:           144 << 20,
			GOGC:                      50,
			CopyBufBytes:              64 << 10,
			BlocksPerChunk:            16,
			MaxTransportChunkBytes:    16 * CryptoBlockBytes, // 1,048,832 B
			RecommendedParallelChunks: 1,
			MaxParallelChunks:         3,
			MaxActiveRooms:            128,
			MaxConns:                  128,
			MaxConnsPerIP:             16,
			MaxTransferStreams:        8,
			MaxTransferStreamsPerIP:   3,
			DefaultSpool:              SpoolDisk,
			SpoolMaxTotalBytes:        512 << 20,
			SpoolMaxMailboxBytes:      256 << 20,
			SpoolMaxItemBytes:         100 << 20,
			SpoolMaxItemsPerMailbox:   64,
			MaxMailboxes:              4096,
			SpoolDefaultTTLSec:        86400,
			SpoolMaxTTLSec:            259200,
			MaxDownloadsPerChunk:      5,
			ControlRatePerMin:         240,
			ControlBurst:              80,
			DataRatePerMin:            3600,
			DataBurst:                 480,
			MaxTrackedIPs:             4096,
			MaxNonceEntries:           65536,
		}, nil
	case ProfileMedia:
		return ProfilePreset{
			Name:                      ProfileMedia,
			GoMemLimitBytes:           384 << 20,
			GOGC:                      100,
			CopyBufBytes:              64 << 10,
			BlocksPerChunk:            32,
			MaxTransportChunkBytes:    32 * CryptoBlockBytes, // 2,097,664 B
			RecommendedParallelChunks: 2,
			MaxParallelChunks:         4,
			MaxActiveRooms:            512,
			MaxConns:                  512,
			MaxConnsPerIP:             32,
			MaxTransferStreams:        32,
			MaxTransferStreamsPerIP:   8,
			DefaultSpool:              SpoolDisk,
			SpoolMaxTotalBytes:        10 << 30,
			SpoolMaxMailboxBytes:      4 << 30,
			SpoolMaxItemBytes:         2 << 30,
			SpoolMaxItemsPerMailbox:   256,
			MaxMailboxes:              32768,
			SpoolDefaultTTLSec:        259200,
			SpoolMaxTTLSec:            604800,
			MaxDownloadsPerChunk:      5,
			ControlRatePerMin:         480,
			ControlBurst:              160,
			DataRatePerMin:            6000,
			DataBurst:                 800,
			MaxTrackedIPs:             16384,
			MaxNonceEntries:           262144,
		}, nil
	default:
		return ProfilePreset{}, fmt.Errorf("unknown profile %q (valid: auto, nano, standard, media)", name)
	}
}

func ResolveAutoProfileName(memBytes uint64) ProfileName {
	if memBytes == 0 {
		return ProfileStandard
	}
	if memBytes < AutoProfileNanoMaxBytes {
		return ProfileNano
	}
	if memBytes < AutoProfileMediaMinBytes {
		return ProfileStandard
	}
	return ProfileMedia
}

// EffectiveMemoryBytes returns min(hostMem, cgroupLimit) across whichever limits are positive.
func EffectiveMemoryBytes(hostMem, cgroupLimit uint64) uint64 {
	if hostMem > 0 && cgroupLimit > 0 {
		if cgroupLimit < hostMem {
			return cgroupLimit
		}
		return hostMem
	}
	if cgroupLimit > 0 {
		return cgroupLimit
	}
	return hostMem
}

// ComputeSafeGoMemLimit computes a safe GOMEMLIMIT (~58.6% of effective memory, so 256 MiB yields 150 MiB),
// bounded by a safe per-profile ceiling so bare-metal hosts without cgroup limits do not over-reserve RAM.
func ComputeSafeGoMemLimit(effectiveMem uint64, preset ProfilePreset) int64 {
	if effectiveMem == 0 {
		return preset.GoMemLimitBytes
	}
	// 75/128 = 58.59375% (within ~56-62%; 256 MiB -> 150 MiB).
	safe := int64((effectiveMem / 128) * 75)
	if safe <= 0 {
		safe = int64((effectiveMem * 3) / 5)
	}
	if safe < 24<<20 {
		safe = 24 << 20
	}
	var maxCap int64
	switch preset.Name {
	case ProfileNano:
		maxCap = 96 << 20
	case ProfileStandard:
		maxCap = 256 << 20
	case ProfileMedia:
		maxCap = 768 << 20
	default:
		maxCap = preset.GoMemLimitBytes * 2
	}
	if maxCap > 0 && safe > maxCap {
		safe = maxCap
	}
	return safe
}

type Config struct {
	ListenAddr       string
	PublicHost       string
	Profile          ProfileName
	Spool            SpoolBackend
	TLSMode          TLSMode
	TLSCertPath      string
	TLSKeyPath       string
	DataDir          string
	AccessKey        string
	TrustedProxies   []netip.Prefix
	CORSOrigins      []string
	MaxBandwidthMbps float64
	ServerVersion    string

	// Optional overrides (0 = inherit preset)
	SpoolMaxTotalBytes      int64
	SpoolMaxMailboxBytes    int64
	SpoolMaxItemBytes       int64
	SpoolMaxItemsPerMailbox int
	SpoolMaxMailboxes       int
	SpoolDefaultTTLSec      int64
	SpoolMaxTTLSec          int64
	MaxDownloadsPerChunk    int
	RendezvousTimeout       time.Duration
	StallTimeout            time.Duration
	MaxChunkDuration        time.Duration
	SSEKeepaliveInterval    time.Duration
	SSEMaxDuration          time.Duration

	// Test hooks
	DetectMemFunc       func() uint64
	DetectMemLimitsFunc func() (hostMem, cgroupLimit uint64)
	DiskFreeFunc        func(string) (uint64, bool)
	NowFunc             func() time.Time
	DisableMemTune      bool
}

type ResolvedConfig struct {
	Config
	Preset     ProfilePreset
	SpoolMode  SpoolBackend
	AccessKey  string
	KeyCreated bool
	Warnings   []string
}

func DefaultConfig() Config {
	return Config{
		ListenAddr: ":54843",
		Profile:    ProfileAuto,
		Spool:      SpoolAuto,
		TLSMode:    TLSSelfSigned,
		DataDir:    "/data",
	}
}

func LoadConfigFromEnv(base Config) (Config, error) {
	cfg := base
	if v := strings.TrimSpace(os.Getenv("SYNCTOOL_LISTEN")); v != "" {
		cfg.ListenAddr = v
	}
	if v := strings.TrimSpace(os.Getenv("SYNCTOOL_PUBLIC_HOST")); v != "" {
		cfg.PublicHost = v
	}
	if v := strings.TrimSpace(os.Getenv("SYNCTOOL_PROFILE")); v != "" {
		cfg.Profile = ProfileName(strings.ToLower(v))
	}
	if v := strings.TrimSpace(os.Getenv("SYNCTOOL_SPOOL")); v != "" {
		cfg.Spool = SpoolBackend(strings.ToLower(v))
	}
	if v := strings.TrimSpace(os.Getenv("SYNCTOOL_TLS")); v != "" {
		cfg.TLSMode = TLSMode(strings.ToLower(v))
	}
	if v := strings.TrimSpace(os.Getenv("SYNCTOOL_TLS_CERT")); v != "" {
		cfg.TLSCertPath = v
	}
	if v := strings.TrimSpace(os.Getenv("SYNCTOOL_TLS_KEY")); v != "" {
		cfg.TLSKeyPath = v
	}
	if v := strings.TrimSpace(os.Getenv("SYNCTOOL_DATA_DIR")); v != "" {
		cfg.DataDir = v
	}
	if v := strings.TrimSpace(os.Getenv("SYNCTOOL_ACCESS_KEY")); v != "" {
		cfg.AccessKey = v
	}
	if v := strings.TrimSpace(os.Getenv("SYNCTOOL_TRUSTED_PROXIES")); v != "" {
		prefixes, err := ParseTrustedProxies(v)
		if err != nil {
			return cfg, err
		}
		cfg.TrustedProxies = prefixes
	}
	if v := strings.TrimSpace(os.Getenv("SYNCTOOL_CORS_ORIGINS")); v != "" {
		origins, err := ParseCORSOrigins(v)
		if err != nil {
			return cfg, err
		}
		cfg.CORSOrigins = origins
	}
	if v := strings.TrimSpace(os.Getenv("SYNCTOOL_MAX_BANDWIDTH_MBPS")); v != "" {
		mbps, err := strconv.ParseFloat(v, 64)
		if err != nil || mbps < 0 {
			return cfg, fmt.Errorf("invalid SYNCTOOL_MAX_BANDWIDTH_MBPS: %q", v)
		}
		cfg.MaxBandwidthMbps = mbps
	}
	return cfg, nil
}

// ParseCORSOrigins parses comma-separated exact origins (e.g. "https://app.example.com,http://localhost:5173") or "*".
func ParseCORSOrigins(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p == "*" {
			if !seen["*"] {
				seen["*"] = true
				out = append(out, "*")
			}
			continue
		}
		norm, ok := normalizeExactOrigin(p)
		if !ok {
			return nil, fmt.Errorf("invalid CORS origin %q (expected exact scheme://host[:port] or *)", p)
		}
		if !seen[norm] {
			seen[norm] = true
			out = append(out, norm)
		}
	}
	return out, nil
}

func normalizeExactOrigin(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" || !strings.Contains(raw, "://") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	if u.Path != "" && u.Path != "/" {
		return "", false
	}
	if strings.Contains(u.Host, "*") {
		return "", false
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), true
}

// MatchCORSOrigin checks if reqOrigin matches the configured allowlist.
// Returns the Access-Control-Allow-Origin value to emit ("*" or reqOrigin) and true on match.
func MatchCORSOrigin(allowlist []string, reqOrigin string) (string, bool) {
	if len(allowlist) == 0 {
		return "", false
	}
	normReq, ok := normalizeExactOrigin(reqOrigin)
	if !ok {
		return "", false
	}
	for _, allowed := range allowlist {
		if allowed == "*" {
			return "*", true
		}
		if allowed == normReq {
			return strings.TrimSpace(reqOrigin), true
		}
	}
	return "", false
}

func ParseTrustedProxies(raw string) ([]netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]netip.Prefix, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "/") {
			pref, err := netip.ParsePrefix(p)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", p, err)
			}
			addr := pref.Addr()
			bits := pref.Bits()
			if addr.Is4In6() {
				addr = addr.Unmap()
				if bits >= 96 {
					bits -= 96
				} else {
					bits = 0
				}
			}
			addr = addr.WithZone("")
			out = append(out, netip.PrefixFrom(addr, bits).Masked())
		} else {
			addr, err := netip.ParseAddr(p)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy IP %q: %w", p, err)
			}
			addr = addr.Unmap().WithZone("")
			out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return out, nil
}

func IsLoopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.Trim(host, "[]")
	if host == "" || host == "0.0.0.0" || host == "::" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.Unmap().WithZone("").IsLoopback()
}

// ParseCgroupV2MaxBytes parses a cgroup v2 memory.max file payload ("max" or empty -> 0).
func ParseCgroupV2MaxBytes(content string) uint64 {
	s := strings.TrimSpace(content)
	if s == "" || s == "max" {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v == 0 || v >= (1<<60) {
		return 0
	}
	return v
}

// WalkCgroupV2TightestMax walks from the leaf cgroup v2 slice up to cgroupRoot,
// returning the minimum positive memory.max across all ancestor slices (handles leaf "max").
func WalkCgroupV2TightestMax(cgroupRoot, v2Rel string, readFile func(string) ([]byte, error)) uint64 {
	if cgroupRoot == "" || readFile == nil {
		return 0
	}
	rootClean := filepath.Clean(cgroupRoot)
	cur := rootClean
	if rel := strings.TrimSpace(v2Rel); rel != "" && rel != "/" && !strings.Contains(rel, "..") {
		cand := filepath.Clean(filepath.Join(rootClean, filepath.FromSlash(strings.TrimPrefix(rel, "/"))))
		if cand == rootClean || strings.HasPrefix(cand, rootClean+string(filepath.Separator)) {
			cur = cand
		}
	}

	var tightest uint64
	for {
		if data, err := readFile(filepath.Join(cur, "memory.max")); err == nil {
			if v := ParseCgroupV2MaxBytes(string(data)); v > 0 && (tightest == 0 || v < tightest) {
				tightest = v
			}
		}
		if cur == rootClean {
			break
		}
		parent := filepath.Dir(cur)
		if parent == cur || !strings.HasPrefix(parent, rootClean) {
			break
		}
		cur = parent
	}
	return tightest
}

// ParseProcSelfCgroupPaths extracts relative cgroup v2 and v1 memory slice paths from /proc/self/cgroup.
func ParseProcSelfCgroupPaths(content string) (v2Rel string, v1MemRel string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "0::") {
			rel := strings.TrimSpace(strings.TrimPrefix(line, "0::"))
			if rel != "" && rel != "/" && !strings.Contains(rel, "..") {
				v2Rel = rel
			}
			continue
		}
		first := strings.IndexByte(line, ':')
		if first < 0 {
			continue
		}
		rest := line[first+1:]
		second := strings.IndexByte(rest, ':')
		if second < 0 {
			continue
		}
		subsys := rest[:second]
		rel := strings.TrimSpace(rest[second+1:])
		if rel == "" || rel == "/" || strings.Contains(rel, "..") {
			continue
		}
		for _, s := range strings.Split(subsys, ",") {
			if s == "memory" {
				v1MemRel = rel
				break
			}
		}
	}
	return v2Rel, v1MemRel
}

func GenerateAccessKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	defer clear(buf)
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func EnsureAccessKey(dataDir, provided string) (key string, created bool, err error) {
	provided = strings.TrimSpace(provided)
	if provided != "" {
		if len(provided) < 32 {
			return "", false, errors.New("access key must be at least 32 characters")
		}
		return provided, false, nil
	}
	if dataDir != "" {
		keyPath := filepath.Join(dataDir, "access.key")
		raw, readErr := os.ReadFile(keyPath)
		if readErr == nil {
			k := strings.TrimSpace(string(raw))
			clear(raw)
			if len(k) < 32 {
				return "", false, fmt.Errorf("persisted access.key at %s is shorter than 32 chars", keyPath)
			}
			return k, false, nil
		}
		if !os.IsNotExist(readErr) {
			return "", false, readErr
		}
		k, genErr := GenerateAccessKey()
		if genErr != nil {
			return "", false, genErr
		}
		if mkErr := os.MkdirAll(dataDir, 0o700); mkErr != nil {
			return "", false, fmt.Errorf("access key not provided and cannot create data-dir %s: %w", dataDir, mkErr)
		}
		if wErr := atomicWriteFile(keyPath, []byte(k+"\n"), 0o600); wErr != nil {
			return "", false, fmt.Errorf("access key not provided and cannot write %s: %w", keyPath, wErr)
		}
		return k, true, nil
	}
	k, genErr := GenerateAccessKey()
	if genErr != nil {
		return "", false, genErr
	}
	return k, true, nil
}

func (c Config) Resolve() (ResolvedConfig, error) {
	rc := ResolvedConfig{Config: c}
	if rc.ListenAddr == "" {
		rc.ListenAddr = ":54843"
	}
	if rc.Profile == "" {
		rc.Profile = ProfileAuto
	}
	if rc.Spool == "" {
		rc.Spool = SpoolAuto
	}
	if rc.TLSMode == "" {
		rc.TLSMode = TLSSelfSigned
	}

	// Validate TLS mode and safety guard.
	switch rc.TLSMode {
	case TLSSelfSigned:
	case TLSCert:
		if rc.TLSCertPath == "" || rc.TLSKeyPath == "" {
			return rc, errors.New("--tls=cert requires both --tls-cert and --tls-key")
		}
	case TLSOff:
		if !IsLoopbackListenAddr(rc.ListenAddr) && len(rc.TrustedProxies) == 0 {
			return rc, fmt.Errorf("refusing --tls=off on non-loopback address %q without --trust-proxies", rc.ListenAddr)
		}
	default:
		return rc, fmt.Errorf("invalid tls mode %q (valid: selfsigned, cert, off)", rc.TLSMode)
	}

	// Validate & normalize optional CORS origins.
	if len(rc.CORSOrigins) > 0 {
		normOrigins, cerr := ParseCORSOrigins(strings.Join(rc.CORSOrigins, ","))
		if cerr != nil {
			return rc, cerr
		}
		rc.CORSOrigins = normOrigins
	}

	// Detect effective memory and resolve profile preset + safe GOMEMLIMIT.
	var effectiveMem uint64
	if rc.DetectMemLimitsFunc != nil {
		h, cg := rc.DetectMemLimitsFunc()
		effectiveMem = EffectiveMemoryBytes(h, cg)
	} else if rc.DetectMemFunc != nil {
		effectiveMem = rc.DetectMemFunc()
	} else {
		h, cg := detectMemoryLimits()
		effectiveMem = EffectiveMemoryBytes(h, cg)
	}

	profName := rc.Profile
	if profName == ProfileAuto {
		profName = ResolveAutoProfileName(effectiveMem)
	}
	preset, err := PresetFor(profName)
	if err != nil {
		return rc, err
	}
	if effectiveMem > 0 {
		preset.GoMemLimitBytes = ComputeSafeGoMemLimit(effectiveMem, preset)
	}

	// Apply explicit overrides if provided.
	if rc.SpoolMaxTotalBytes > 0 {
		preset.SpoolMaxTotalBytes = rc.SpoolMaxTotalBytes
	}
	if rc.SpoolMaxMailboxBytes > 0 {
		preset.SpoolMaxMailboxBytes = rc.SpoolMaxMailboxBytes
	}
	if rc.SpoolMaxItemBytes > 0 {
		preset.SpoolMaxItemBytes = rc.SpoolMaxItemBytes
	}
	if rc.SpoolMaxItemsPerMailbox > 0 {
		preset.SpoolMaxItemsPerMailbox = rc.SpoolMaxItemsPerMailbox
	}
	if rc.SpoolMaxMailboxes > 0 {
		preset.MaxMailboxes = rc.SpoolMaxMailboxes
	}
	if rc.SpoolDefaultTTLSec > 0 {
		preset.SpoolDefaultTTLSec = rc.SpoolDefaultTTLSec
	}
	if rc.SpoolMaxTTLSec > 0 {
		preset.SpoolMaxTTLSec = rc.SpoolMaxTTLSec
	}
	if rc.MaxDownloadsPerChunk > 0 {
		preset.MaxDownloadsPerChunk = rc.MaxDownloadsPerChunk
	}
	rc.Preset = preset

	// Resolve spool backend with explicit override taking absolute priority.
	switch rc.Spool {
	case SpoolOff, SpoolMemory, SpoolDisk:
		rc.SpoolMode = rc.Spool
	case SpoolAuto:
		rc.SpoolMode = preset.DefaultSpool
		if rc.SpoolMode == SpoolDisk {
			ok := false
			if rc.DataDir != "" {
				if mkErr := os.MkdirAll(filepath.Join(rc.DataDir, "spool"), 0o700); mkErr == nil {
					check := rc.DiskFreeFunc
					if check == nil {
						check = detectFreeDiskBytes
					}
					free, supported := check(rc.DataDir)
					if !supported || free >= MinAutoDiskFreeBytes {
						ok = true
					}
				}
			}
			if !ok {
				rc.SpoolMode = SpoolMemory
				rc.Warnings = append(rc.Warnings, "auto spool downgraded from disk to memory (data-dir unavailable or <256 MiB free)")
			}
		}
	default:
		return rc, fmt.Errorf("invalid spool mode %q (valid: auto, off, memory, disk)", rc.Spool)
	}

	if rc.SpoolMode == SpoolDisk && rc.DataDir == "" {
		return rc, errors.New("--spool=disk requires --data-dir")
	}

	// Ensure private access key (never hardcoded).
	ak, created, err := EnsureAccessKey(rc.DataDir, rc.AccessKey)
	if err != nil {
		return rc, err
	}
	rc.AccessKey = ak
	rc.KeyCreated = created

	// Apply default durations.
	if rc.RendezvousTimeout <= 0 {
		rc.RendezvousTimeout = RendezvousTimeout
	}
	if rc.StallTimeout <= 0 {
		rc.StallTimeout = StallTimeout
	}
	if rc.MaxChunkDuration <= 0 {
		rc.MaxChunkDuration = MaxChunkTransferDuration
	}
	if rc.SSEKeepaliveInterval <= 0 {
		rc.SSEKeepaliveInterval = SSEKeepaliveInterval
	}
	if rc.SSEMaxDuration <= 0 {
		rc.SSEMaxDuration = SSEMaxDuration
	}
	if rc.NowFunc == nil {
		rc.NowFunc = time.Now
	}

	return rc, nil
}

func ApplyMemoryTuning(preset ProfilePreset) {
	if os.Getenv("GOMEMLIMIT") == "" && preset.GoMemLimitBytes > 0 {
		debug.SetMemoryLimit(preset.GoMemLimitBytes)
	}
	if os.Getenv("GOGC") == "" && preset.GOGC > 0 {
		debug.SetGCPercent(preset.GOGC)
	}
}
