package relay

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type tokenBucket struct {
	tokens   float64
	max      float64
	ratePerS float64
	last     time.Time
}

func newTokenBucket(ratePerMin float64, burst int, now time.Time) tokenBucket {
	return tokenBucket{
		tokens:   float64(burst),
		max:      float64(burst),
		ratePerS: ratePerMin / 60.0,
		last:     now,
	}
}

func (tb *tokenBucket) allow(now time.Time) bool {
	if now.After(tb.last) {
		elapsed := now.Sub(tb.last).Seconds()
		tb.tokens += elapsed * tb.ratePerS
		if tb.tokens > tb.max {
			tb.tokens = tb.max
		}
		tb.last = now
	}
	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}
	return false
}

type ipEntry struct {
	ctrl        tokenBucket
	data        tokenBucket
	strikes     int
	lastStrike  time.Time
	bannedUntil time.Time
	lastSeen    time.Time
}

type IPGuard struct {
	mu             sync.Mutex
	trustedProxies []netip.Prefix
	maxTrackedIPs  int
	ctrlRate       float64
	ctrlBurst      int
	dataRate       float64
	dataBurst      int
	entries        map[netip.Prefix]*ipEntry
}

func NewIPGuard(preset ProfilePreset, trustedProxies []netip.Prefix) *IPGuard {
	return &IPGuard{
		trustedProxies: trustedProxies,
		maxTrackedIPs:  preset.MaxTrackedIPs,
		ctrlRate:       preset.ControlRatePerMin,
		ctrlBurst:      preset.ControlBurst,
		dataRate:       preset.DataRatePerMin,
		dataBurst:      preset.DataBurst,
		entries:        make(map[netip.Prefix]*ipEntry, 128),
	}
}

func NormalizeIPKey(addr netip.Addr) netip.Prefix {
	addr = addr.Unmap()
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked()
	}
	return netip.PrefixFrom(addr, 32)
}

func (g *IPGuard) isTrusted(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range g.trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func ParseRemoteAddrIP(remoteAddr string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// ExtractClientIP extracts the true client IP safely respecting TRUSTED_PROXIES.
func (g *IPGuard) ExtractClientIP(r *http.Request) netip.Addr {
	remoteIP, ok := ParseRemoteAddrIP(r.RemoteAddr)
	if !ok {
		return netip.MustParseAddr("0.0.0.0")
	}
	if len(g.trustedProxies) == 0 || !g.isTrusted(remoteIP) {
		return remoteIP
	}

	// Walk X-Forwarded-For right-to-left and pick first IP not in TRUSTED_PROXIES.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			cand := strings.TrimSpace(parts[i])
			if addr, err := netip.ParseAddr(cand); err == nil {
				addr = addr.Unmap()
				if !g.isTrusted(addr) {
					return addr
				}
			}
		}
	}

	// Fallback to CF-Connecting-IP / X-Real-IP when proxy is explicitly trusted.
	for _, hdr := range []string{"CF-Connecting-IP", "X-Real-IP"} {
		if v := strings.TrimSpace(r.Header.Get(hdr)); v != "" {
			if addr, err := netip.ParseAddr(v); err == nil {
				return addr.Unmap()
			}
		}
	}

	return remoteIP
}

func (g *IPGuard) IsBanned(addr netip.Addr, now time.Time) bool {
	key := NormalizeIPKey(addr)
	g.mu.Lock()
	defer g.mu.Unlock()
	ent, ok := g.entries[key]
	if !ok {
		return false
	}
	return now.Before(ent.bannedUntil)
}

func (g *IPGuard) getOrCreateLocked(key netip.Prefix, now time.Time) *ipEntry {
	if ent, ok := g.entries[key]; ok {
		ent.lastSeen = now
		return ent
	}
	if len(g.entries) >= g.maxTrackedIPs {
		g.evictLocked(now)
	}
	ent := &ipEntry{
		ctrl:     newTokenBucket(g.ctrlRate, g.ctrlBurst, now),
		data:     newTokenBucket(g.dataRate, g.dataBurst, now),
		lastSeen: now,
	}
	g.entries[key] = ent
	return ent
}

func (g *IPGuard) evictLocked(now time.Time) {
	// First drop idle non-banned entries (>10 min idle).
	cutoff := now.Add(-10 * time.Minute)
	removed := 0
	target := g.maxTrackedIPs / 8
	if target < 16 {
		target = 16
	}
	for k, v := range g.entries {
		if !now.Before(v.bannedUntil) && v.lastSeen.Before(cutoff) {
			delete(g.entries, k)
			removed++
			if removed >= target {
				return
			}
		}
	}
	// If still at capacity, remove arbitrary oldest-ish batch.
	for k := range g.entries {
		delete(g.entries, k)
		removed++
		if removed >= target {
			return
		}
	}
}

func (g *IPGuard) AllowRequest(addr netip.Addr, isDataOrEvent bool, now time.Time) (allowed bool, banned bool) {
	key := NormalizeIPKey(addr)
	g.mu.Lock()
	defer g.mu.Unlock()
	ent := g.getOrCreateLocked(key, now)
	if now.Before(ent.bannedUntil) {
		return false, true
	}
	if isDataOrEvent {
		return ent.data.allow(now), false
	}
	return ent.ctrl.allow(now), false
}

func (g *IPGuard) RecordStrike(addr netip.Addr, now time.Time) (bannedNow bool) {
	key := NormalizeIPKey(addr)
	g.mu.Lock()
	defer g.mu.Unlock()
	ent := g.getOrCreateLocked(key, now)
	if !ent.lastStrike.IsZero() && now.After(ent.lastStrike) {
		decay := int(now.Sub(ent.lastStrike) / StrikeDecayWindow)
		if decay > 0 {
			ent.strikes -= decay
			if ent.strikes < 0 {
				ent.strikes = 0
			}
		}
	}
	ent.strikes++
	ent.lastStrike = now
	if ent.strikes >= StrikeBanThreshold {
		ent.bannedUntil = now.Add(StrikeBanDuration)
		ent.strikes = 0
		return true
	}
	return false
}

// LimitListener enforces L4 active TCP concurrency and drops banned IPs at Accept().
type LimitListener struct {
	net.Listener
	guard     *IPGuard
	nowFunc   func() time.Time
	maxTotal  int
	maxPerIP  int
	mu        sync.Mutex
	total     int
	perIP     map[netip.Prefix]int
	hasProxy  bool
}

func NewLimitListener(inner net.Listener, guard *IPGuard, maxTotal, maxPerIP int, nowFunc func() time.Time) *LimitListener {
	if nowFunc == nil {
		nowFunc = time.Now
	}
	return &LimitListener{
		Listener: inner,
		guard:    guard,
		nowFunc:  nowFunc,
		maxTotal: maxTotal,
		maxPerIP: maxPerIP,
		perIP:    make(map[netip.Prefix]int, 64),
		hasProxy: guard != nil && len(guard.trustedProxies) > 0,
	}
}

func (l *LimitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		addr, ok := ParseRemoteAddrIP(conn.RemoteAddr().String())
		var key netip.Prefix
		if ok {
			key = NormalizeIPKey(addr)
			// Only drop at L4 if source is not a trusted reverse proxy.
			if l.guard != nil && !l.guard.isTrusted(addr) && l.guard.IsBanned(addr, l.nowFunc()) {
				_ = conn.Close()
				continue
			}
		}

		l.mu.Lock()
		isTrusted := ok && l.guard != nil && l.guard.isTrusted(addr)
		if l.total >= l.maxTotal || (ok && !isTrusted && l.perIP[key] >= l.maxPerIP) {
			l.mu.Unlock()
			_ = conn.Close()
			continue
		}
		l.total++
		if ok && !isTrusted {
			l.perIP[key]++
		}
		l.mu.Unlock()

		return &trackedConn{
			Conn:      conn,
			listener:  l,
			key:       key,
			trackPerP: ok && !isTrusted,
		}, nil
	}
}

type trackedConn struct {
	net.Conn
	listener  *LimitListener
	key       netip.Prefix
	trackPerP bool
	once      sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.listener.mu.Lock()
		c.listener.total--
		if c.trackPerP {
			if n := c.listener.perIP[c.key] - 1; n <= 0 {
				delete(c.listener.perIP, c.key)
			} else {
				c.listener.perIP[c.key] = n
			}
		}
		c.listener.mu.Unlock()
	})
	return c.Conn.Close()
}

// TransferGate limits L7 concurrent media streams (global & per-IP).
type TransferGate struct {
	mu       sync.Mutex
	maxTotal int
	maxPerIP int
	active   int
	perIP    map[netip.Prefix]int
	waitCh   chan struct{}
}

func NewTransferGate(maxTotal, maxPerIP int) *TransferGate {
	return &TransferGate{
		maxTotal: maxTotal,
		maxPerIP: maxPerIP,
		perIP:    make(map[netip.Prefix]int, 32),
		waitCh:   make(chan struct{}),
	}
}

func (tg *TransferGate) Acquire(ctx context.Context, ip netip.Addr, wait time.Duration) (release func(), ok bool) {
	key := NormalizeIPKey(ip)
	deadline := time.NewTimer(wait)
	defer deadline.Stop()

	for {
		tg.mu.Lock()
		if tg.active < tg.maxTotal && tg.perIP[key] < tg.maxPerIP {
			tg.active++
			tg.perIP[key]++
			tg.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					tg.mu.Lock()
					tg.active--
					if n := tg.perIP[key] - 1; n <= 0 {
						delete(tg.perIP, key)
					} else {
						tg.perIP[key] = n
					}
					close(tg.waitCh)
					tg.waitCh = make(chan struct{})
					tg.mu.Unlock()
				})
			}, true
		}
		ch := tg.waitCh
		tg.mu.Unlock()

		select {
		case <-ch:
		case <-deadline.C:
			return nil, false
		case <-ctx.Done():
			return nil, false
		}
	}
}

// BandwidthLimiter provides optional global throughput pacing (in bytes/sec).
type BandwidthLimiter struct {
	mu         sync.Mutex
	bytesPerS  float64
	burstBytes float64
	tokens     float64
	last       time.Time
}

func NewBandwidthLimiter(mbps float64) *BandwidthLimiter {
	if mbps <= 0 {
		return nil
	}
	bps := mbps * 1_000_000 / 8.0
	burst := bps * 0.25
	if burst < 65536 {
		burst = 65536
	}
	return &BandwidthLimiter{
		bytesPerS:  bps,
		burstBytes: burst,
		tokens:     burst,
		last:       time.Now(),
	}
}

func (bl *BandwidthLimiter) WaitN(ctx context.Context, n int) error {
	if bl == nil || n <= 0 {
		return nil
	}
	for {
		bl.mu.Lock()
		now := time.Now()
		if now.After(bl.last) {
			bl.tokens += now.Sub(bl.last).Seconds() * bl.bytesPerS
			if bl.tokens > bl.burstBytes {
				bl.tokens = bl.burstBytes
			}
			bl.last = now
		}
		if bl.tokens >= float64(n) {
			bl.tokens -= float64(n)
			bl.mu.Unlock()
			return nil
		}
		deficit := float64(n) - bl.tokens
		waitDur := time.Duration((deficit / bl.bytesPerS) * float64(time.Second))
		if waitDur < time.Millisecond {
			waitDur = time.Millisecond
		}
		bl.mu.Unlock()

		timer := time.NewTimer(waitDur)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}

type rateLimitedReader struct {
	ctx context.Context
	r   io.Reader
	bl  *BandwidthLimiter
}

func (rl *rateLimitedReader) Read(p []byte) (int, error) {
	n, err := rl.r.Read(p)
	if n > 0 && rl.bl != nil {
		if werr := rl.bl.WaitN(rl.ctx, n); werr != nil {
			return n, werr
		}
	}
	return n, err
}

func ZeroBytes(b []byte) {
	clear(b)
}
