package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

const (
	StagedCertFileName = "tls-next.crt"
	StagedKeyFileName  = "tls-next.key"
)

type CertBundle struct {
	TLSCert       tls.Certificate
	Leaf          *x509.Certificate
	SPKISHA256Hex string
	ExpiresAt     int64
}

type CertManager struct {
	mode     TLSMode
	certPath string
	keyPath  string
	current  atomic.Pointer[CertBundle]
}

func NewCertManager(cfg ResolvedConfig) (*CertManager, error) {
	cm := &CertManager{mode: cfg.TLSMode}
	switch cfg.TLSMode {
	case TLSOff:
		return cm, nil
	case TLSCert:
		cm.certPath = cfg.TLSCertPath
		cm.keyPath = cfg.TLSKeyPath
		if err := cm.Reload(); err != nil {
			return nil, err
		}
		return cm, nil
	case TLSSelfSigned:
		if cfg.DataDir != "" {
			cm.certPath = filepath.Join(cfg.DataDir, "cert.pem")
			cm.keyPath = filepath.Join(cfg.DataDir, "key.pem")
			if fileExists(cm.certPath) && fileExists(cm.keyPath) {
				if err := cm.Reload(); err != nil {
					return nil, err
				}
				return cm, nil
			}
		}
		b, err := GenerateSelfSignedCert(cfg.PublicHost, cfg.NowFunc(), cm.certPath, cm.keyPath)
		if err != nil {
			return nil, err
		}
		cm.current.Store(b)
		return cm, nil
	default:
		return nil, fmt.Errorf("unsupported tls mode: %s", cfg.TLSMode)
	}
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func LoadCertBundle(certPath, keyPath string) (*CertBundle, error) {
	tc, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	if len(tc.Certificate) == 0 {
		return nil, fmt.Errorf("certificate chain empty in %s", certPath)
	}
	leaf, err := x509.ParseCertificate(tc.Certificate[0])
	if err != nil {
		return nil, err
	}
	tc.Leaf = leaf
	return &CertBundle{
		TLSCert:       tc,
		Leaf:          leaf,
		SPKISHA256Hex: SPKISHA256Hex(leaf),
		ExpiresAt:     leaf.NotAfter.Unix(),
	}, nil
}

func ReadLeafCert(certPath string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	for len(raw) > 0 {
		var blk *pem.Block
		blk, raw = pem.Decode(raw)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			return x509.ParseCertificate(blk.Bytes)
		}
	}
	return nil, fmt.Errorf("no CERTIFICATE PEM block found in %s", certPath)
}

func LoadECPrivateKey(keyPath string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	defer clear(raw)

	for rest := raw; len(rest) > 0; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "EC PRIVATE KEY":
			priv, perr := x509.ParseECPrivateKey(blk.Bytes)
			if perr != nil {
				return nil, perr
			}
			if priv.Curve != elliptic.P256() {
				return nil, fmt.Errorf("unsupported ECDSA curve in %s (expected P-256)", keyPath)
			}
			return priv, nil
		case "PRIVATE KEY":
			pk, perr := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if perr != nil {
				return nil, perr
			}
			ecPriv, ok := pk.(*ecdsa.PrivateKey)
			if !ok || ecPriv.Curve != elliptic.P256() {
				return nil, fmt.Errorf("unsupported PKCS#8 key type in %s (expected ECDSA P-256)", keyPath)
			}
			return ecPriv, nil
		}
	}
	return nil, fmt.Errorf("no ECDSA P-256 private key PEM block found in %s", keyPath)
}

// ExtractCertPublicHosts returns comma-separated non-loopback IPAddresses and non-localhost DNSNames from leaf.
func ExtractCertPublicHosts(leaf *x509.Certificate) string {
	if leaf == nil {
		return ""
	}
	var out []string
	seen := make(map[string]bool)
	for _, ip := range leaf.IPAddresses {
		if ip == nil || ip.IsLoopback() {
			continue
		}
		s := ip.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, dns := range leaf.DNSNames {
		d := strings.ToLower(strings.TrimSpace(dns))
		if d == "" || d == "localhost" {
			continue
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return strings.Join(out, ",")
}

func extractPrimaryHostToken(raw string) string {
	h := strings.TrimSpace(raw)
	if h == "" {
		return ""
	}
	if idx := strings.IndexByte(h, ','); idx >= 0 {
		h = strings.TrimSpace(h[:idx])
	}
	if strings.Contains(h, "://") {
		if u, err := url.Parse(h); err == nil && u.Hostname() != "" {
			return strings.Trim(u.Hostname(), "[]")
		}
	}
	if hostOnly, _, err := net.SplitHostPort(h); err == nil && hostOnly != "" {
		h = hostOnly
	}
	return strings.Trim(h, "[]")
}

// ResolveCertServerName derives the TLS SNI / hostname verification target for healthcheck under --tls=cert.
func ResolveCertServerName(publicHost, listenAddr, certPath string) string {
	if h := extractPrimaryHostToken(publicHost); h != "" {
		return h
	}
	if certPath != "" {
		if leaf, err := ReadLeafCert(certPath); err == nil {
			for _, d := range leaf.DNSNames {
				d = strings.TrimSpace(d)
				if d != "" && !strings.EqualFold(d, "localhost") && !strings.HasPrefix(d, "*.") {
					return d
				}
			}
			for _, d := range leaf.DNSNames {
				d = strings.TrimSpace(d)
				if strings.HasPrefix(d, "*.") && len(d) > 2 {
					return "healthcheck." + d[2:]
				}
				if d != "" {
					return d
				}
			}
			for _, ip := range leaf.IPAddresses {
				if ip != nil && !ip.IsLoopback() {
					return ip.String()
				}
			}
			for _, ip := range leaf.IPAddresses {
				if ip != nil {
					return ip.String()
				}
			}
			if cn := strings.TrimSpace(leaf.Subject.CommonName); cn != "" && !strings.HasPrefix(cn, "*.") {
				return cn
			}
		}
	}
	if host, _, err := net.SplitHostPort(listenAddr); err == nil {
		trimmed := strings.Trim(host, "[]")
		if trimmed != "" && trimmed != "0.0.0.0" && trimmed != "::" {
			return trimmed
		}
	}
	return "localhost"
}

func GenerateSelfSignedCert(publicHosts string, now time.Time, certPath, keyPath string) (*CertBundle, error) {
	return GenerateSelfSignedCertWithKey(nil, publicHosts, now, certPath, keyPath)
}

func GenerateSelfSignedCertWithKey(priv *ecdsa.PrivateKey, publicHosts string, now time.Time, certPath, keyPath string) (*CertBundle, error) {
	// Inherit non-loopback IP/DNS SANs from existing certificate when publicHosts is omitted.
	if strings.TrimSpace(publicHosts) == "" && certPath != "" {
		if oldLeaf, err := ReadLeafCert(certPath); err == nil {
			publicHosts = ExtractCertPublicHosts(oldLeaf)
		}
	}

	var err error
	if priv == nil {
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
	} else if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("expected ECDSA P-256 private key")
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	if serial.Sign() <= 0 {
		serial = big.NewInt(1)
	}

	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	dnsNames := []string{"localhost"}
	seenIP := map[string]bool{"127.0.0.1": true, "::1": true}
	seenDNS := map[string]bool{"localhost": true}

	for _, raw := range strings.Split(publicHosts, ",") {
		h := strings.TrimSpace(raw)
		if h == "" {
			continue
		}
		// Strip scheme or port if user accidentally passed host:port or https://host:port
		if strings.Contains(h, "://") {
			if u, parseErr := url.Parse(h); parseErr == nil && u.Hostname() != "" {
				h = u.Hostname()
			}
		} else if hostOnly, _, splitErr := net.SplitHostPort(h); splitErr == nil && hostOnly != "" {
			h = hostOnly
		}
		h = strings.Trim(h, "[]")
		if ip := net.ParseIP(h); ip != nil {
			if !seenIP[ip.String()] {
				seenIP[ip.String()] = true
				ips = append(ips, ip)
			}
		} else if h != "" {
			lh := strings.ToLower(h)
			if !seenDNS[lh] {
				seenDNS[lh] = true
				dnsNames = append(dnsNames, lh)
			}
		}
	}

	// Strictly 730 days (<=730d, safely below Apple's 825-day leaf cert ceiling).
	notBefore := now.UTC().Add(-5 * time.Minute)
	notAfter := notBefore.Add(CertValidityDays * 24 * time.Hour)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "synctool-relay",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		IPAddresses:           ips,
		DNSNames:              dnsNames,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	defer clear(keyDER)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	defer clear(keyPEM)

	if certPath != "" && keyPath != "" {
		if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
			return nil, err
		}
		if err := atomicWriteFile(certPath, certPEM, 0o600); err != nil {
			return nil, err
		}
		if err := atomicWriteFile(keyPath, keyPEM, 0o600); err != nil {
			return nil, err
		}
	}

	tc, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	tc.Leaf = leaf

	return &CertBundle{
		TLSCert:       tc,
		Leaf:          leaf,
		SPKISHA256Hex: SPKISHA256Hex(leaf),
		ExpiresAt:     leaf.NotAfter.Unix(),
	}, nil
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmp := fmt.Sprintf("%s.%x.tmp", path, rnd[:])
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	_ = f.Chmod(perm)
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(tmp)
		if werr != nil {
			return werr
		}
		if serr != nil {
			return serr
		}
		return cerr
	}
	var renameErr error
	for attempt := 0; attempt < 5; attempt++ {
		if renameErr = os.Rename(tmp, path); renameErr == nil {
			return nil
		}
		time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
	}
	_ = os.Remove(tmp)
	return renameErr
}

// RotateSelfSignedReuseKey re-signs a fresh 730-day leaf certificate reusing the existing ECDSA P-256 private key
// so the SPKI SHA-256 pin remains unchanged across routine renewals.
func RotateSelfSignedReuseKey(publicHosts string, now time.Time, certPath, keyPath string) (*CertBundle, error) {
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("certPath and keyPath are required for --reuse-key")
	}
	priv, err := LoadECPrivateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load existing private key %s: %w", keyPath, err)
	}
	return GenerateSelfSignedCertWithKey(priv, publicHosts, now, certPath, keyPath)
}

// StageNextSelfSignedCert generates tls-next.crt and tls-next.key alongside the active cert.pem/key.pem
// without modifying the active certificate, returning both current and staged bundles for dual-pin rollout.
func StageNextSelfSignedCert(dataDir, publicHosts string, now time.Time) (current *CertBundle, staged *CertBundle, err error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, nil, fmt.Errorf("data-dir is required for --stage-next")
	}
	curCertPath := filepath.Join(dataDir, "cert.pem")
	curKeyPath := filepath.Join(dataDir, "key.pem")
	cur, err := LoadCertBundle(curCertPath, curKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load active certificate in %s: %w", dataDir, err)
	}
	if strings.TrimSpace(publicHosts) == "" {
		publicHosts = ExtractCertPublicHosts(cur.Leaf)
	}
	nextCertPath := filepath.Join(dataDir, StagedCertFileName)
	nextKeyPath := filepath.Join(dataDir, StagedKeyFileName)
	next, err := GenerateSelfSignedCertWithKey(nil, publicHosts, now, nextCertPath, nextKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("generate staged certificate: %w", err)
	}
	return cur, next, nil
}

// PromoteStagedCert validates tls-next.crt/tls-next.key and atomically promotes them to cert.pem/key.pem.
func PromoteStagedCert(dataDir string, now time.Time) (*CertBundle, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, fmt.Errorf("data-dir is required for --promote-staged")
	}
	nextCertPath := filepath.Join(dataDir, StagedCertFileName)
	nextKeyPath := filepath.Join(dataDir, StagedKeyFileName)
	staged, err := LoadCertBundle(nextCertPath, nextKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load staged certificate (%s / %s): %w", StagedCertFileName, StagedKeyFileName, err)
	}
	if !now.Before(staged.Leaf.NotAfter) {
		return nil, fmt.Errorf("staged certificate in %s has already expired (%s)", StagedCertFileName, staged.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}

	nextCertPEM, err := os.ReadFile(nextCertPath)
	if err != nil {
		return nil, err
	}
	nextKeyPEM, err := os.ReadFile(nextKeyPath)
	if err != nil {
		return nil, err
	}
	defer clear(nextKeyPEM)

	curCertPath := filepath.Join(dataDir, "cert.pem")
	curKeyPath := filepath.Join(dataDir, "key.pem")
	oldKeyPEM, _ := os.ReadFile(curKeyPath)
	defer clear(oldKeyPEM)

	if err := atomicWriteFile(curKeyPath, nextKeyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("promote %s -> key.pem: %w", StagedKeyFileName, err)
	}
	if err := atomicWriteFile(curCertPath, nextCertPEM, 0o600); err != nil {
		if len(oldKeyPEM) > 0 {
			_ = atomicWriteFile(curKeyPath, oldKeyPEM, 0o600)
		}
		return nil, fmt.Errorf("promote %s -> cert.pem: %w", StagedCertFileName, err)
	}
	_ = os.Remove(nextCertPath)
	_ = os.Remove(nextKeyPath)

	return LoadCertBundle(curCertPath, curKeyPath)
}

func SPKISHA256Hex(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func (cm *CertManager) Reload() error {
	if cm.mode == TLSOff {
		return nil
	}
	b, err := LoadCertBundle(cm.certPath, cm.keyPath)
	if err != nil {
		return err
	}
	cm.current.Store(b)
	return nil
}

func (cm *CertManager) RotateSelfSigned(publicHosts string, now time.Time) (*CertBundle, error) {
	if cm.mode != TLSSelfSigned {
		return nil, fmt.Errorf("cert-rotate only applies to tls=selfsigned (current: %s)", cm.mode)
	}
	if strings.TrimSpace(publicHosts) == "" {
		if cur := cm.current.Load(); cur != nil && cur.Leaf != nil {
			publicHosts = ExtractCertPublicHosts(cur.Leaf)
		}
	}
	b, err := GenerateSelfSignedCert(publicHosts, now, cm.certPath, cm.keyPath)
	if err != nil {
		return nil, err
	}
	cm.current.Store(b)
	return b, nil
}

func (cm *CertManager) RotateSelfSignedReuseKey(publicHosts string, now time.Time) (*CertBundle, error) {
	if cm.mode != TLSSelfSigned {
		return nil, fmt.Errorf("cert-rotate only applies to tls=selfsigned (current: %s)", cm.mode)
	}
	if strings.TrimSpace(publicHosts) == "" {
		if cur := cm.current.Load(); cur != nil && cur.Leaf != nil {
			publicHosts = ExtractCertPublicHosts(cur.Leaf)
		}
	}
	b, err := RotateSelfSignedReuseKey(publicHosts, now, cm.certPath, cm.keyPath)
	if err != nil {
		return nil, err
	}
	cm.current.Store(b)
	return b, nil
}

func (cm *CertManager) Current() *CertBundle {
	return cm.current.Load()
}

func (cm *CertManager) Status(now time.Time) (expiresAt int64, rotateRecommended bool) {
	b := cm.current.Load()
	if b == nil || b.ExpiresAt == 0 {
		return 0, false
	}
	rem := time.Unix(b.ExpiresAt, 0).Sub(now)
	return b.ExpiresAt, rem < CertRotateWarnDays*24*time.Hour
}

func (cm *CertManager) TLSConfig() *tls.Config {
	if cm.mode == TLSOff {
		return nil
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			b := cm.current.Load()
			if b == nil {
				return nil, fmt.Errorf("no tls certificate loaded")
			}
			return &b.TLSCert, nil
		},
	}
}

// BuildRelayURI formats the canonical synctool://relay onboarding URI.
// Supports single 64-hex pin or comma-separated multi-pin ("<cur>,<next>").
// Sensitive access_key is placed strictly in #fragment per spec/PROTOCOL.md §7.4.
func BuildRelayURI(canonicalOrigin, spkiHex, accessKey string) string {
	var b strings.Builder
	b.WriteString("synctool://relay?v=1&u=")
	b.WriteString(url.QueryEscape(canonicalOrigin))
	if spkiHex != "" {
		b.WriteString("&pin=")
		b.WriteString(strings.ToLower(spkiHex))
	}
	b.WriteString("#k=")
	b.WriteString(accessKey)
	return b.String()
}

// BuildRedactedRelayURI formats the synctool://relay URI with #k=<redacted> for safe non-secret output.
func BuildRedactedRelayURI(canonicalOrigin, spkiHex string) string {
	return BuildRelayURI(canonicalOrigin, spkiHex, "<redacted>")
}

func CanonicalOrigin(publicHost, listenAddr string, tlsMode TLSMode) string {
	scheme := "https"
	defaultPort := "443"
	if tlsMode == TLSOff {
		// Typically fronted by reverse proxy on HTTPS 443 when publicHost is set.
		if publicHost == "" || IsLoopbackListenAddr(listenAddr) {
			scheme = "http"
			defaultPort = "80"
		}
	}

	_, listenPort, err := net.SplitHostPort(listenAddr)
	if err != nil || listenPort == "" {
		listenPort = "54843"
	}

	host := strings.TrimSpace(publicHost)
	if host == "" {
		host = "127.0.0.1"
	}
	// If user passed full URL, normalize it.
	if strings.Contains(host, "://") {
		if u, err := url.Parse(host); err == nil && u.Hostname() != "" {
			if u.Scheme != "" {
				scheme = strings.ToLower(u.Scheme)
			}
			port := u.Port()
			if port == "" {
				if scheme == "http" {
					port = "80"
				} else {
					port = "443"
				}
			}
			h := strings.ToLower(u.Hostname())
			if strings.Contains(h, ":") {
				h = "[" + h + "]"
			}
			return fmt.Sprintf("%s://%s:%s", scheme, h, port)
		}
	}

	// If user passed comma-separated hosts, take first.
	if idx := strings.IndexByte(host, ','); idx >= 0 {
		host = strings.TrimSpace(host[:idx])
	}
	port := listenPort
	if h, p, splitErr := net.SplitHostPort(host); splitErr == nil {
		host = h
		if p != "" {
			port = p
		}
	} else if tlsMode == TLSOff && !IsLoopbackListenAddr(listenAddr) {
		port = defaultPort
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}
