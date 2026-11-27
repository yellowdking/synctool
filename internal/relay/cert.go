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

func GenerateSelfSignedCert(publicHosts string, now time.Time, certPath, keyPath string) (*CertBundle, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
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
	b, err := GenerateSelfSignedCert(publicHosts, now, cm.certPath, cm.keyPath)
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
