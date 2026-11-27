package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

const (
	// MasterSeedSize is the exact byte length of device_master_seed.
	MasterSeedSize = 32
	// DeviceIDRawSize is the raw byte length of device_id (16 bytes = 32 hex chars).
	DeviceIDRawSize = 16
	// MsgIDRawSize is the raw byte length of msg_id (16 bytes = 32 hex chars).
	MsgIDRawSize = 16

	masterSeedSalt     = "synctool-v1/master-seed-salt"
	infoEd25519Sign    = "synctool-v1/ed25519-sign"
	infoX25519KEM      = "synctool-v1/x25519-kem"
	infoMailboxAuthPfx = "synctool-v1/mailbox-auth/"
	infoLocalMetaKey   = "synctool-v1/local-storage-key"

	prefixRelayID    = "synctool-v1/relay-id:"
	prefixDeviceID   = "synctool-v1/device-id:"
	prefixMailboxID  = "synctool-v1/mailbox-id:"
	prefixDeviceCard = "synctool-v1/device-card\n"
)

// RFC 8410 DER prefixes for WebCrypto / cross-platform key import/export (CRYPTO_AND_AUTH.md §2.2).
var (
	// Ed25519PKCS8Prefix is the 16-byte PKCS#8 DER prefix for a 32-byte Ed25519 seed (total 48B).
	Ed25519PKCS8Prefix = [16]byte{0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20}
	// X25519PKCS8Prefix is the 16-byte PKCS#8 DER prefix for a 32-byte X25519 private key (total 48B).
	X25519PKCS8Prefix = [16]byte{0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20}
	// Ed25519SPKIPrefix is the 12-byte SPKI DER prefix for a 32-byte Ed25519 public key (total 44B).
	Ed25519SPKIPrefix = [12]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}
	// X25519SPKIPrefix is the 12-byte SPKI DER prefix for a 32-byte X25519 public key (total 44B).
	X25519SPKIPrefix = [12]byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00}
)

var (
	ErrInvalidSeed       = errors.New("device_master_seed must be 32 bytes")
	ErrInvalidKeyLength  = errors.New("invalid key length")
	ErrAllZeroSharedKey  = errors.New("x25519 shared secret is all zeros")
	ErrInvalidRelayURL   = errors.New("invalid canonical relay origin")
	ErrInvalidSignature  = errors.New("invalid ed25519 signature")
	ErrDeviceIDMismatch  = errors.New("device_id does not match sign_pk")
	ErrMailboxIDMismatch = errors.New("mailbox_id does not match mailbox_auth_pk")
)

// DeviceKeys holds all long-term device keys deterministically derived from device_master_seed.
type DeviceKeys struct {
	MasterSeed   [32]byte
	MasterPRK    [32]byte
	SignSeed     [32]byte
	SignPriv     ed25519.PrivateKey
	SignPub      ed25519.PublicKey
	KEMPrivBytes [32]byte
	KEMPriv      *ecdh.PrivateKey
	KEMPub       *ecdh.PublicKey
	KEMPubBytes  [32]byte
	LocalMetaKey [32]byte
	DeviceIDRaw  [16]byte
	DeviceID     string
}

// MailboxKeys holds per-relay mailbox ownership credentials derived from device_master_seed.
type MailboxKeys struct {
	RelayID   string
	AuthSeed  [32]byte
	AuthPriv  ed25519.PrivateKey
	AuthPub   ed25519.PublicKey
	MailboxID string
}

// ZeroBytes overwrites a byte slice with zeros.
func ZeroBytes(b []byte) {
	clear(b)
}

// Zero clears sensitive key material in DeviceKeys.
func (k *DeviceKeys) Zero() {
	if k == nil {
		return
	}
	clear(k.MasterSeed[:])
	clear(k.MasterPRK[:])
	clear(k.SignSeed[:])
	clear(k.SignPriv)
	clear(k.KEMPrivBytes[:])
	clear(k.LocalMetaKey[:])
}

// Zero clears sensitive key material in MailboxKeys.
func (m *MailboxKeys) Zero() {
	if m == nil {
		return
	}
	clear(m.AuthSeed[:])
	clear(m.AuthPriv)
}

// GenerateMasterSeed creates a fresh 32-byte CSPRNG device_master_seed.
func GenerateMasterSeed() ([32]byte, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return seed, fmt.Errorf("generate master seed: %w", err)
	}
	return seed, nil
}

// hkdfExtract follows the spec argument order: HKDF-Extract(salt, ikm).
// Go 1.24 crypto/hkdf.Extract takes (h, secret/ikm, salt).
func hkdfExtract(salt, ikm []byte) ([]byte, error) {
	return hkdf.Extract(sha256.New, ikm, salt)
}

// hkdfExpand wraps Go 1.24 crypto/hkdf.Expand(sha256.New, prk, info, length).
func hkdfExpand(prk, info []byte, length int) ([]byte, error) {
	return hkdf.Expand(sha256.New, prk, string(info), length)
}

// DeriveDeviceKeys derives all device long-term keys from a 32-byte device_master_seed
// per CRYPTO_AND_AUTH.md §3.1-§3.3.
func DeriveDeviceKeys(seed []byte) (*DeviceKeys, error) {
	if len(seed) != MasterSeedSize {
		return nil, ErrInvalidSeed
	}
	prk, err := hkdfExtract([]byte(masterSeedSalt), seed)
	if err != nil {
		return nil, err
	}
	signSeed, err := hkdfExpand(prk, []byte(infoEd25519Sign), 32)
	if err != nil {
		clear(prk)
		return nil, err
	}
	kemBytes, err := hkdfExpand(prk, []byte(infoX25519KEM), 32)
	if err != nil {
		clear(prk)
		clear(signSeed)
		return nil, err
	}
	localMeta, err := hkdfExpand(prk, []byte(infoLocalMetaKey), 32)
	if err != nil {
		clear(prk)
		clear(signSeed)
		clear(kemBytes)
		return nil, err
	}

	signPriv := ed25519.NewKeyFromSeed(signSeed)
	signPub := signPriv.Public().(ed25519.PublicKey)

	kemPriv, err := ecdh.X25519().NewPrivateKey(kemBytes)
	if err != nil {
		clear(prk)
		clear(signSeed)
		clear(kemBytes)
		clear(localMeta)
		return nil, fmt.Errorf("x25519 kem key: %w", err)
	}
	kemPub := kemPriv.PublicKey()

	devRaw, devHex := DeriveDeviceID(signPub)

	dk := &DeviceKeys{
		SignPriv:    signPriv,
		SignPub:     signPub,
		KEMPriv:     kemPriv,
		KEMPub:      kemPub,
		DeviceIDRaw: devRaw,
		DeviceID:    devHex,
	}
	copy(dk.MasterSeed[:], seed)
	copy(dk.MasterPRK[:], prk)
	copy(dk.SignSeed[:], signSeed)
	copy(dk.KEMPrivBytes[:], kemBytes)
	copy(dk.KEMPubBytes[:], kemPub.Bytes())
	copy(dk.LocalMetaKey[:], localMeta)

	clear(prk)
	clear(signSeed)
	clear(kemBytes)
	clear(localMeta)
	return dk, nil
}

// DeriveMailboxKeys derives the relay-isolated Ed25519 mailbox auth keypair and mailbox_id.
func (k *DeviceKeys) DeriveMailboxKeys(relayID string) (*MailboxKeys, error) {
	if k == nil {
		return nil, ErrInvalidSeed
	}
	if relayID == "" {
		return nil, errors.New("relay_id must not be empty")
	}
	info := make([]byte, len(infoMailboxAuthPfx)+len(relayID))
	copy(info, infoMailboxAuthPfx)
	copy(info[len(infoMailboxAuthPfx):], relayID)

	authSeed, err := hkdfExpand(k.MasterPRK[:], info, 32)
	if err != nil {
		return nil, err
	}
	authPriv := ed25519.NewKeyFromSeed(authSeed)
	authPub := authPriv.Public().(ed25519.PublicKey)
	mbID := DeriveMailboxID(authPub)

	mk := &MailboxKeys{
		RelayID:   relayID,
		AuthPriv:  authPriv,
		AuthPub:   authPub,
		MailboxID: mbID,
	}
	copy(mk.AuthSeed[:], authSeed)
	clear(authSeed)
	return mk, nil
}

// CanonicalRelayOrigin normalizes a relay URL into lowercase "scheme://host:port"
// with an explicit port and no path, query, or fragment.
func CanonicalRelayOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidRelayURL, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("%w: unsupported scheme %q", ErrInvalidRelayURL, u.Scheme)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%w: origin must not contain userinfo, query, or fragment", ErrInvalidRelayURL)
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("%w: origin must not contain path %q", ErrInvalidRelayURL, u.Path)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("%w: empty host", ErrInvalidRelayURL)
	}
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	// Plaintext http is only allowed for loopback hosts.
	if scheme == "http" && !IsLoopbackHost(host) {
		return "", fmt.Errorf("%w: http scheme only permitted for loopback", ErrInvalidRelayURL)
	}
	return scheme + "://" + net.JoinHostPort(host, port), nil
}

// IsLoopbackHost reports whether host is localhost, 127.0.0.0/8, or ::1.
func IsLoopbackHost(host string) bool {
	h := strings.ToLower(strings.Trim(host, "[]"))
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// IsIPHost reports whether host is a literal IPv4 or IPv6 address.
func IsIPHost(host string) bool {
	return net.ParseIP(strings.Trim(host, "[]")) != nil
}

// DeriveRelayID computes relay_id = hex(SHA256("synctool-v1/relay-id:" || canonicalOrigin)[0:16]).
func DeriveRelayID(canonicalOrigin string) string {
	h := sha256.New()
	h.Write([]byte(prefixRelayID))
	h.Write([]byte(canonicalOrigin))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// DeriveDeviceID computes device_id = SHA256("synctool-v1/device-id:" || signPK)[0:16].
func DeriveDeviceID(signPK []byte) ([16]byte, string) {
	var raw [16]byte
	h := sha256.New()
	h.Write([]byte(prefixDeviceID))
	h.Write(signPK)
	sum := h.Sum(nil)
	copy(raw[:], sum[:16])
	return raw, hex.EncodeToString(raw[:])
}

// DeriveMailboxID computes mailbox_id = hex(SHA256("synctool-v1/mailbox-id:" || mailboxAuthPK)[0:16]).
func DeriveMailboxID(mailboxAuthPK []byte) string {
	h := sha256.New()
	h.Write([]byte(prefixMailboxID))
	h.Write(mailboxAuthPK)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// DeviceCardSignInput constructs the exact 96-byte signing input for a DeviceCard:
// "synctool-v1/device-card\n"(24B) || sign_pk(32B) || kem_pk(32B) || uint64_be(issued_at)(8B).
func DeviceCardSignInput(signPK, kemPK []byte, issuedAt int64) ([]byte, error) {
	if len(signPK) != ed25519.PublicKeySize || len(kemPK) != 32 {
		return nil, ErrInvalidKeyLength
	}
	if issuedAt < 0 {
		return nil, errors.New("issued_at must be non-negative")
	}
	buf := make([]byte, len(prefixDeviceCard)+32+32+8)
	off := 0
	off += copy(buf[off:], prefixDeviceCard)
	off += copy(buf[off:], signPK)
	off += copy(buf[off:], kemPK)
	binary.BigEndian.PutUint64(buf[off:], uint64(issuedAt))
	return buf, nil
}

// SignDeviceCard signs a device's (sign_pk, kem_pk, issued_at) binding with sign_sk.
func SignDeviceCard(signSK ed25519.PrivateKey, kemPK []byte, issuedAt int64) ([]byte, error) {
	if len(signSK) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKeyLength
	}
	signPK := signSK.Public().(ed25519.PublicKey)
	input, err := DeviceCardSignInput(signPK, kemPK, issuedAt)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(signSK, input), nil
}

// VerifyDeviceCard verifies both device_id derivation and the Ed25519 card_sig binding.
func VerifyDeviceCard(deviceID string, signPK, kemPK []byte, issuedAt int64, cardSig []byte) error {
	if len(signPK) != ed25519.PublicKeySize || len(kemPK) != 32 || len(cardSig) != ed25519.SignatureSize {
		return ErrInvalidKeyLength
	}
	_, expectedID := DeriveDeviceID(signPK)
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(deviceID)), []byte(expectedID)) != 1 {
		return ErrDeviceIDMismatch
	}
	input, err := DeviceCardSignInput(signPK, kemPK, issuedAt)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(signPK), input, cardSig) {
		return ErrInvalidSignature
	}
	return nil
}

// X25519SharedSecret computes X25519(priv, peerPubBytes) and explicitly rejects
// all-zero shared secrets (low-order point defense, RFC 7748 §6.1).
func X25519SharedSecret(priv *ecdh.PrivateKey, peerPubBytes []byte) ([]byte, error) {
	if priv == nil || len(peerPubBytes) != 32 {
		return nil, ErrInvalidKeyLength
	}
	peerPub, err := ecdh.X25519().NewPublicKey(peerPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid x25519 public key: %w", err)
	}
	shared, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAllZeroSharedKey, err)
	}
	var zeros [32]byte
	if subtle.ConstantTimeCompare(shared, zeros[:]) == 1 {
		clear(shared)
		return nil, ErrAllZeroSharedKey
	}
	return shared, nil
}

// EncodeEd25519PKCS8 wraps a 32-byte Ed25519 seed into 48-byte RFC 8410 PKCS#8 DER.
func EncodeEd25519PKCS8(seed32 []byte) ([]byte, error) {
	if len(seed32) != 32 {
		return nil, ErrInvalidKeyLength
	}
	out := make([]byte, 48)
	copy(out[:16], Ed25519PKCS8Prefix[:])
	copy(out[16:], seed32)
	return out, nil
}

// EncodeX25519PKCS8 wraps a 32-byte X25519 private key into 48-byte RFC 8410 PKCS#8 DER.
func EncodeX25519PKCS8(sk32 []byte) ([]byte, error) {
	if len(sk32) != 32 {
		return nil, ErrInvalidKeyLength
	}
	out := make([]byte, 48)
	copy(out[:16], X25519PKCS8Prefix[:])
	copy(out[16:], sk32)
	return out, nil
}

// EncodeEd25519SPKI wraps a 32-byte Ed25519 public key into 44-byte RFC 8410 SPKI DER.
func EncodeEd25519SPKI(pk32 []byte) ([]byte, error) {
	if len(pk32) != 32 {
		return nil, ErrInvalidKeyLength
	}
	out := make([]byte, 44)
	copy(out[:12], Ed25519SPKIPrefix[:])
	copy(out[12:], pk32)
	return out, nil
}

// EncodeX25519SPKI wraps a 32-byte X25519 public key into 44-byte RFC 8410 SPKI DER.
func EncodeX25519SPKI(pk32 []byte) ([]byte, error) {
	if len(pk32) != 32 {
		return nil, ErrInvalidKeyLength
	}
	out := make([]byte, 44)
	copy(out[:12], X25519SPKIPrefix[:])
	copy(out[12:], pk32)
	return out, nil
}
