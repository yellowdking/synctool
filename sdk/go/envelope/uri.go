package envelope

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
)

const (
	TLSModeSystemCA = "system_ca"
	TLSModeSPKIPin  = "spki_pin"
	MaxSPKIPins     = 8
)

// RelayProfile holds validated connection & security settings for one self-hosted relay.
type RelayProfile struct {
	RelayID    string   `json:"relay_id"`
	Alias      string   `json:"alias,omitempty"`
	Endpoint   string   `json:"endpoint"`   // canonical_relay_origin (scheme://host:port)
	AccessKey  string   `json:"access_key"` // secret — NEVER log
	TLSMode    string   `json:"tls_mode"`   // "system_ca" | "spki_pin"
	SPKISHA256 string   `json:"spki_sha256,omitempty"`
	SPKIPin    string   `json:"spki_pin,omitempty"`  // primary pin alias (kept in sync with SPKISHA256 / SPKIPins[0])
	SPKIPins   []string `json:"spki_pins,omitempty"` // 1..8 normalized 64-lowercase-hex SPKI pins
	IsDefault  bool     `json:"is_default,omitempty"`
}

// PairOffer holds a parsed synctool://pair URI (Mode 0 direct / Mode 1 QR OOB / Mode 2 SAS).
type PairOffer struct {
	Version    int      `json:"v"`
	RoomID     string   `json:"r"` // canonical 8-char uppercase Crockford Base32
	Mode       int      `json:"m"` // 0 | 1 | 2
	Purpose    string   `json:"p"` // "direct" | "oneshot" | "pair"
	Endpoint   string   `json:"u,omitempty"`
	SPKISHA256 string   `json:"pin,omitempty"`
	SPKIPin    string   `json:"-"`                   // primary pin alias (kept in sync with SPKISHA256 / SPKIPins[0])
	SPKIPins   []string `json:"spki_pins,omitempty"` // 1..8 normalized 64-lowercase-hex SPKI pins
	ExpiresAt  int64    `json:"exp,omitempty"`
	OOBSecret  []byte   `json:"-"` // 16B secret (ONLY for Mode 1; NEVER log)
	AccessKey  string   `json:"-"` // optional relay key (NEVER log)
}

// ParseSPKIPins parses 1..8 comma-separated 64-character hex SPKI SHA-256 pins into normalized lowercase hex.
func ParseSPKIPins(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	if len(parts) < 1 || len(parts) > MaxSPKIPins {
		return nil, NewError(ErrCodeURIInvalid, false, 0, fmt.Sprintf("pin count must be between 1 and %d", MaxSPKIPins), nil)
	}
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		p := strings.ToLower(strings.TrimSpace(part))
		if !reHex64.MatchString(p) {
			return nil, NewError(ErrCodeURIInvalid, false, 0, "each SPKI pin must be 64 hex chars", nil)
		}
		if _, dup := seen[p]; !dup {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out, nil
}

// NormalizeSPKIPins resolves and validates SPKIPins alongside single-pin aliases (SPKISHA256 / SPKIPin),
// supporting callers that set SPKIPins, SPKISHA256, or SPKIPin (including comma-separated strings or single-pin overrides).
func NormalizeSPKIPins(pins []string, spkiSHA256, spkiPin string) ([]string, error) {
	s1 := strings.ToLower(strings.TrimSpace(spkiSHA256))
	s2 := strings.ToLower(strings.TrimSpace(spkiPin))
	if len(pins) > 0 {
		// Detect when a caller cloned a 1-pin struct and mutated SPKISHA256 or SPKIPin directly.
		firstNorm := strings.ToLower(strings.TrimSpace(pins[0]))
		if len(pins) == 1 {
			if s1 != "" && s1 != firstNorm && (s2 == "" || s2 == firstNorm) {
				return ParseSPKIPins(s1)
			}
			if s2 != "" && s2 != firstNorm && (s1 == "" || s1 == firstNorm) {
				return ParseSPKIPins(s2)
			}
		}
		var expanded []string
		for _, item := range pins {
			for _, sub := range strings.Split(item, ",") {
				expanded = append(expanded, sub)
			}
		}
		if len(expanded) > MaxSPKIPins {
			return nil, NewError(ErrCodeURIInvalid, false, 0, fmt.Sprintf("pin count must be between 1 and %d", MaxSPKIPins), nil)
		}
		out := make([]string, 0, len(expanded))
		seen := make(map[string]struct{}, len(expanded))
		for _, item := range expanded {
			p := strings.ToLower(strings.TrimSpace(item))
			if !reHex64.MatchString(p) {
				return nil, NewError(ErrCodeURIInvalid, false, 0, "each SPKI pin must be 64 hex chars", nil)
			}
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				out = append(out, p)
			}
		}
		return out, nil
	}
	if s2 != "" {
		return ParseSPKIPins(s2)
	}
	if s1 != "" {
		return ParseSPKIPins(s1)
	}
	return nil, nil
}

// SyncPins normalizes and synchronizes SPKIPins, SPKISHA256, and SPKIPin on RelayProfile.
func (p *RelayProfile) SyncPins() error {
	if p == nil {
		return nil
	}
	pins, err := NormalizeSPKIPins(p.SPKIPins, p.SPKISHA256, p.SPKIPin)
	if err != nil {
		return err
	}
	if len(pins) == 0 {
		p.SPKIPins = nil
		p.SPKISHA256 = ""
		p.SPKIPin = ""
		return nil
	}
	p.SPKIPins = pins
	p.SPKISHA256 = pins[0]
	p.SPKIPin = pins[0]
	return nil
}

// SyncPins normalizes and synchronizes SPKIPins, SPKISHA256, and SPKIPin on PairOffer.
func (o *PairOffer) SyncPins() error {
	if o == nil {
		return nil
	}
	pins, err := NormalizeSPKIPins(o.SPKIPins, o.SPKISHA256, o.SPKIPin)
	if err != nil {
		return err
	}
	if len(pins) == 0 {
		o.SPKIPins = nil
		o.SPKISHA256 = ""
		o.SPKIPin = ""
		return nil
	}
	o.SPKIPins = pins
	o.SPKISHA256 = pins[0]
	o.SPKIPin = pins[0]
	return nil
}

// RedactURI strips any #fragment from a synctool:// URI so secrets can never leak into logs.
func RedactURI(raw string) string {
	if idx := strings.IndexByte(raw, '#'); idx >= 0 {
		return raw[:idx] + "#[REDACTED]"
	}
	return raw
}

// ParseRelayURI parses and strictly validates synctool://relay?v=1&u=<origin>[&pin=<64hex>[,<64hex>...]]#k=<key>.
// Enforces that bare IPv4/IPv6 hosts MUST carry at least one valid 64-hex SPKI pin.
func ParseRelayURI(raw string) (*RelayProfile, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "malformed relay URI", nil)
	}
	if strings.ToLower(u.Scheme) != "synctool" || strings.ToLower(u.Host) != "relay" {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "expected synctool://relay URI", nil)
	}
	q := u.Query()
	if v := q.Get("v"); v != "" && v != "1" {
		if vInt, verr := strconv.Atoi(v); verr == nil && vInt > 1 {
			return nil, NewError(ErrCodeUnsupportedVersion, false, 0, fmt.Sprintf("unsupported relay URI version %d (supported: 1)", vInt), map[string]any{
				"version":           vInt,
				"supported_version": 1,
			})
		}
		return nil, NewError(ErrCodeURIInvalid, false, 0, fmt.Sprintf("unsupported relay URI version %q", v), nil)
	}
	rawOrigin := q.Get("u")
	if rawOrigin == "" {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "missing required parameter u", nil)
	}
	origin, err := synccrypto.CanonicalRelayOrigin(rawOrigin)
	if err != nil {
		return nil, NewError(ErrCodeURIInvalid, false, 0, err.Error(), nil)
	}

	parsedOrigin, _ := url.Parse(origin)
	var pins []string
	var primaryPin string
	tlsMode := TLSModeSystemCA
	if q.Has("pin") {
		rawPin := strings.TrimSpace(strings.Join(q["pin"], ","))
		if rawPin == "" {
			return nil, NewError(ErrCodeURIInvalid, false, 0, "empty pin parameter", nil)
		}
		pins, err = ParseSPKIPins(rawPin)
		if err != nil {
			return nil, err
		}
		primaryPin = pins[0]
		tlsMode = TLSModeSPKIPin
	} else if parsedOrigin.Scheme == "https" && synccrypto.IsIPHost(parsedOrigin.Hostname()) {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "bare IP relay requires 64-hex SPKI pin", nil)
	}

	fragVals, err := url.ParseQuery(u.Fragment)
	if err != nil {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "malformed URI fragment", nil)
	}
	// Reject secret passed in query string instead of #fragment.
	if q.Has("k") || q.Has("s") {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "access key k must be placed in #fragment, not query", nil)
	}
	accessKey := fragVals.Get("k")
	if len(accessKey) < 32 {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "missing or short access key k in #fragment (min 32 chars)", nil)
	}

	return &RelayProfile{
		RelayID:    synccrypto.DeriveRelayID(origin),
		Endpoint:   origin,
		AccessKey:  accessKey,
		TLSMode:    tlsMode,
		SPKISHA256: primaryPin,
		SPKIPin:    primaryPin,
		SPKIPins:   pins,
	}, nil
}

// FormatRelayURI formats a RelayProfile into the canonical synctool://relay URI.
// Callers MUST NOT log the returned string without RedactURI.
func FormatRelayURI(p *RelayProfile) (string, error) {
	if p == nil {
		return "", NewError(ErrCodeURIInvalid, false, 0, "nil relay profile", nil)
	}
	origin, err := synccrypto.CanonicalRelayOrigin(p.Endpoint)
	if err != nil {
		return "", NewError(ErrCodeURIInvalid, false, 0, err.Error(), nil)
	}
	if len(p.AccessKey) < 32 {
		return "", NewError(ErrCodeURIInvalid, false, 0, "access key must be >= 32 chars", nil)
	}
	pins, err := NormalizeSPKIPins(p.SPKIPins, p.SPKISHA256, p.SPKIPin)
	if err != nil {
		return "", err
	}
	parsedOrigin, _ := url.Parse(origin)
	if len(pins) == 0 && parsedOrigin.Scheme == "https" && synccrypto.IsIPHost(parsedOrigin.Hostname()) {
		return "", NewError(ErrCodeURIInvalid, false, 0, "bare IP relay requires SPKI pin", nil)
	}
	var sb strings.Builder
	sb.WriteString("synctool://relay?v=1&u=")
	sb.WriteString(url.QueryEscape(origin))
	if len(pins) > 0 {
		sb.WriteString("&pin=")
		sb.WriteString(strings.Join(pins, ","))
	}
	sb.WriteString("#k=")
	sb.WriteString(url.QueryEscape(p.AccessKey))
	return sb.String(), nil
}

// ParsePairURI parses synctool://pair?...[#...] enforcing #s= rules for m=0/1/2.
func ParsePairURI(raw string) (*PairOffer, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "malformed pair URI", nil)
	}
	if strings.ToLower(u.Scheme) != "synctool" || strings.ToLower(u.Host) != "pair" {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "expected synctool://pair URI", nil)
	}
	q := u.Query()
	if q.Has("s") || q.Has("k") {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "secrets s/k must be in #fragment, not query", nil)
	}
	if v := q.Get("v"); v != "" && v != "1" {
		if vInt, verr := strconv.Atoi(v); verr == nil && vInt > 1 {
			return nil, NewError(ErrCodeUnsupportedVersion, false, 0, fmt.Sprintf("unsupported pair URI version %d (supported: 1)", vInt), map[string]any{
				"version":           vInt,
				"supported_version": 1,
			})
		}
		return nil, NewError(ErrCodeURIInvalid, false, 0, fmt.Sprintf("unsupported pair URI version %q", v), nil)
	}
	roomID, err := synccrypto.NormalizeRoomID(q.Get("r"))
	if err != nil {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "invalid room_id r", nil)
	}
	modeStr := q.Get("m")
	mode, err := strconv.Atoi(modeStr)
	if err != nil || (mode != synccrypto.ModeDirect && mode != synccrypto.ModeQROOB && mode != synccrypto.ModeCommitSAS) {
		return nil, NewError(ErrCodeURIInvalid, false, 0, fmt.Sprintf("invalid mode m=%q", modeStr), nil)
	}
	purpose := q.Get("p")
	switch mode {
	case synccrypto.ModeDirect:
		if purpose != synccrypto.PurposeDirect {
			return nil, NewError(ErrCodeURIInvalid, false, 0, "mode=0 requires p=direct", nil)
		}
	case synccrypto.ModeQROOB, synccrypto.ModeCommitSAS:
		if purpose != synccrypto.PurposeOneshot && purpose != synccrypto.PurposePair {
			return nil, NewError(ErrCodeURIInvalid, false, 0, "mode=1/2 requires p=oneshot or p=pair", nil)
		}
	}

	var origin, primaryPin string
	var pins []string
	rawOrigin := q.Get("u")
	if rawOrigin != "" {
		origin, err = synccrypto.CanonicalRelayOrigin(rawOrigin)
		if err != nil {
			return nil, NewError(ErrCodeURIInvalid, false, 0, err.Error(), nil)
		}
		parsedOrigin, _ := url.Parse(origin)
		if q.Has("pin") {
			rawPin := strings.TrimSpace(strings.Join(q["pin"], ","))
			if rawPin == "" {
				return nil, NewError(ErrCodeURIInvalid, false, 0, "empty pin parameter", nil)
			}
			pins, err = ParseSPKIPins(rawPin)
			if err != nil {
				return nil, err
			}
			primaryPin = pins[0]
		} else if parsedOrigin.Scheme == "https" && synccrypto.IsIPHost(parsedOrigin.Hostname()) {
			return nil, NewError(ErrCodeURIInvalid, false, 0, "bare IP in pair URI requires SPKI pin", nil)
		}
	} else if q.Has("pin") {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "pin parameter requires u relay origin", nil)
	}

	var exp int64
	if q.Has("exp") {
		expStr := q.Get("exp")
		exp, err = strconv.ParseInt(expStr, 10, 64)
		if err != nil || exp <= 0 {
			return nil, NewError(ErrCodeURIInvalid, false, 0, "invalid exp timestamp (must be positive unix seconds)", nil)
		}
	}

	fragVals, err := url.ParseQuery(u.Fragment)
	if err != nil {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "malformed fragment", nil)
	}
	sStr := fragVals.Get("s")
	var oob []byte
	if mode == synccrypto.ModeQROOB {
		if sStr == "" {
			return nil, NewError(ErrCodeURIInvalid, false, 0, "mode=1 requires #s= oob_secret", nil)
		}
		oob, err = base64.RawURLEncoding.DecodeString(sStr)
		if err != nil || len(oob) != synccrypto.OOBSecretSize {
			return nil, NewError(ErrCodeURIInvalid, false, 0, "invalid #s= oob_secret (expected 22-char b64u 16B)", nil)
		}
	} else if fragVals.Has("s") {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "mode=0/2 must omit #s=", nil)
	}

	accessKey := fragVals.Get("k")
	if fragVals.Has("k") && len(accessKey) < 32 {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "access key #k= too short", nil)
	}

	return &PairOffer{
		Version:    1,
		RoomID:     roomID,
		Mode:       mode,
		Purpose:    purpose,
		Endpoint:   origin,
		SPKISHA256: primaryPin,
		SPKIPin:    primaryPin,
		SPKIPins:   pins,
		ExpiresAt:  exp,
		OOBSecret:  oob,
		AccessKey:  accessKey,
	}, nil
}

// FormatPairURI serializes a PairOffer into synctool://pair?...[#...].
func FormatPairURI(o *PairOffer) (string, error) {
	if o == nil {
		return "", NewError(ErrCodeURIInvalid, false, 0, "nil pair offer", nil)
	}
	if o.ExpiresAt < 0 {
		return "", NewError(ErrCodeURIInvalid, false, 0, "invalid negative exp timestamp", nil)
	}
	if o.AccessKey != "" && len(o.AccessKey) < 32 {
		return "", NewError(ErrCodeURIInvalid, false, 0, "access key #k= must be >= 32 chars", nil)
	}
	roomID, err := synccrypto.NormalizeRoomID(o.RoomID)
	if err != nil {
		return "", NewError(ErrCodeURIInvalid, false, 0, "invalid room_id", nil)
	}
	switch o.Mode {
	case synccrypto.ModeDirect:
		if o.Purpose != synccrypto.PurposeDirect || len(o.OOBSecret) != 0 {
			return "", NewError(ErrCodeURIInvalid, false, 0, "mode=0 requires p=direct and no oob_secret", nil)
		}
	case synccrypto.ModeQROOB:
		if (o.Purpose != synccrypto.PurposeOneshot && o.Purpose != synccrypto.PurposePair) || len(o.OOBSecret) != synccrypto.OOBSecretSize {
			return "", NewError(ErrCodeURIInvalid, false, 0, "mode=1 requires p=oneshot|pair and 16B oob_secret", nil)
		}
	case synccrypto.ModeCommitSAS:
		if (o.Purpose != synccrypto.PurposeOneshot && o.Purpose != synccrypto.PurposePair) || len(o.OOBSecret) != 0 {
			return "", NewError(ErrCodeURIInvalid, false, 0, "mode=2 requires p=oneshot|pair and no oob_secret", nil)
		}
	default:
		return "", NewError(ErrCodeURIInvalid, false, 0, "unsupported pair mode", nil)
	}

	pins, err := NormalizeSPKIPins(o.SPKIPins, o.SPKISHA256, o.SPKIPin)
	if err != nil {
		return "", err
	}
	if o.Endpoint == "" && len(pins) > 0 {
		return "", NewError(ErrCodeURIInvalid, false, 0, "pin requires endpoint u", nil)
	}

	var sb strings.Builder
	sb.WriteString("synctool://pair?r=")
	sb.WriteString(roomID)
	sb.WriteString("&m=")
	sb.WriteString(strconv.Itoa(o.Mode))
	sb.WriteString("&p=")
	sb.WriteString(o.Purpose)
	sb.WriteString("&v=1")
	if o.Endpoint != "" {
		origin, err := synccrypto.CanonicalRelayOrigin(o.Endpoint)
		if err != nil {
			return "", NewError(ErrCodeURIInvalid, false, 0, err.Error(), nil)
		}
		parsedOrigin, _ := url.Parse(origin)
		if len(pins) == 0 && parsedOrigin.Scheme == "https" && synccrypto.IsIPHost(parsedOrigin.Hostname()) {
			return "", NewError(ErrCodeURIInvalid, false, 0, "bare IP in pair URI requires SPKI pin", nil)
		}
		sb.WriteString("&u=")
		sb.WriteString(url.QueryEscape(origin))
		if len(pins) > 0 {
			sb.WriteString("&pin=")
			sb.WriteString(strings.Join(pins, ","))
		}
	}
	if o.ExpiresAt > 0 {
		sb.WriteString("&exp=")
		sb.WriteString(strconv.FormatInt(o.ExpiresAt, 10))
	}

	var frags []string
	if o.Mode == synccrypto.ModeQROOB {
		frags = append(frags, "s="+base64.RawURLEncoding.EncodeToString(o.OOBSecret))
	}
	if o.AccessKey != "" {
		frags = append(frags, "k="+url.QueryEscape(o.AccessKey))
	}
	if len(frags) > 0 {
		sb.WriteByte('#')
		sb.WriteString(strings.Join(frags, "&"))
	}
	return sb.String(), nil
}

// RelayProfileFromEnv parses a RelayProfile from SYNCTOOL_RELAY (or fallback SYNCTOOL_RELAY_URI)
// so scripts and services can connect without exposing #k= secrets in command-line arguments.
func RelayProfileFromEnv() (*RelayProfile, error) {
	raw := strings.TrimSpace(os.Getenv("SYNCTOOL_RELAY"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("SYNCTOOL_RELAY_URI"))
	}
	if raw == "" {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "SYNCTOOL_RELAY environment variable is not set", nil)
	}
	return ParseRelayURI(raw)
}

// PairURIFromEnv reads a synctool://pair URI or 8-char room code from SYNCTOOL_PAIR_URI.
func PairURIFromEnv() (string, error) {
	raw := strings.TrimSpace(os.Getenv("SYNCTOOL_PAIR_URI"))
	if raw == "" {
		return "", NewError(ErrCodeURIInvalid, false, 0, "SYNCTOOL_PAIR_URI environment variable is not set", nil)
	}
	return raw, nil
}
