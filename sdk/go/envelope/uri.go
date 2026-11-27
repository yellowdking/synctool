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
)

// RelayProfile holds validated connection & security settings for one self-hosted relay.
type RelayProfile struct {
	RelayID    string `json:"relay_id"`
	Alias      string `json:"alias,omitempty"`
	Endpoint   string `json:"endpoint"`   // canonical_relay_origin (scheme://host:port)
	AccessKey  string `json:"access_key"` // secret — NEVER log
	TLSMode    string `json:"tls_mode"`   // "system_ca" | "spki_pin"
	SPKISHA256 string `json:"spki_sha256,omitempty"`
	IsDefault  bool   `json:"is_default,omitempty"`
}

// PairOffer holds a parsed synctool://pair URI (Mode 0 direct / Mode 1 QR OOB / Mode 2 SAS).
type PairOffer struct {
	Version    int    `json:"v"`
	RoomID     string `json:"r"` // canonical 8-char uppercase Crockford Base32
	Mode       int    `json:"m"` // 0 | 1 | 2
	Purpose    string `json:"p"` // "direct" | "oneshot" | "pair"
	Endpoint   string `json:"u,omitempty"`
	SPKISHA256 string `json:"pin,omitempty"`
	ExpiresAt  int64  `json:"exp,omitempty"`
	OOBSecret  []byte `json:"-"` // 16B secret (ONLY for Mode 1; NEVER log)
	AccessKey  string `json:"-"` // optional relay key (NEVER log)
}

// RedactURI strips any #fragment from a synctool:// URI so secrets can never leak into logs.
func RedactURI(raw string) string {
	if idx := strings.IndexByte(raw, '#'); idx >= 0 {
		return raw[:idx] + "#[REDACTED]"
	}
	return raw
}

// ParseRelayURI parses and strictly validates synctool://relay?v=1&u=<origin>[&pin=<64hex>]#k=<key>.
// Enforces that bare IPv4/IPv6 hosts MUST carry a valid 64-hex SPKI pin.
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
	pin := strings.ToLower(strings.TrimSpace(q.Get("pin")))
	tlsMode := TLSModeSystemCA
	if pin != "" {
		if !reHex64.MatchString(pin) {
			return nil, NewError(ErrCodeURIInvalid, false, 0, "pin must be 64 lowercase hex chars", nil)
		}
		tlsMode = TLSModeSPKIPin
	} else if parsedOrigin.Scheme == "https" && synccrypto.IsIPHost(parsedOrigin.Hostname()) {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "bare IP relay requires 64-hex SPKI pin", nil)
	}

	fragVals, err := url.ParseQuery(u.Fragment)
	if err != nil {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "malformed URI fragment", nil)
	}
	// Reject secret passed in query string instead of #fragment.
	if q.Get("k") != "" {
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
		SPKISHA256: pin,
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
	parsedOrigin, _ := url.Parse(origin)
	pin := strings.ToLower(strings.TrimSpace(p.SPKISHA256))
	if pin != "" && !reHex64.MatchString(pin) {
		return "", NewError(ErrCodeURIInvalid, false, 0, "invalid SPKI pin", nil)
	}
	if pin == "" && parsedOrigin.Scheme == "https" && synccrypto.IsIPHost(parsedOrigin.Hostname()) {
		return "", NewError(ErrCodeURIInvalid, false, 0, "bare IP relay requires SPKI pin", nil)
	}
	var sb strings.Builder
	sb.WriteString("synctool://relay?v=1&u=")
	sb.WriteString(url.QueryEscape(origin))
	if pin != "" {
		sb.WriteString("&pin=")
		sb.WriteString(pin)
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
	if q.Get("s") != "" || q.Get("k") != "" {
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

	var origin, pin string
	if rawOrigin := q.Get("u"); rawOrigin != "" {
		origin, err = synccrypto.CanonicalRelayOrigin(rawOrigin)
		if err != nil {
			return nil, NewError(ErrCodeURIInvalid, false, 0, err.Error(), nil)
		}
		pin = strings.ToLower(strings.TrimSpace(q.Get("pin")))
		parsedOrigin, _ := url.Parse(origin)
		if pin != "" {
			if !reHex64.MatchString(pin) {
				return nil, NewError(ErrCodeURIInvalid, false, 0, "invalid SPKI pin", nil)
			}
		} else if parsedOrigin.Scheme == "https" && synccrypto.IsIPHost(parsedOrigin.Hostname()) {
			return nil, NewError(ErrCodeURIInvalid, false, 0, "bare IP in pair URI requires SPKI pin", nil)
		}
	}

	var exp int64
	if expStr := q.Get("exp"); expStr != "" {
		exp, err = strconv.ParseInt(expStr, 10, 64)
		if err != nil || exp < 0 {
			return nil, NewError(ErrCodeURIInvalid, false, 0, "invalid exp timestamp", nil)
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
	} else if sStr != "" {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "mode=0/2 must omit #s=", nil)
	}

	accessKey := fragVals.Get("k")
	if accessKey != "" && len(accessKey) < 32 {
		return nil, NewError(ErrCodeURIInvalid, false, 0, "access key #k= too short", nil)
	}

	return &PairOffer{
		Version:    1,
		RoomID:     roomID,
		Mode:       mode,
		Purpose:    purpose,
		Endpoint:   origin,
		SPKISHA256: pin,
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
		sb.WriteString("&u=")
		sb.WriteString(url.QueryEscape(origin))
		if o.SPKISHA256 != "" {
			sb.WriteString("&pin=")
			sb.WriteString(strings.ToLower(o.SPKISHA256))
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
