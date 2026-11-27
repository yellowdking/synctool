package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

// Config configures a synctool Go SDK Client.
type Config struct {
	AppID          string
	DeviceLabel    string
	Platform       string
	Relay          *envelope.RelayProfile
	KeyStore       envelope.KeyStore
	TempDir        string
	OnCertExpiring func(envelope.RelayCertExpiringEvent)
}

// Client is the high-level synctool v1 SDK client (ENVELOPE_AND_SDK.md §5.3).
type Client struct {
	appID          string
	deviceLabel    string
	platform       string
	profile        *envelope.RelayProfile
	keyStore       envelope.KeyStore
	tempDir        string
	onCertExpiring func(envelope.RelayCertExpiringEvent)

	httpClient     *http.Client
	deviceKeys     *synccrypto.DeviceKeys
	mailboxKeys    *synccrypto.MailboxKeys
	clockOffsetSec atomic.Int64
}

// PingResult matches GET /v1/ping (PROTOCOL.md §5.1).
type PingResult struct {
	ProtoV                int    `json:"proto_v"`
	ServerTS              int64  `json:"server_ts"`
	Profile               string `json:"profile"`
	SpoolBackend          string `json:"spool_backend"`
	CertExpiresAt         int64  `json:"cert_expires_at"`
	CertRotateRecommended bool   `json:"cert_rotate_recommended"`
	RTTMs                 int64  `json:"rtt_ms"`
	ClockOffsetSec        int64  `json:"clock_offset_sec"`
}

// RelayCaps matches GET /v1/caps (PROTOCOL.md §5.1).
type RelayCaps struct {
	ProtoV                    int           `json:"proto_v"`
	Profile                   string        `json:"profile"`
	ServerTS                  int64         `json:"server_ts"`
	CertExpiresAt             int64         `json:"cert_expires_at"`
	CertRotateRecommended     bool          `json:"cert_rotate_recommended"`
	CryptoPlaintextBlockBytes int           `json:"crypto_plaintext_block_bytes"`
	CryptoBlockBytes          int           `json:"crypto_block_bytes"`
	Streaming                 StreamingCaps `json:"streaming"`
	Spool                     SpoolCaps     `json:"spool"`
}

type StreamingCaps struct {
	Enabled                   bool `json:"enabled"`
	BlocksPerChunk            int  `json:"blocks_per_chunk"`
	MaxTransportChunkBytes    int  `json:"max_transport_chunk_bytes"`
	RecommendedParallelChunks int  `json:"recommended_parallel_chunks"`
	MaxParallelChunks         int  `json:"max_parallel_chunks"`
	RendezvousTimeoutSec      int  `json:"rendezvous_timeout_sec"`
	RoomTTLMaxSec             int  `json:"room_ttl_max_sec"`
}

type SpoolCaps struct {
	Enabled                 bool   `json:"enabled"`
	Backend                 string `json:"backend"`
	MaxItemBytes            int64  `json:"max_item_bytes"`
	MaxMailboxBytes         int64  `json:"max_mailbox_bytes"`
	MaxTotalBytes           int64  `json:"max_total_bytes"`
	MaxItemsPerMailbox      int    `json:"max_items_per_mailbox"`
	DefaultTTLSec           int    `json:"default_ttl_sec"`
	MaxTTLSec               int    `json:"max_ttl_sec"`
	UncommittedTTLSec       int    `json:"uncommitted_ttl_sec"`
	MaxManifestDownloads    int    `json:"max_manifest_downloads"`
	MaxDownloadsPerChunk    int    `json:"max_downloads_per_chunk"`
	MaxDepositTokensPerMbox int    `json:"max_deposit_tokens_per_mailbox"`
}

// InboxItemMeta represents one entry returned by GET /v1/mailboxes/{id}/items.
type InboxItemMeta struct {
	ItemID       string                `json:"item_id"`
	CreatedAt    int64                 `json:"created_at"`
	ExpiresAt    int64                 `json:"expires_at"`
	TotalBytes   int64                 `json:"total_bytes"`
	SealedHeader string                `json:"sealed_header"`
	Parts        []envelope.PartLayout `json:"parts"`
}

// InboxPreview is returned by ListInbox (two-phase preview without pulling blobs).
type InboxPreview struct {
	ItemID     string            `json:"item_id"`
	CreatedAt  int64             `json:"created_at"`
	ExpiresAt  int64             `json:"expires_at"`
	TotalBytes int64             `json:"total_bytes"`
	Cached     bool              `json:"cached"`
	Manifest   envelope.Manifest `json:"manifest"`
}

// InboxWatchEvent represents a real-time notification from WatchInbox.
type InboxWatchEvent struct {
	ItemID     string `json:"item_id"`
	TotalBytes int64  `json:"total_bytes"`
	CreatedAt  int64  `json:"created_at"`
	ExpiresAt  int64  `json:"expires_at"`
}

// SendResult summarizes a completed Mode A or Mode B send.
type SendResult struct {
	Mode       string `json:"mode"` // "pipe" | "spool"
	MsgID      string `json:"msg_id"`
	ItemID     string `json:"item_id,omitempty"`
	RoomID     string `json:"room_id,omitempty"`
	TotalBytes int64  `json:"total_bytes"`
	ExpiresAt  int64  `json:"expires_at,omitempty"`
}

// OfferReadyInfo is passed to OnOfferReady when a Mode A room is created.
type OfferReadyInfo struct {
	RoomID      string `json:"room_id"`
	DisplayCode string `json:"display_code"`
	Mode        int    `json:"mode"`
	Purpose     string `json:"purpose"`
	PairURI     string `json:"pair_uri"`
	ExpiresAt   int64  `json:"expires_at"`
}

// PairOptions configures Flow 1 pairing or one-shot transfers.
type PairOptions struct {
	Mode         int // synccrypto.ModeQROOB (1) or synccrypto.ModeCommitSAS (2)
	Label        string
	IncludeRelay bool
	TTLSec       int
	OnOfferReady func(OfferReadyInfo)
	OnSASInput   func() (string, error)
	OnSASDisplay func(sas6Digits string)
	OnProgress   func(envelope.TransferEvent)
}

// SendOptions configures Flow 2 SendToDevice.
type SendOptions struct {
	DeliveryMode string // "auto" (default) | "spool" | "pipe"
	TTLSec       int
	IncludeRelay bool
	OnOfferReady func(OfferReadyInfo)
	OnProgress   func(envelope.TransferEvent)
}

// ReceiveOptions configures Mode A or Mode B receiving.
type ReceiveOptions struct {
	OnSASDisplay func(sas6Digits string)
	OnProgress   func(envelope.TransferEvent)
}

// ParcelHandler processes a verified, locally persisted ReceivedParcel.
// Only after ParcelHandler returns nil does the SDK record seen_msg_ids and send signed ACK.
type ParcelHandler func(p envelope.ReceivedParcel) error

// New constructs a synctool Client from Config.
func New(cfg Config) (*Client, error) {
	if cfg.Relay == nil {
		return nil, envelope.NewError(envelope.ErrCodeURIInvalid, false, 0, "relay profile is required", nil)
	}
	if cfg.KeyStore == nil {
		return nil, envelope.NewError(envelope.ErrCodeKeystoreError, false, 0, "keystore is required", nil)
	}
	origin, err := synccrypto.CanonicalRelayOrigin(cfg.Relay.Endpoint)
	if err != nil {
		return nil, envelope.NewError(envelope.ErrCodeURIInvalid, false, 0, err.Error(), nil)
	}
	prof := *cfg.Relay
	prof.Endpoint = origin
	if prof.RelayID == "" {
		prof.RelayID = synccrypto.DeriveRelayID(origin)
	}
	if prof.TLSMode == "" {
		if prof.SPKISHA256 != "" {
			prof.TLSMode = envelope.TLSModeSPKIPin
		} else {
			prof.TLSMode = envelope.TLSModeSystemCA
		}
	}

	httpCli, err := buildHTTPClient(&prof)
	if err != nil {
		return nil, err
	}

	seed, err := cfg.KeyStore.LoadOrCreateMasterSeed()
	if err != nil {
		return nil, err
	}
	dk, err := synccrypto.DeriveDeviceKeys(seed[:])
	clear(seed[:])
	if err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeKeystoreError, false, 0, "derive device keys", err)
	}
	mk, err := dk.DeriveMailboxKeys(prof.RelayID)
	if err != nil {
		dk.Zero()
		return nil, envelope.WrapError(envelope.ErrCodeKeystoreError, false, 0, "derive mailbox keys", err)
	}

	appID := cfg.AppID
	if appID == "" {
		appID = "synctool.cli"
	}
	label := strings.TrimSpace(cfg.DeviceLabel)
	if label == "" {
		if stored, _ := cfg.KeyStore.GetLocalLabel(); stored != "" {
			label = stored
		} else if host, err := os.Hostname(); err == nil && host != "" {
			label = host
		} else {
			label = "synctool-device"
		}
	}
	plat := cfg.Platform
	if plat == "" {
		plat = defaultPlatform()
	}
	tempDir := cfg.TempDir
	if tempDir == "" {
		tempDir = filepath.Join(os.TempDir(), "synctool-tmp")
	}

	return &Client{
		appID:          appID,
		deviceLabel:    label,
		platform:       plat,
		profile:        &prof,
		keyStore:       cfg.KeyStore,
		tempDir:        tempDir,
		onCertExpiring: cfg.OnCertExpiring,
		httpClient:     httpCli,
		deviceKeys:     dk,
		mailboxKeys:    mk,
	}, nil
}

func defaultPlatform() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "darwin":
		return "macos"
	case "linux":
		return "linux"
	case "android":
		return "android"
	case "ios":
		return "ios"
	default:
		return "unknown"
	}
}

// Close wipes derived key material from memory and closes idle HTTP connections.
func (c *Client) Close() {
	if c == nil {
		return
	}
	if c.deviceKeys != nil {
		c.deviceKeys.Zero()
	}
	if c.mailboxKeys != nil {
		c.mailboxKeys.Zero()
	}
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
}

// Identity returns public identity metadata for this device on the active relay (never returns private keys).
func (c *Client) Identity() (deviceID, label, signPKB64U, kemPKB64U, mailboxID string) {
	return c.deviceKeys.DeviceID,
		c.deviceLabel,
		base64.RawURLEncoding.EncodeToString(c.deviceKeys.SignPub),
		base64.RawURLEncoding.EncodeToString(c.deviceKeys.KEMPubBytes[:]),
		c.mailboxKeys.MailboxID
}

// RelayProfile returns a copy of the active relay profile.
func (c *Client) RelayProfile() envelope.RelayProfile {
	return *c.profile
}

// ClockOffsetSec returns the currently cached clock offset in seconds.
func (c *Client) ClockOffsetSec() int64 {
	return c.clockOffsetSec.Load()
}

// SetClockOffsetSec overrides the local clock offset (primarily for clock-skew testing).
func (c *Client) SetClockOffsetSec(offsetSec int64) {
	c.clockOffsetSec.Store(offsetSec)
}

func (c *Client) checkCertRotation(expiresAt int64, recommended bool) {
	if expiresAt <= 0 || c.onCertExpiring == nil {
		return
	}
	remSec := expiresAt - time.Now().Unix()
	days := int(remSec / 86400)
	if recommended || days < 30 {
		sev := "warning"
		if days <= 7 {
			sev = "urgent"
		}
		c.onCertExpiring(envelope.RelayCertExpiringEvent{
			Type:          "event",
			Event:         "relay_cert_expiring_soon",
			RelayID:       c.profile.RelayID,
			ExpiresAt:     expiresAt,
			DaysRemaining: days,
			Severity:      sev,
		})
	}
}

// Ping probes relay connectivity, profile, clock offset, and TLS cert expiration.
func (c *Client) Ping(ctx context.Context) (*PingResult, error) {
	start := time.Now()
	resp, err := c.doControl(ctx, http.MethodGet, "/v1/ping", nil, reqOptions{})
	if err != nil {
		return nil, err
	}
	var out PingResult
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeBadRequest, false, resp.StatusCode, "decode ping response", err)
	}
	out.RTTMs = time.Since(start).Milliseconds()
	out.ClockOffsetSec = out.ServerTS - time.Now().Unix()
	c.checkCertRotation(out.CertExpiresAt, out.CertRotateRecommended)
	return &out, nil
}

// Capabilities fetches GET /v1/caps from the relay.
func (c *Client) Capabilities(ctx context.Context) (*RelayCaps, error) {
	resp, err := c.doControl(ctx, http.MethodGet, "/v1/caps", nil, reqOptions{})
	if err != nil {
		return nil, err
	}
	var out RelayCaps
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeBadRequest, false, resp.StatusCode, "decode caps response", err)
	}
	c.checkCertRotation(out.CertExpiresAt, out.CertRotateRecommended)
	return &out, nil
}

// EnsureMailboxRegistered registers this device's blinded mailbox (PUT /v1/mailboxes/{mailbox_id}).
// When relay runs with --spool=off, returns nil without error if spool is disabled.
// ParseRelayFromPairURI extracts a RelayProfile if a pair URI embeds u (+ pin) + #k.
func ParseRelayFromPairURI(raw string) (*envelope.RelayProfile, bool, error) {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(trimmed), "synctool://pair") {
		return nil, false, nil
	}
	offer, err := envelope.ParsePairURI(trimmed)
	if err != nil {
		return nil, false, err
	}
	if offer.Endpoint == "" || offer.AccessKey == "" {
		return nil, false, nil
	}
	tlsMode := envelope.TLSModeSystemCA
	if offer.SPKISHA256 != "" {
		tlsMode = envelope.TLSModeSPKIPin
	}
	return &envelope.RelayProfile{
		RelayID:    synccrypto.DeriveRelayID(offer.Endpoint),
		Endpoint:   offer.Endpoint,
		AccessKey:  offer.AccessKey,
		TLSMode:    tlsMode,
		SPKISHA256: offer.SPKISHA256,
	}, true, nil
}

// ResolveDeviceByIDOrLabel finds a trusted non-revoked device by exact device_id or case-insensitive label.
func ResolveDeviceByIDOrLabel(ks envelope.KeyStore, query string) (*envelope.DeviceCard, error) {
	q := strings.TrimSpace(query)
	if q == "" {
		return nil, envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "empty target device", nil)
	}
	if card, err := ks.GetDevice(q); err != nil {
		return nil, err
	} else if card != nil && !card.Revoked {
		return card, nil
	}
	cards, err := ks.ListDevices()
	if err != nil {
		return nil, err
	}
	var matches []envelope.DeviceCard
	for _, card := range cards {
		if strings.EqualFold(card.Label, q) || strings.HasPrefix(card.DeviceID, strings.ToLower(q)) {
			matches = append(matches, card)
		}
	}
	if len(matches) == 1 {
		c := matches[0]
		return &c, nil
	}
	if len(matches) > 1 {
		return nil, envelope.NewError(envelope.ErrCodeConflict, false, 0, "ambiguous device label/prefix; specify full device_id", nil)
	}
	return nil, envelope.NewError(envelope.ErrCodeDeviceUntrusted, false, 0, "target device not found in keystore", nil)
}
