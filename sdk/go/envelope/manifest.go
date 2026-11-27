package envelope

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
)

const (
	EnvelopeVersion           = 1
	MaxInlinePayloadBytes     = 65536
	MaxManifestBytes          = synccrypto.ManifestMaxRawBytes // 131072
	MaxPaddedManifestBytes    = 135168                         // ceil((4 + 131072) / 4096) * 4096
	MaxEncryptedManifestBytes = 135216                         // 135168 + 3 * 16B AEAD tags
	MaxManifestChunks         = 4                              // At most 3 64KiB blocks (capped at 4 chunks)
	MaxBlobs                  = synccrypto.MaxPartID           // 63
	MaxBlobMetaBytes          = 2048
	MaxSafeIntJS              = int64(9007199254740991)
)

var (
	reAppOrSchema = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,63}$`)
	reRole        = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	reHex32       = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reHex64       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// SenderInfo identifies the sender inside the encrypted Manifest.
type SenderInfo struct {
	DeviceID string `json:"device_id"`
	Label    string `json:"label"`
	Platform string `json:"platform,omitempty"`
}

// BlobDescriptor describes a single encrypted binary attachment slot (part_id 1..63).
type BlobDescriptor struct {
	PartID   uint32         `json:"part_id"`
	Role     string         `json:"role"`
	Name     string         `json:"name"`
	MIME     string         `json:"mime"`
	Size     int64          `json:"size"`
	SHA256   string         `json:"sha256"`
	Key      string         `json:"key"` // 43-char unpadded b64u (32B random blob_key)
	Encoding string         `json:"encoding,omitempty"`
	Meta     map[string]any `json:"meta,omitempty"`
}

// Manifest is the decrypted JSON structure carried in part_id = 0 (ENVELOPE_AND_SDK.md §2.2).
type Manifest struct {
	EnvelopeVersion int              `json:"envelope_version"`
	MsgID           string           `json:"msg_id"`
	AppID           string           `json:"app_id"`
	Schema          string           `json:"schema"`
	CreatedAt       int64            `json:"created_at"`
	Sender          SenderInfo       `json:"sender"`
	InlinePayload   map[string]any   `json:"inline_payload,omitempty"`
	Blobs           []BlobDescriptor `json:"blobs"`
}

// BlobInput specifies an outbound binary attachment strictly by file path or streaming opener
// (NEVER by raw []byte, preventing mobile/desktop OOM on large videos).
type BlobInput struct {
	Role     string
	Name     string
	MIME     string
	Encoding string
	Meta     map[string]any
	FilePath string
	// Open allows streaming from a non-file source. Must return a fresh stream and exact plaintext size.
	Open func() (io.ReadCloser, int64, error)
}

// OpenStream opens a fresh streaming reader for BlobInput and returns its exact plaintext byte size.
func (b BlobInput) OpenStream() (io.ReadCloser, int64, error) {
	if b.Open != nil {
		return b.Open()
	}
	if b.FilePath == "" {
		return nil, 0, NewError(ErrCodeStorageIO, false, 0, "blob input missing FilePath and Open", nil)
	}
	f, err := os.Open(b.FilePath)
	if err != nil {
		return nil, 0, WrapError(ErrCodeStorageIO, false, 0, "open blob file", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, WrapError(ErrCodeStorageIO, false, 0, "stat blob file", err)
	}
	if st.IsDir() {
		_ = f.Close()
		return nil, 0, NewError(ErrCodeStorageIO, false, 0, "blob path is a directory", nil)
	}
	return f, st.Size(), nil
}

// ParcelInput is the business-layer payload handed to Client.Send* APIs.
type ParcelInput struct {
	AppID         string
	Schema        string
	InlinePayload map[string]any
	Blobs         []BlobInput
}

// Parcel is a convenient alias for ParcelInput.
type Parcel = ParcelInput

// BlobFromFile constructs a streaming BlobInput backed by a local file path (never loads file into RAM).
func BlobFromFile(role, filePath string, mimeType ...string) BlobInput {
	if role == "" {
		role = "file"
	}
	mt := ""
	if len(mimeType) > 0 {
		mt = mimeType[0]
	}
	if mt == "" {
		mt = inferBasicMIME(filePath)
	}
	return BlobInput{
		Role:     role,
		Name:     filepath.Base(filePath),
		MIME:     mt,
		FilePath: filePath,
	}
}

// BlobFromReader constructs a streaming BlobInput from a repeatable stream factory with known plaintext byte size.
func BlobFromReader(role, name, mimeType string, size int64, open func() (io.ReadCloser, error)) BlobInput {
	if role == "" {
		role = "file"
	}
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	return BlobInput{
		Role: role,
		Name: name,
		MIME: mimeType,
		Open: func() (io.ReadCloser, int64, error) {
			rc, err := open()
			return rc, size, err
		},
	}
}

// ParcelText constructs a zero-boilerplate UTF-8 text parcel (`schema = "clip.text.v1"`).
func ParcelText(appID, text string) ParcelInput {
	return ParcelInput{
		AppID:         appID,
		Schema:        "clip.text.v1",
		InlinePayload: map[string]any{"text": text},
	}
}

// ParcelJSON constructs a structured parcel with optional streaming blob attachments.
func ParcelJSON(appID, schema string, payload map[string]any, blobs ...BlobInput) ParcelInput {
	return ParcelInput{
		AppID:         appID,
		Schema:        schema,
		InlinePayload: payload,
		Blobs:         blobs,
	}
}

func inferBasicMIME(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".txt", ".md", ".log":
		return "text/plain; charset=utf-8"
	case ".json":
		return "application/json"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".webp":
		return "image/webp"
	case ".gif":
		return "image/gif"
	case ".mp4":
		return "video/mp4"
	case ".m4a":
		return "audio/mp4"
	case ".mp3":
		return "audio/mpeg"
	case ".pdf":
		return "application/pdf"
	default:
		return "application/octet-stream"
	}
}

// ReceivedBlob describes a verified, locally persisted attachment handed to ParcelHandler.
type ReceivedBlob struct {
	Descriptor BlobDescriptor
	SafePath   string // Verified local file path under TempDir/<msg_id>/part_<part_id>.verified (mode 0600)
	SafeName   string // Sanitized filename stripped of traversal/control/reserved device names
}

// SaveToDir safely moves/copies the verified attachment into outDir with mode 0600,
// refusing symlinks and never overwriting existing files (auto-suffixing _1, _2 on collision).
func (b ReceivedBlob) SaveToDir(outDir string) (string, error) {
	if outDir == "" {
		return "", NewError(ErrCodeStorageIO, false, 0, "empty output directory", nil)
	}
	if fi, err := os.Lstat(outDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return "", NewError(ErrCodeStorageIO, false, 0, "output directory must be a real directory, not a symlink or file", nil)
		}
	} else if !os.IsNotExist(err) {
		return "", WrapError(ErrCodeStorageIO, false, 0, "lstat output directory", err)
	} else if err := os.MkdirAll(outDir, 0o700); err != nil {
		return "", WrapError(ErrCodeStorageIO, false, 0, "create output directory", err)
	}

	baseName := b.SafeName
	if baseName == "" {
		baseName = b.Descriptor.Name
	}
	safeName := SanitizeFilename(baseName)
	ext := filepath.Ext(safeName)
	stem := strings.TrimSuffix(safeName, ext)

	in, err := os.Open(b.SafePath)
	if err != nil {
		return "", WrapError(ErrCodeStorageIO, false, 0, "open verified blob", err)
	}
	defer in.Close()

	var dst string
	var out *os.File
	for i := 0; i < 10000; i++ {
		candName := safeName
		if i > 0 {
			candName = fmt.Sprintf("%s_%d%s", stem, i, ext)
		}
		cand := filepath.Join(outDir, candName)
		f, openErr := os.OpenFile(cand, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if openErr == nil {
			dst = cand
			out = f
			break
		}
		if !os.IsExist(openErr) {
			return "", WrapError(ErrCodeStorageIO, false, 0, "create destination file", openErr)
		}
	}
	if out == nil {
		return "", NewError(ErrCodeStorageIO, false, 0, "too many filename collisions in output directory", nil)
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return "", WrapError(ErrCodeStorageIO, false, 0, "write destination file", err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return "", WrapError(ErrCodeStorageIO, false, 0, "sync destination file", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return "", WrapError(ErrCodeStorageIO, false, 0, "close destination file", err)
	}
	_ = in.Close()
	_ = os.Remove(b.SafePath)
	return dst, nil
}

// ReceivedParcel is delivered to the application only after full AEAD + SHA-256 verification.
type ReceivedParcel struct {
	ItemID   string // Non-empty for Mode B spool pulls
	Manifest Manifest
	Blobs    []ReceivedBlob
}

// DeviceCardPayload is exchanged inside PairBindPayload during Flow 1 pairing.
type DeviceCardPayload struct {
	DeviceID string `json:"device_id"`
	SignPK   string `json:"sign_pk"`
	KEMPK    string `json:"kem_pk"`
	IssuedAt int64  `json:"issued_at"`
	CardSig  string `json:"card_sig"`
	Label    string `json:"label"`
	Platform string `json:"platform,omitempty"`
}

// MailboxBindPayload carries per-peer mailbox routing + deposit token (nil/omitted when --spool=off).
type MailboxBindPayload struct {
	RelayOrigin  string `json:"relay_origin"`
	MailboxID    string `json:"mailbox_id"`
	DepositToken string `json:"deposit_token"`
}

// PairBindPayload is encrypted inside the room during Flow 1 purpose="pair".
type PairBindPayload struct {
	DeviceCard DeviceCardPayload   `json:"device_card"`
	Mailbox    *MailboxBindPayload `json:"mailbox,omitempty"`
}

// PartLayout declares encrypted size and transport chunk count for one part_id.
type PartLayout struct {
	PartID     uint32 `json:"part_id"`
	TotalBytes int64  `json:"total_bytes"`
	ChunkCount int    `json:"chunk_count"`
}

// PipeStartPayload is the encrypted control command sent by Sender on Flow 1 oneshot Mode A.
type PipeStartPayload struct {
	Op             string       `json:"op"` // "pipe_start"
	MsgID          string       `json:"msg_id"`
	BlocksPerChunk int          `json:"blocks_per_chunk"`
	Parts          []PartLayout `json:"parts"`
}

// PipeAckPayload is the completion acknowledgement command sent by Receiver on Mode A.
// AckMAC is populated for Flow 2 Mode A direct transfers (CRYPTO_AND_AUTH.md §5.4).
type PipeAckPayload struct {
	Op     string `json:"op"` // "pipe_ack"
	MsgID  string `json:"msg_id"`
	AckMAC string `json:"ack_mac,omitempty"`
}

// DirectRoomInitPayload is M1 (initial_msg_b64) for Flow 2 Mode A direct streaming (mode=0, purpose="direct").
type DirectRoomInitPayload struct {
	ProtoV         int          `json:"proto_v"`
	Mode           int          `json:"mode"`    // 0
	Purpose        string       `json:"purpose"` // "direct"
	SealedHeader   string       `json:"sealed_header"`
	BlocksPerChunk int          `json:"blocks_per_chunk"`
	Parts          []PartLayout `json:"parts"`
}

// TransferEvent represents unified cross-language progress reporting (ENVELOPE_AND_SDK.md §4.3).
type TransferEvent struct {
	Type           string `json:"type"`  // "event"
	Event          string `json:"event"` // "transfer_progress"
	Stage          string `json:"stage"`
	Direction      string `json:"direction"` // "send" | "recv"
	Mode           string `json:"mode"`      // "pipe" | "spool"
	MsgID          string `json:"msg_id,omitempty"`
	PartID         uint32 `json:"part_id"`
	PartsTotal     int    `json:"parts_total"`
	BytesDone      int64  `json:"bytes_done"`
	BytesTotal     int64  `json:"bytes_total"`
	PartBytesDone  int64  `json:"part_bytes_done"`
	PartBytesTotal int64  `json:"part_bytes_total"`
	SpeedBPS       int64  `json:"speed_bps,omitempty"`
	Resumed        bool   `json:"resumed"`
	TS             int64  `json:"ts"`
}

// RelayCertExpiringEvent warns callers when a 730-day self-signed relay cert has <30 days left.
type RelayCertExpiringEvent struct {
	Type          string `json:"type"`  // "event"
	Event         string `json:"event"` // "relay_cert_expiring_soon"
	RelayID       string `json:"relay_id"`
	ExpiresAt     int64  `json:"expires_at"`
	DaysRemaining int    `json:"days_remaining"`
	Severity      string `json:"severity"` // "warning" | "urgent"
}

// Validate checks every schema invariant on Manifest per ENVELOPE_AND_SDK.md §2.2.
func (m *Manifest) Validate() error {
	if m == nil {
		return NewError(ErrCodeManifestInvalid, false, 0, "manifest is nil", nil)
	}
	if m.EnvelopeVersion > EnvelopeVersion {
		return NewError(ErrCodeUnsupportedVersion, false, 0, fmt.Sprintf("unsupported envelope_version %d (supported: %d)", m.EnvelopeVersion, EnvelopeVersion), map[string]any{
			"envelope_version":  m.EnvelopeVersion,
			"supported_version": EnvelopeVersion,
		})
	}
	if m.EnvelopeVersion != EnvelopeVersion {
		return NewError(ErrCodeManifestInvalid, false, 0, fmt.Sprintf("unsupported envelope_version %d", m.EnvelopeVersion), nil)
	}
	if !reHex32.MatchString(m.MsgID) {
		return NewError(ErrCodeManifestInvalid, false, 0, "msg_id must be 32 lowercase hex chars", nil)
	}
	if !reAppOrSchema.MatchString(m.AppID) {
		return NewError(ErrCodeManifestInvalid, false, 0, fmt.Sprintf("invalid app_id %q", m.AppID), nil)
	}
	if !reAppOrSchema.MatchString(m.Schema) {
		return NewError(ErrCodeManifestInvalid, false, 0, fmt.Sprintf("invalid schema %q", m.Schema), nil)
	}
	if m.CreatedAt < 0 {
		return NewError(ErrCodeManifestInvalid, false, 0, "created_at must be non-negative", nil)
	}
	if !reHex32.MatchString(m.Sender.DeviceID) {
		return NewError(ErrCodeManifestInvalid, false, 0, "sender.device_id must be 32 lowercase hex chars", nil)
	}
	labelRunes := len([]rune(m.Sender.Label))
	if labelRunes < 1 || labelRunes > 64 {
		return NewError(ErrCodeManifestInvalid, false, 0, "sender.label must be 1..64 UTF-8 chars", nil)
	}
	if m.InlinePayload != nil {
		b, err := json.Marshal(m.InlinePayload)
		if err != nil {
			return WrapError(ErrCodeManifestInvalid, false, 0, "marshal inline_payload", err)
		}
		if len(b) > MaxInlinePayloadBytes {
			return NewError(ErrCodeManifestInvalid, false, 0, fmt.Sprintf("inline_payload exceeds %d bytes", MaxInlinePayloadBytes), nil)
		}
	}
	if m.Blobs == nil {
		return NewError(ErrCodeManifestInvalid, false, 0, "blobs must be an array (use [] when empty)", nil)
	}
	if len(m.Blobs) > MaxBlobs {
		return NewError(ErrCodeManifestInvalid, false, 0, fmt.Sprintf("blobs count %d exceeds max %d", len(m.Blobs), MaxBlobs), nil)
	}
	seenParts := make(map[uint32]struct{}, len(m.Blobs))
	for i, blob := range m.Blobs {
		if blob.PartID < 1 || blob.PartID > MaxBlobs {
			return NewError(ErrCodeManifestInvalid, false, 0, fmt.Sprintf("blobs[%d].part_id %d out of range 1..%d", i, blob.PartID, MaxBlobs), nil)
		}
		if _, dup := seenParts[blob.PartID]; dup {
			return NewError(ErrCodeManifestInvalid, false, 0, fmt.Sprintf("duplicate blobs part_id %d", blob.PartID), nil)
		}
		seenParts[blob.PartID] = struct{}{}
		if !reRole.MatchString(blob.Role) {
			return NewError(ErrCodeManifestInvalid, false, 0, fmt.Sprintf("blobs[%d].role invalid: %q", i, blob.Role), nil)
		}
		nameRunes := len([]rune(blob.Name))
		if nameRunes < 1 || nameRunes > 255 {
			return NewError(ErrCodeManifestInvalid, false, 0, fmt.Sprintf("blobs[%d].name must be 1..255 chars", i), nil)
		}
		if len(blob.MIME) < 1 || len(blob.MIME) > 128 {
			return NewError(ErrCodeManifestInvalid, false, 0, fmt.Sprintf("blobs[%d].mime must be 1..128 chars", i), nil)
		}
		if blob.Size < 0 || blob.Size > MaxSafeIntJS {
			return NewError(ErrCodeManifestInvalid, false, 0, fmt.Sprintf("blobs[%d].size out of range", i), nil)
		}
		if !reHex64.MatchString(blob.SHA256) {
			return NewError(ErrCodeManifestInvalid, false, 0, fmt.Sprintf("blobs[%d].sha256 must be 64 lowercase hex", i), nil)
		}
		rawKey, err := base64.RawURLEncoding.DecodeString(blob.Key)
		if err != nil || len(rawKey) != 32 {
			return NewError(ErrCodeManifestInvalid, false, 0, fmt.Sprintf("blobs[%d].key must be 43-char b64u (32B)", i), nil)
		}
		if blob.Encoding != "" && blob.Encoding != "identity" && blob.Encoding != "gzip" && blob.Encoding != "zstd" {
			return NewError(ErrCodeManifestInvalid, false, 0, fmt.Sprintf("blobs[%d].encoding invalid: %q", i, blob.Encoding), nil)
		}
		if blob.Meta != nil {
			mb, err := json.Marshal(blob.Meta)
			if err != nil || len(mb) > MaxBlobMetaBytes {
				return NewError(ErrCodeManifestInvalid, false, 0, fmt.Sprintf("blobs[%d].meta exceeds %d bytes", i, MaxBlobMetaBytes), nil)
			}
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return WrapError(ErrCodeManifestInvalid, false, 0, "marshal manifest", err)
	}
	if len(raw) > MaxManifestBytes {
		return NewError(ErrCodeManifestInvalid, false, 0, fmt.Sprintf("manifest exceeds %d bytes", MaxManifestBytes), nil)
	}
	return nil
}

// MarshalManifest validates and encodes Manifest to UTF-8 JSON bytes.
func MarshalManifest(m *Manifest) ([]byte, error) {
	if m != nil && m.Blobs == nil {
		m.Blobs = []BlobDescriptor{}
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, WrapError(ErrCodeManifestInvalid, false, 0, "marshal manifest", err)
	}
	if len(raw) == 0 || len(raw) > MaxManifestBytes {
		return nil, NewError(ErrCodeManifestInvalid, false, 0, "manifest size out of bounds", nil)
	}
	return raw, nil
}

// ParseManifest unmarshals and strictly validates Manifest UTF-8 JSON bytes.
func ParseManifest(raw []byte) (*Manifest, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytes {
		return nil, NewError(ErrCodeManifestInvalid, false, 0, "manifest byte length out of bounds", nil)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, WrapError(ErrCodeManifestInvalid, false, 0, "parse manifest json", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func isBidiOrControlRune(r rune) bool {
	if r == 0 || unicode.IsControl(r) {
		return true
	}
	// Unicode Bidi override/isolate runes (defeats Right-to-Left Override extension spoofing).
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C
}

func isWindowsReservedDeviceStem(stem string) bool {
	switch strings.ToUpper(strings.TrimSpace(stem)) {
	case "CON", "PRN", "AUX", "NUL",
		"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM\u00B9", "COM\u00B2", "COM\u00B3",
		"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT\u00B9", "LPT\u00B2", "LPT\u00B3":
		return true
	default:
		return false
	}
}

func truncateUTF8Safe(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	ext := filepath.Ext(s)
	if len(ext) > 16 || len(ext) >= maxBytes {
		ext = ""
	}
	stem := strings.TrimSuffix(s, ext)
	budget := maxBytes - len(ext)
	var b strings.Builder
	for _, r := range stem {
		rl := utf8.RuneLen(r)
		if rl < 0 {
			continue
		}
		if b.Len()+rl > budget {
			break
		}
		b.WriteRune(r)
	}
	trimmedStem := strings.TrimRightFunc(b.String(), func(r rune) bool {
		return r == '.' || unicode.IsSpace(r)
	})
	if trimmedStem == "" {
		return "blob.bin"
	}
	return trimmedStem + ext
}

// SanitizeFilename strips directory separators, traversal segments, NUL/control/Bidi runes,
// leading/trailing dots & spaces, UTF-8 byte-split hazards, and Windows reserved device names.
func SanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
		name = name[idx+1:]
	}
	var b strings.Builder
	for _, r := range name {
		if r == utf8.RuneError {
			continue
		}
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C {
			continue
		}
		if isBidiOrControlRune(r) || r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimFunc(b.String(), func(r rune) bool {
		return r == '.' || unicode.IsSpace(r)
	})
	if out == "" || strings.Trim(out, "._") == "" {
		return "blob.bin"
	}
	out = truncateUTF8Safe(out, 199)
	out = strings.TrimFunc(out, func(r rune) bool {
		return r == '.' || unicode.IsSpace(r)
	})
	if out == "" || out == "." || out == ".." {
		return "blob.bin"
	}
	stem := out
	if dot := strings.IndexByte(out, '.'); dot >= 0 {
		stem = out[:dot]
	}
	if isWindowsReservedDeviceStem(stem) {
		out = "_" + out
	}
	return out
}
