package relay

import (
	"container/list"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	HeaderSyncTS           = "X-Sync-TS"
	HeaderSyncNonce        = "X-Sync-Nonce"
	HeaderSyncSig          = "X-Sync-Sig"
	HeaderSyncClient       = "X-Sync-Client"
	HeaderSyncRoomToken    = "X-Sync-Room-Token"
	HeaderSyncMailboxSig   = "X-Sync-Mailbox-Sig"
	HeaderSyncDepositToken = "X-Sync-Deposit-Token"
	HeaderSyncUploadToken  = "X-Sync-Upload-Token"

	EmptyBodySHA256Binding = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

func DeriveRelayHMACKey(accessKey string) [32]byte {
	h := sha256.New()
	h.Write([]byte("synctool-v1/access-key:"))
	h.Write([]byte(accessKey))
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func HashDepositToken(raw string) string {
	h := sha256.New()
	h.Write([]byte("synctool-v1/deposit-token:"))
	h.Write([]byte(raw))
	return hex.EncodeToString(h.Sum(nil))
}

func HashUploadToken(raw string) string {
	h := sha256.New()
	h.Write([]byte("synctool-v1/upload-token:"))
	h.Write([]byte(raw))
	return hex.EncodeToString(h.Sum(nil))
}

func DeriveMailboxID(authPK []byte) string {
	h := sha256.New()
	h.Write([]byte("synctool-v1/mailbox-id:"))
	h.Write(authPK)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

func ControlBodyBinding(rawBody []byte) string {
	if len(rawBody) == 0 {
		return EmptyBodySHA256Binding
	}
	sum := sha256.Sum256(rawBody)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func StreamBodyBinding(contentLength int64) string {
	return "stream:" + strconv.FormatInt(contentLength, 10)
}

func ExtraTokenBinding(depositToken, uploadToken string) string {
	if depositToken != "" {
		return "deposit:" + HashDepositToken(depositToken)
	}
	if uploadToken != "" {
		return "upload:" + HashUploadToken(uploadToken)
	}
	return ""
}

// CanonicalPathAndQuery returns the exact PATH_AND_RAW_QUERY per CRYPTO_AND_AUTH.md §7.2:
// no trailing "?" when query is empty (equivalent to r.URL.RequestURI() / JS pathname+search).
func CanonicalPathAndQuery(r *http.Request) string {
	p := r.URL.EscapedPath()
	if p == "" {
		p = "/"
	}
	if r.URL.RawQuery != "" {
		return p + "?" + r.URL.RawQuery
	}
	return p
}

func ComputeRelaySig(hmacKey [32]byte, method, pathAndQuery, ts, nonce, bodyBinding, extraBinding string) string {
	mac := hmac.New(sha256.New, hmacKey[:])
	mac.Write([]byte(method))
	mac.Write([]byte("\n"))
	mac.Write([]byte(pathAndQuery))
	mac.Write([]byte("\n"))
	mac.Write([]byte(ts))
	mac.Write([]byte("\n"))
	mac.Write([]byte(nonce))
	mac.Write([]byte("\n"))
	mac.Write([]byte(bodyBinding))
	mac.Write([]byte("\n"))
	mac.Write([]byte(extraBinding))
	return hex.EncodeToString(mac.Sum(nil))
}

func VerifyRelaySig(hmacKey [32]byte, gotSig, method, pathAndQuery, ts, nonce, bodyBinding, extraBinding string) bool {
	if !isLowerHexLen(gotSig, 64) {
		return false
	}
	expected := ComputeRelaySig(hmacKey, method, pathAndQuery, ts, nonce, bodyBinding, extraBinding)
	return hmac.Equal([]byte(expected), []byte(gotSig))
}

func VerifyMailboxSig(authPK ed25519.PublicKey, sigB64u, method, pathAndQuery, mailboxID, ts, nonce, bodyBinding string) bool {
	if len(authPK) != ed25519.PublicKeySize || sigB64u == "" {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64u)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	var b strings.Builder
	b.Grow(len(method) + len(pathAndQuery) + len(mailboxID) + len(ts) + len(nonce) + len(bodyBinding) + 32)
	b.WriteString("synctool-v1/mailbox-auth\n")
	b.WriteString(method)
	b.WriteByte('\n')
	b.WriteString(pathAndQuery)
	b.WriteByte('\n')
	b.WriteString(mailboxID)
	b.WriteByte('\n')
	b.WriteString(ts)
	b.WriteByte('\n')
	b.WriteString(nonce)
	b.WriteByte('\n')
	b.WriteString(bodyBinding)
	return ed25519.Verify(authPK, []byte(b.String()), sig)
}

func ConstantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func isLowerHexLen(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isValidClientHeader(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func isValidAuthHeaderToken(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > MaxAuthHeaderBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func isValidRoomID(s string) bool {
	if len(s) != 8 {
		return false
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i := 0; i < 8; i++ {
		if strings.IndexByte(alphabet, s[i]) < 0 {
			return false
		}
	}
	return true
}

func isValidTokenID(s string) bool {
	if len(s) < 8 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

func isValidItemID(s string) bool {
	return strings.HasPrefix(s, "itm_") && isLowerHexLen(s[4:], 32)
}

type NonceResult int

const (
	NonceAccepted NonceResult = iota
	NonceReplay
	NonceCacheFull
)

func decodeLowerHex16(s string) ([16]byte, bool) {
	var out [16]byte
	if len(s) != 32 {
		return out, false
	}
	for i := 0; i < 16; i++ {
		hi, ok1 := fromLowerHexNibble(s[2*i])
		lo, ok2 := fromLowerHexNibble(s[2*i+1])
		if !ok1 || !ok2 {
			return out, false
		}
		out[i] = (hi << 4) | lo
	}
	return out, true
}

func fromLowerHexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	default:
		return 0, false
	}
}

// NonceCache enforces bounded O(1) replay detection using compact [16]byte keys and 125s TTL.
// Never silently evicts unexpired (live) nonces; returns NonceCacheFull when saturated.
type NonceCache struct {
	mu         sync.Mutex
	maxEntries int
	ttl        time.Duration
	order      *list.List
	items      map[[16]byte]*list.Element
}

type nonceEntry struct {
	nonce     [16]byte
	expiresAt time.Time
}

func NewNonceCache(maxEntries int, ttl time.Duration) *NonceCache {
	if maxEntries <= 0 {
		maxEntries = NonceCacheMaxEntries
	}
	if ttl <= 0 {
		ttl = NonceCacheTTL
	}
	return &NonceCache{
		maxEntries: maxEntries,
		ttl:        ttl,
		order:      list.New(),
		items:      make(map[[16]byte]*list.Element, 256),
	}
}

// CheckAndAddStatus checks and records a 32-char lowercase hex nonce.
// Returns NonceAccepted if fresh, NonceReplay if duplicate/malformed, or NonceCacheFull if all slots hold live nonces.
func (nc *NonceCache) CheckAndAddStatus(nonce string, now time.Time) NonceResult {
	key, ok := decodeLowerHex16(nonce)
	if !ok {
		return NonceReplay
	}

	nc.mu.Lock()
	defer nc.mu.Unlock()

	// Evict expired entries from the front (oldest first).
	for e := nc.order.Front(); e != nil; {
		next := e.Next()
		ent := e.Value.(*nonceEntry)
		if !now.Before(ent.expiresAt) {
			nc.order.Remove(e)
			delete(nc.items, ent.nonce)
		} else {
			break
		}
		e = next
	}

	// Always check duplicate replay BEFORE checking capacity!
	if existing, exists := nc.items[key]; exists {
		ent := existing.Value.(*nonceEntry)
		if now.Before(ent.expiresAt) {
			return NonceReplay
		}
		nc.order.Remove(existing)
		delete(nc.items, key)
	}

	// Never evict an unexpired (live) nonce when full!
	for nc.order.Len() >= nc.maxEntries {
		front := nc.order.Front()
		if front == nil {
			break
		}
		ent := front.Value.(*nonceEntry)
		if now.Before(ent.expiresAt) {
			return NonceCacheFull
		}
		nc.order.Remove(front)
		delete(nc.items, ent.nonce)
	}

	el := nc.order.PushBack(&nonceEntry{
		nonce:     key,
		expiresAt: now.Add(nc.ttl),
	})
	nc.items[key] = el
	return NonceAccepted
}

// CheckAndAdd returns true if nonce is fresh and was recorded, false otherwise.
func (nc *NonceCache) CheckAndAdd(nonce string, now time.Time) bool {
	return nc.CheckAndAddStatus(nonce, now) == NonceAccepted
}

func (nc *NonceCache) Len() int {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	return len(nc.items)
}
