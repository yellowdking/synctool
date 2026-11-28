package crypto

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
)

const (
	prefixAccessKey     = "synctool-v1/access-key:"
	prefixDepositToken  = "synctool-v1/deposit-token:"
	prefixUploadToken   = "synctool-v1/upload-token:"
	prefixMailboxAuthIn = "synctool-v1/mailbox-auth\n"

	// HeaderRelayTS is the Unix seconds timestamp header.
	HeaderRelayTS = "X-Sync-TS"
	// HeaderRelayNonce is the 32-char lowercase hex replay nonce header.
	HeaderRelayNonce = "X-Sync-Nonce"
	// HeaderRelaySig is the 64-char lowercase hex HMAC-SHA256 signature header.
	HeaderRelaySig = "X-Sync-Sig"
	// HeaderRoomToken is the room/pipe token header.
	HeaderRoomToken = "X-Sync-Room-Token"
	// HeaderMailboxSig is the 86-char unpadded base64url Ed25519 mailbox owner signature header.
	HeaderMailboxSig = "X-Sync-Mailbox-Sig"
	// HeaderDepositToken is the per-peer deposit token header.
	HeaderDepositToken = "X-Sync-Deposit-Token"
	// HeaderUploadToken is the relay-issued spool upload token header.
	HeaderUploadToken = "X-Sync-Upload-Token"
	// HeaderClientAgent is the optional diagnostic user-agent header.
	HeaderClientAgent = "X-Sync-Client"
)

// DeriveRelayHMACKey derives the 32-byte HMAC key from any relay access_key string:
// SHA256("synctool-v1/access-key:" || utf8(accessKey)).
func DeriveRelayHMACKey(accessKey string) [32]byte {
	h := sha256.New()
	h.Write([]byte(prefixAccessKey))
	h.Write([]byte(accessKey))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// HashDepositToken computes hex(SHA256("synctool-v1/deposit-token:" || utf8(rawToken))).
func HashDepositToken(rawToken string) string {
	h := sha256.New()
	h.Write([]byte(prefixDepositToken))
	h.Write([]byte(rawToken))
	return hex.EncodeToString(h.Sum(nil))
}

// HashUploadToken computes hex(SHA256("synctool-v1/upload-token:" || utf8(rawToken))).
func HashUploadToken(rawToken string) string {
	h := sha256.New()
	h.Write([]byte(prefixUploadToken))
	h.Write([]byte(rawToken))
	return hex.EncodeToString(h.Sum(nil))
}

// BodyBindingControl returns "sha256:<64-hex>" for control-plane JSON or empty bodies.
func BodyBindingControl(rawBody []byte) string {
	sum := sha256.Sum256(rawBody)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BodyBindingStream returns "stream:<decimal_content_length>" for data-plane chunk PUT uploads.
func BodyBindingStream(contentLength int64) string {
	return "stream:" + strconv.FormatInt(contentLength, 10)
}

// ExtraTokenBinding computes the 6th line of canonical_req per CRYPTO_AND_AUTH.md §7.2:
// "deposit:<hash>", "upload:<hash>", or "" if neither header is present.
func ExtraTokenBinding(depositToken, uploadToken string) string {
	if depositToken != "" {
		return "deposit:" + HashDepositToken(depositToken)
	}
	if uploadToken != "" {
		return "upload:" + HashUploadToken(uploadToken)
	}
	return ""
}

// BuildCanonicalRequest builds the exact 6-line "\n"-delimited canonical string for X-Sync-Sig.
// pathAndRawQuery MUST NOT include a trailing "?" when there is no query string
// (equivalent to Go r.URL.RequestURI() and JS url.pathname + url.search).
func BuildCanonicalRequest(method, pathAndRawQuery, ts, nonce, bodyBinding, extraTokenBinding string) string {
	var b strings.Builder
	b.Grow(len(method) + len(pathAndRawQuery) + len(ts) + len(nonce) + len(bodyBinding) + len(extraTokenBinding) + 5)
	b.WriteString(strings.ToUpper(method))
	b.WriteByte('\n')
	b.WriteString(pathAndRawQuery)
	b.WriteByte('\n')
	b.WriteString(ts)
	b.WriteByte('\n')
	b.WriteString(nonce)
	b.WriteByte('\n')
	b.WriteString(bodyBinding)
	b.WriteByte('\n')
	b.WriteString(extraTokenBinding)
	return b.String()
}

// SignRelayRequest computes the 64-char lowercase hex X-Sync-Sig value.
func SignRelayRequest(accessKey, method, pathAndRawQuery, ts, nonce, bodyBinding, extraTokenBinding string) string {
	hmacKey := DeriveRelayHMACKey(accessKey)
	defer clear(hmacKey[:])
	canon := BuildCanonicalRequest(method, pathAndRawQuery, ts, nonce, bodyBinding, extraTokenBinding)
	mac := hmac.New(sha256.New, hmacKey[:])
	mac.Write([]byte(canon))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyRelayRequest verifies X-Sync-Sig in constant time.
// Per CRYPTO_AND_AUTH.md §2.3 & §7.1, sigHex MUST be exact 64-char lowercase hex.
func VerifyRelayRequest(accessKey, method, pathAndRawQuery, ts, nonce, bodyBinding, extraTokenBinding, sigHex string) bool {
	if !isLowerHex(sigHex, 64) {
		return false
	}
	got, err := hex.DecodeString(sigHex)
	if err != nil || len(got) != 32 {
		return false
	}
	hmacKey := DeriveRelayHMACKey(accessKey)
	defer clear(hmacKey[:])
	canon := BuildCanonicalRequest(method, pathAndRawQuery, ts, nonce, bodyBinding, extraTokenBinding)
	mac := hmac.New(sha256.New, hmacKey[:])
	mac.Write([]byte(canon))
	return hmac.Equal(mac.Sum(nil), got)
}

func isLowerHex(s string, wantLen int) bool {
	if len(s) != wantLen {
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

// BuildMailboxSigInput constructs the exact 7-line "\n"-delimited Ed25519 signing input
// for X-Sync-Mailbox-Sig per CRYPTO_AND_AUTH.md §7.4.
func BuildMailboxSigInput(method, pathAndRawQuery, mailboxID, ts, nonce, bodyBinding string) string {
	var b strings.Builder
	b.Grow(len(prefixMailboxAuthIn) + len(method) + len(pathAndRawQuery) + len(mailboxID) + len(ts) + len(nonce) + len(bodyBinding) + 5)
	b.WriteString(prefixMailboxAuthIn)
	b.WriteString(strings.ToUpper(method))
	b.WriteByte('\n')
	b.WriteString(pathAndRawQuery)
	b.WriteByte('\n')
	b.WriteString(mailboxID)
	b.WriteByte('\n')
	b.WriteString(ts)
	b.WriteByte('\n')
	b.WriteString(nonce)
	b.WriteByte('\n')
	b.WriteString(bodyBinding)
	return b.String()
}

// SignMailboxRequest computes the 86-char unpadded base64url Ed25519 X-Sync-Mailbox-Sig.
func SignMailboxRequest(mailboxAuthSK ed25519.PrivateKey, method, pathAndRawQuery, mailboxID, ts, nonce, bodyBinding string) string {
	input := BuildMailboxSigInput(method, pathAndRawQuery, mailboxID, ts, nonce, bodyBinding)
	sig := ed25519.Sign(mailboxAuthSK, []byte(input))
	return base64.RawURLEncoding.EncodeToString(sig)
}

// VerifyMailboxRequest verifies X-Sync-Mailbox-Sig against mailboxAuthPK.
func VerifyMailboxRequest(mailboxAuthPK ed25519.PublicKey, method, pathAndRawQuery, mailboxID, ts, nonce, bodyBinding, sigB64U string) bool {
	if len(mailboxAuthPK) != ed25519.PublicKeySize || IsSmallOrderOrNonCanonicalEd25519PK(mailboxAuthPK) {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64U)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	input := BuildMailboxSigInput(method, pathAndRawQuery, mailboxID, ts, nonce, bodyBinding)
	return ed25519.Verify(mailboxAuthPK, []byte(input), sig)
}

// GenerateNonceHex returns 16 CSPRNG bytes formatted as 32 lowercase hex characters.
func GenerateNonceHex() (string, error) {
	b, err := GenerateRandomBytes(16)
	if err != nil {
		return "", err
	}
	defer clear(b)
	return hex.EncodeToString(b), nil
}

// GenerateTokenB64U returns 32 CSPRNG bytes encoded as 43-char unpadded base64url.
func GenerateTokenB64U() (string, error) {
	b, err := GenerateRandomBytes(32)
	if err != nil {
		return "", err
	}
	defer clear(b)
	return base64.RawURLEncoding.EncodeToString(b), nil
}
