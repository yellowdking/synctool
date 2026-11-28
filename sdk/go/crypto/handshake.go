package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	ProtoVersion = 1

	ModeDirect    = 0
	ModeQROOB     = 1
	ModeCommitSAS = 2

	HandshakeModeDirect = ModeDirect
	HandshakeModeQROOB  = ModeQROOB
	HandshakeModeSAS    = ModeCommitSAS

	PurposeDirect  = "direct"
	PurposeOneshot = "oneshot"
	PurposePair    = "pair"

	PurposeCodeOneshot uint8 = 0x01
	PurposeCodePair    uint8 = 0x02

	OOBSecretSize = 16
	HSNonceSize   = 32

	prefixHSQR          = "synctool-v1/hs-qr"
	prefixCommit        = "synctool-v1/commit"
	prefixHSSAS         = "synctool-v1/hs-sas"
	infoSessionKey      = "synctool-v1/session-key"
	infoConfirmA        = "synctool-v1/confirm-a"
	infoConfirmB        = "synctool-v1/confirm-b"
	infoSAS             = "synctool-v1/sas"
	infoOneshotPart0Key = "synctool-v1/oneshot-part0-key"
	infoOneshotPart0NP  = "synctool-v1/oneshot-part0-np"
	infoPipeCtrlKey     = "synctool-v1/pipe-ctrl-key"
	infoPipeCtrlNP      = "synctool-v1/pipe-ctrl-np"
	prefixPipeCtrlAAD   = "synctool-v1/pipe-ctrl"
	infoPairNonceA      = "synctool-v1/pair-nonce-a"
	infoPairNonceB      = "synctool-v1/pair-nonce-b"
	prefixPairBindA     = "synctool-v1/pair-bind/a"
	prefixPairBindB     = "synctool-v1/pair-bind/b"
)

var (
	ErrInvalidPurpose   = errors.New("invalid handshake purpose")
	ErrCommitMismatch   = errors.New("handshake commit_a verification failed")
	ErrMACMismatch      = errors.New("handshake key confirmation mac mismatch")
	ErrSASMismatch      = errors.New("handshake sas mismatch")
	ErrDecryptFailed    = errors.New("aead decryption failed")
	ErrInvalidCtrlSeq   = errors.New("invalid pipe control sequence number")
	ErrInvalidOOBSecret = errors.New("oob_secret must be 16 bytes")
)

// PurposeCode maps "oneshot"/"pair" to its 1-byte wire transcript code.
func PurposeCode(purpose string) (uint8, error) {
	switch purpose {
	case PurposeOneshot:
		return PurposeCodeOneshot, nil
	case PurposePair:
		return PurposeCodePair, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrInvalidPurpose, purpose)
	}
}

// HandshakeResult contains all keys and authenticators derived from a Flow 1 handshake.
type HandshakeResult struct {
	TH          [32]byte
	PRK         [32]byte
	SessionKey  [32]byte
	ConfirmKeyA [32]byte
	ConfirmKeyB [32]byte
	MacA        [32]byte
	MacB        [32]byte
	SASBytes    [4]byte // populated for mode=2 only
	SASInt      uint32  // populated for mode=2 only (0..999999)
	SASStr      string  // populated for mode=2 only ("000000".."999999")
}

// Zero wipes secret fields in HandshakeResult.
func (r *HandshakeResult) Zero() {
	if r == nil {
		return
	}
	clear(r.PRK[:])
	clear(r.SessionKey[:])
	clear(r.ConfirmKeyA[:])
	clear(r.ConfirmKeyB[:])
}

// GenerateEphemeralX25519 creates a fresh ephemeral X25519 keypair and wipes the raw seed buffer.
func GenerateEphemeralX25519() (*ecdh.PrivateKey, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	defer clear(raw[:])
	return ecdh.X25519().NewPrivateKey(raw[:])
}

// GenerateRandomBytes fills a newly allocated slice of n CSPRNG bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// BuildQRTranscript constructs the exact 154-byte transcript_1 for mode=1 (qr_oob_x25519).
func BuildQRTranscript(purpose string, roomID string, eAPub, nA, eBPub, nB []byte) ([]byte, error) {
	pCode, err := PurposeCode(purpose)
	if err != nil {
		return nil, err
	}
	if !IsCanonicalRoomID(roomID) {
		return nil, ErrInvalidRoomID
	}
	if len(eAPub) != 32 || len(nA) != HSNonceSize || len(eBPub) != 32 || len(nB) != HSNonceSize {
		return nil, ErrInvalidKeyLength
	}
	buf := make([]byte, 0, len(prefixHSQR)+1+RoomIDLength+128)
	buf = append(buf, prefixHSQR...)
	buf = append(buf, pCode)
	buf = append(buf, roomID...)
	buf = append(buf, eAPub...)
	buf = append(buf, nA...)
	buf = append(buf, eBPub...)
	buf = append(buf, nB...)
	return buf, nil
}

// DeriveQROOBSession derives all mode=1 (qr_oob_x25519) handshake keys and MACs.
// Pass local ephemeral private key and remote ephemeral public key alongside both public keys
// (eAPub = initiator, eBPub = responder).
func DeriveQROOBSession(
	purpose string,
	roomID string,
	localPriv *ecdh.PrivateKey,
	remotePubBytes []byte,
	eAPub, nA, eBPub, nB []byte,
	oobSecret []byte,
) (*HandshakeResult, error) {
	if len(oobSecret) != OOBSecretSize {
		return nil, ErrInvalidOOBSecret
	}
	shared, err := X25519SharedSecret(localPriv, remotePubBytes)
	if err != nil {
		return nil, err
	}
	defer clear(shared)

	transcript, err := BuildQRTranscript(purpose, roomID, eAPub, nA, eBPub, nB)
	if err != nil {
		return nil, err
	}
	th := sha256.Sum256(transcript)

	ikm := make([]byte, 48)
	copy(ikm[:32], shared)
	copy(ikm[32:], oobSecret)
	defer clear(ikm)

	prk, err := hkdfExtract(th[:], ikm)
	if err != nil {
		return nil, err
	}
	defer clear(prk)

	res := &HandshakeResult{TH: th}
	copy(res.PRK[:], prk)
	if err := fillSessionAndConfirm(res, prk, th[:]); err != nil {
		res.Zero()
		return nil, err
	}
	return res, nil
}

// ComputeCommitA computes the exact 32-byte commitment for mode=2 (commit_sas_x25519):
// SHA256("synctool-v1/commit"(18B) || purpose_code(1B) || room_id(8B) || E_a(32B) || n_a(32B)).
func ComputeCommitA(purpose string, roomID string, eAPub, nA []byte) ([32]byte, error) {
	var zero [32]byte
	pCode, err := PurposeCode(purpose)
	if err != nil {
		return zero, err
	}
	if !IsCanonicalRoomID(roomID) {
		return zero, ErrInvalidRoomID
	}
	if len(eAPub) != 32 || len(nA) != HSNonceSize {
		return zero, ErrInvalidKeyLength
	}
	buf := make([]byte, 0, len(prefixCommit)+1+RoomIDLength+64)
	buf = append(buf, prefixCommit...)
	buf = append(buf, pCode)
	buf = append(buf, roomID...)
	buf = append(buf, eAPub...)
	buf = append(buf, nA...)
	return sha256.Sum256(buf), nil
}

// VerifyCommitA verifies commit_a in constant time.
func VerifyCommitA(purpose string, roomID string, eAPub, nA, commitA []byte) error {
	if len(commitA) != 32 {
		return ErrCommitMismatch
	}
	expected, err := ComputeCommitA(purpose, roomID, eAPub, nA)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(expected[:], commitA) != 1 {
		return ErrCommitMismatch
	}
	return nil
}

// BuildSASTranscript constructs the exact 187-byte transcript_2 for mode=2 (commit_sas_x25519).
func BuildSASTranscript(purpose string, roomID string, commitA, eAPub, nA, eBPub, nB []byte) ([]byte, error) {
	pCode, err := PurposeCode(purpose)
	if err != nil {
		return nil, err
	}
	if !IsCanonicalRoomID(roomID) {
		return nil, ErrInvalidRoomID
	}
	if len(commitA) != 32 || len(eAPub) != 32 || len(nA) != HSNonceSize || len(eBPub) != 32 || len(nB) != HSNonceSize {
		return nil, ErrInvalidKeyLength
	}
	buf := make([]byte, 0, len(prefixHSSAS)+1+RoomIDLength+32+128)
	buf = append(buf, prefixHSSAS...)
	buf = append(buf, pCode)
	buf = append(buf, roomID...)
	buf = append(buf, commitA...)
	buf = append(buf, eAPub...)
	buf = append(buf, nA...)
	buf = append(buf, eBPub...)
	buf = append(buf, nB...)
	return buf, nil
}

// DeriveSASSession derives all mode=2 (commit_sas_x25519) handshake keys, MACs, and 6-digit SAS.
func DeriveSASSession(
	purpose string,
	roomID string,
	localPriv *ecdh.PrivateKey,
	remotePubBytes []byte,
	commitA, eAPub, nA, eBPub, nB []byte,
) (*HandshakeResult, error) {
	if err := VerifyCommitA(purpose, roomID, eAPub, nA, commitA); err != nil {
		return nil, err
	}
	shared, err := X25519SharedSecret(localPriv, remotePubBytes)
	if err != nil {
		return nil, err
	}
	defer clear(shared)

	transcript, err := BuildSASTranscript(purpose, roomID, commitA, eAPub, nA, eBPub, nB)
	if err != nil {
		return nil, err
	}
	th := sha256.Sum256(transcript)

	prk, err := hkdfExtract(th[:], shared)
	if err != nil {
		return nil, err
	}
	defer clear(prk)

	res := &HandshakeResult{TH: th}
	copy(res.PRK[:], prk)
	if err := fillSessionAndConfirm(res, prk, th[:]); err != nil {
		res.Zero()
		return nil, err
	}
	sasBytes, err := hkdfExpand(prk, []byte(infoSAS), 4)
	if err != nil {
		res.Zero()
		return nil, err
	}
	defer clear(sasBytes)
	copy(res.SASBytes[:], sasBytes)
	res.SASInt = binary.BigEndian.Uint32(sasBytes) % 1_000_000
	res.SASStr = fmt.Sprintf("%06d", res.SASInt)
	return res, nil
}

func fillSessionAndConfirm(res *HandshakeResult, prk, th []byte) error {
	sk, err := hkdfExpand(prk, []byte(infoSessionKey), 32)
	if err != nil {
		return err
	}
	ckA, err := hkdfExpand(prk, []byte(infoConfirmA), 32)
	if err != nil {
		clear(sk)
		return err
	}
	ckB, err := hkdfExpand(prk, []byte(infoConfirmB), 32)
	if err != nil {
		clear(sk)
		clear(ckA)
		return err
	}
	copy(res.SessionKey[:], sk)
	copy(res.ConfirmKeyA[:], ckA)
	copy(res.ConfirmKeyB[:], ckB)
	clear(sk)
	clear(ckA)
	clear(ckB)

	macA := computeHMACSHA256(res.ConfirmKeyA[:], th)
	macB := computeHMACSHA256(res.ConfirmKeyB[:], th)
	copy(res.MacA[:], macA)
	copy(res.MacB[:], macB)
	clear(macA)
	clear(macB)
	return nil
}

func computeHMACSHA256(key, msg []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

// VerifyMAC compares a peer's 32-byte key-confirmation MAC in constant time.
func VerifyMAC(expected [32]byte, got []byte) error {
	if len(got) != 32 || subtle.ConstantTimeCompare(expected[:], got) != 1 {
		return ErrMACMismatch
	}
	return nil
}

// VerifySAS compares a user-entered 6-digit SAS (ignoring spaces) in constant time.
func VerifySAS(expected6Digits, entered string) error {
	var clean [6]byte
	n := 0
	for i := 0; i < len(entered); i++ {
		c := entered[i]
		if c == ' ' || c == '-' || c == '\t' || c == '\r' || c == '\n' {
			continue
		}
		if c < '0' || c > '9' || n >= 6 {
			return ErrSASMismatch
		}
		clean[n] = c
		n++
	}
	if n != 6 || len(expected6Digits) != 6 {
		return ErrSASMismatch
	}
	if subtle.ConstantTimeCompare([]byte(expected6Digits), clean[:]) != 1 {
		return ErrSASMismatch
	}
	return nil
}

// DeriveOneshotPart0Keys derives (part0_key, part0_nonce_prefix) for Flow 1 oneshot transfers
// using strict 2-step HKDF-Extract(salt=msg_id, ikm=session_key) + HKDF-Expand.
func DeriveOneshotPart0Keys(sessionKey, msgID []byte) ([32]byte, [7]byte, error) {
	var key [32]byte
	var np [7]byte
	if len(sessionKey) != 32 || len(msgID) != MsgIDRawSize {
		return key, np, ErrInvalidKeyLength
	}
	prk, err := hkdfExtract(msgID, sessionKey)
	if err != nil {
		return key, np, err
	}
	defer clear(prk)

	k, err := hkdfExpand(prk, []byte(infoOneshotPart0Key), 32)
	if err != nil {
		return key, np, err
	}
	defer clear(k)

	n, err := hkdfExpand(prk, []byte(infoOneshotPart0NP), 7)
	if err != nil {
		return key, np, err
	}
	defer clear(n)
	copy(key[:], k)
	copy(np[:], n)
	return key, np, nil
}

// DerivePipeCtrlKeys derives (ctrl_key, ctrl_np) for encrypted Mode A oneshot control frames.
func DerivePipeCtrlKeys(th, sessionKey []byte) ([32]byte, [7]byte, error) {
	var key [32]byte
	var np [7]byte
	if len(th) != 32 || len(sessionKey) != 32 {
		return key, np, ErrInvalidKeyLength
	}
	prk, err := hkdfExtract(th, sessionKey)
	if err != nil {
		return key, np, err
	}
	defer clear(prk)

	k, err := hkdfExpand(prk, []byte(infoPipeCtrlKey), 32)
	if err != nil {
		return key, np, err
	}
	defer clear(k)

	n, err := hkdfExpand(prk, []byte(infoPipeCtrlNP), 7)
	if err != nil {
		return key, np, err
	}
	defer clear(n)
	copy(key[:], k)
	copy(np[:], n)
	return key, np, nil
}

// ValidatePipeCtrlSeq enforces CRYPTO_AND_AUTH.md §4.3 role parity (even 0,2,4... for initiator/sender;
// odd 1,3,5... for responder/receiver) and strict monotonicity (ctrlSeq > lastSeenSeq; pass -1 initially).
func ValidatePipeCtrlSeq(ctrlSeq uint32, fromInitiator bool, lastSeenSeq int64) error {
	wantParity := uint32(1)
	if fromInitiator {
		wantParity = 0
	}
	if (ctrlSeq & 1) != wantParity {
		return ErrInvalidCtrlSeq
	}
	if int64(ctrlSeq) <= lastSeenSeq {
		return ErrInvalidCtrlSeq
	}
	return nil
}

// BuildPipeCtrlAAD builds the exact 57-byte AAD:
// "synctool-v1/pipe-ctrl"(21B) || th(32B) || uint32_be(ctrl_seq)(4B).
func BuildPipeCtrlAAD(th []byte, ctrlSeq uint32) ([57]byte, error) {
	var aad [57]byte
	if len(th) != 32 {
		return aad, ErrInvalidKeyLength
	}
	off := 0
	off += copy(aad[off:], prefixPipeCtrlAAD)
	off += copy(aad[off:], th)
	binary.BigEndian.PutUint32(aad[off:], ctrlSeq)
	return aad, nil
}

// SealPipeCtrl encrypts a Mode A oneshot control plaintext JSON with AES-256-GCM.
func SealPipeCtrl(ctrlKey [32]byte, ctrlNP [7]byte, th []byte, ctrlSeq uint32, plaintext []byte) ([]byte, error) {
	aad, err := BuildPipeCtrlAAD(th, ctrlSeq)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	defer clear(nonce[:])
	copy(nonce[:7], ctrlNP[:])
	binary.BigEndian.PutUint32(nonce[7:11], ctrlSeq)
	nonce[11] = 0x00

	return aesGCMSeal(ctrlKey[:], nonce[:], plaintext, aad[:])
}

// OpenPipeCtrl decrypts and authenticates a Mode A oneshot control frame.
func OpenPipeCtrl(ctrlKey [32]byte, ctrlNP [7]byte, th []byte, ctrlSeq uint32, ciphertext []byte) ([]byte, error) {
	aad, err := BuildPipeCtrlAAD(th, ctrlSeq)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	defer clear(nonce[:])
	copy(nonce[:7], ctrlNP[:])
	binary.BigEndian.PutUint32(nonce[7:11], ctrlSeq)
	nonce[11] = 0x00

	return aesGCMOpen(ctrlKey[:], nonce[:], ciphertext, aad[:])
}

// OpenPipeCtrlVerified validates ctrl_seq parity and monotonicity before AEAD decryption.
func OpenPipeCtrlVerified(ctrlKey [32]byte, ctrlNP [7]byte, th []byte, ctrlSeq uint32, fromInitiator bool, lastSeenSeq int64, ciphertext []byte) ([]byte, error) {
	if err := ValidatePipeCtrlSeq(ctrlSeq, fromInitiator, lastSeenSeq); err != nil {
		return nil, err
	}
	return OpenPipeCtrl(ctrlKey, ctrlNP, th, ctrlSeq, ciphertext)
}

// DerivePairBindNonces derives the 12-byte AES-GCM nonces for PairBindPayload exchange (a & b).
func DerivePairBindNonces(prk []byte) ([12]byte, [12]byte, error) {
	var na, nb [12]byte
	if len(prk) != 32 {
		return na, nb, ErrInvalidKeyLength
	}
	a, err := hkdfExpand(prk, []byte(infoPairNonceA), 12)
	if err != nil {
		return na, nb, err
	}
	defer clear(a)
	b, err := hkdfExpand(prk, []byte(infoPairNonceB), 12)
	if err != nil {
		return na, nb, err
	}
	defer clear(b)
	copy(na[:], a)
	copy(nb[:], b)
	return na, nb, nil
}

// SealPairBind encrypts a PairBindPayload JSON for role "a" (initiator) or "b" (responder).
func SealPairBind(sessionKey [32]byte, prk, th []byte, isInitiator bool, plaintext []byte) ([]byte, error) {
	if len(th) != 32 {
		return nil, ErrInvalidKeyLength
	}
	na, nb, err := DerivePairBindNonces(prk)
	if err != nil {
		return nil, err
	}
	defer clear(na[:])
	defer clear(nb[:])
	var nonce [12]byte
	defer clear(nonce[:])
	var aad []byte
	if isInitiator {
		nonce = na
		aad = append([]byte(prefixPairBindA), th...)
	} else {
		nonce = nb
		aad = append([]byte(prefixPairBindB), th...)
	}
	return aesGCMSeal(sessionKey[:], nonce[:], plaintext, aad)
}

// OpenPairBind decrypts a peer's PairBindPayload JSON (pass fromInitiator=true when opening Alice's payload).
func OpenPairBind(sessionKey [32]byte, prk, th []byte, fromInitiator bool, ciphertext []byte) ([]byte, error) {
	if len(th) != 32 {
		return nil, ErrInvalidKeyLength
	}
	na, nb, err := DerivePairBindNonces(prk)
	if err != nil {
		return nil, err
	}
	defer clear(na[:])
	defer clear(nb[:])
	var nonce [12]byte
	defer clear(nonce[:])
	var aad []byte
	if fromInitiator {
		nonce = na
		aad = append([]byte(prefixPairBindA), th...)
	} else {
		nonce = nb
		aad = append([]byte(prefixPairBindB), th...)
	}
	return aesGCMOpen(sessionKey[:], nonce[:], ciphertext, aad)
}

func aesGCMSeal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func aesGCMOpen(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return pt, nil
}
