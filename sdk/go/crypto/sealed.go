package crypto

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
)

const (
	// SealedHeaderSize is the fixed wire size of a Flow 2 SealedHeader (56B clear + 152B sealed_box).
	SealedHeaderSize = 208
	// ClearHeaderSize is the fixed 56-byte unencrypted prefix of SealedHeader.
	ClearHeaderSize = 56
	// SealedBoxPlaintextSize is the fixed 136-byte plaintext inside sealed_box.
	SealedBoxPlaintextSize = 136
	// SealedBoxSize is SealedBoxPlaintextSize + 16B AES-256-GCM tag = 152B.
	SealedBoxSize = 152
	// ZeroRTTSigInputSize is the exact 149-byte Ed25519 signing input for Flow 2.
	ZeroRTTSigInputSize = 149

	sealedHeaderMagic = "ST01"
	sealedMode0RTT    = uint8(0x02)

	info0RTTHdrKey   = "synctool-v1/0rtt-hdr-key"
	info0RTTHdrNonce = "synctool-v1/0rtt-hdr-nonce"
	info0RTTPart0Key = "synctool-v1/0rtt-part0-key"
	info0RTTPart0NP  = "synctool-v1/0rtt-part0-np"
	prefix0RTTSig    = "synctool-v1/0rtt-sig\n"
	prefixDirectAck  = "synctool-v1/direct-ack"
)

var (
	ErrInvalidSealedHeader = errors.New("invalid 208-byte sealed header")
	ErrRecipientMismatch   = errors.New("sealed header recipient_device_id mismatch")
	ErrUntrustedSender     = errors.New("sealed header sender_device_id not trusted")
)

// SealedHeaderOpenResult holds the authenticated fields and derived part0 keys
// extracted from a verified 208-byte Flow 2 SealedHeader.
type SealedHeaderOpenResult struct {
	MsgIDRaw          [16]byte
	MsgID             string
	EphemeralPK       [32]byte
	SenderDeviceIDRaw [16]byte
	SenderDeviceID    string
	RecipientIDRaw    [16]byte
	RecipientDeviceID string
	CreatedAt         int64
	ManifestSHA256    [32]byte
	SenderSig         [64]byte
	Part0Key          [32]byte
	Part0NoncePrefix  [7]byte
}

// Zero clears derived key material from SealedHeaderOpenResult.
func (r *SealedHeaderOpenResult) Zero() {
	if r == nil {
		return
	}
	clear(r.Part0Key[:])
	clear(r.Part0NoncePrefix[:])
}

// BuildZeroRTTSigInput builds the exact 149-byte Ed25519 signing input (CRYPTO_AND_AUTH.md §5.2):
// "synctool-v1/0rtt-sig\n"(21B) || clear_header(56B) || sender_id(16B) || recipient_id(16B) || created_at(8B) || manifest_sha256(32B).
func BuildZeroRTTSigInput(clearHeader []byte, senderIDRaw, recipientIDRaw [16]byte, createdAt int64, manifestSHA256 [32]byte) ([ZeroRTTSigInputSize]byte, error) {
	var out [ZeroRTTSigInputSize]byte
	if len(clearHeader) != ClearHeaderSize {
		return out, ErrInvalidSealedHeader
	}
	if createdAt < 0 {
		return out, errors.New("created_at must be non-negative")
	}
	off := 0
	off += copy(out[off:], prefix0RTTSig)
	off += copy(out[off:], clearHeader)
	off += copy(out[off:], senderIDRaw[:])
	off += copy(out[off:], recipientIDRaw[:])
	binary.BigEndian.PutUint64(out[off:], uint64(createdAt))
	off += 8
	copy(out[off:], manifestSHA256[:])
	return out, nil
}

// Seal0RTTHeader creates a fresh 208-byte Flow 2 SealedHeader with CSPRNG ephemeral key and msg_id.
func Seal0RTTHeader(
	senderKeys *DeviceKeys,
	recipientIDRaw [16]byte,
	recipientKEMPub []byte,
	createdAt int64,
	manifestSHA256 [32]byte,
) (sealedHeader [SealedHeaderSize]byte, msgIDRaw [16]byte, part0Key [32]byte, part0NP [7]byte, err error) {
	if _, err = rand.Read(msgIDRaw[:]); err != nil {
		return
	}
	ephPriv, err := GenerateEphemeralX25519()
	if err != nil {
		clear(msgIDRaw[:])
		return
	}
	return Seal0RTTHeaderDeterministic(senderKeys, ephPriv, msgIDRaw, recipientIDRaw, recipientKEMPub, createdAt, manifestSHA256)
}

// Seal0RTTHeaderDeterministic creates a 208-byte Flow 2 SealedHeader using caller-supplied
// ephemeral private key and msg_id (used directly for golden test vector generation).
func Seal0RTTHeaderDeterministic(
	senderKeys *DeviceKeys,
	ephPriv *ecdh.PrivateKey,
	msgIDRaw [16]byte,
	recipientIDRaw [16]byte,
	recipientKEMPub []byte,
	createdAt int64,
	manifestSHA256 [32]byte,
) (sealedHeader [SealedHeaderSize]byte, outMsgID [16]byte, part0Key [32]byte, part0NP [7]byte, err error) {
	outMsgID = msgIDRaw
	if senderKeys == nil || ephPriv == nil || len(recipientKEMPub) != 32 {
		err = ErrInvalidKeyLength
		return
	}

	var clearHdr [ClearHeaderSize]byte
	copy(clearHdr[0:4], sealedHeaderMagic)
	clearHdr[4] = sealedMode0RTT
	clearHdr[5] = 0x00 // flags
	clearHdr[6] = 0x00
	clearHdr[7] = 0x00
	copy(clearHdr[8:24], msgIDRaw[:])
	copy(clearHdr[24:56], ephPriv.PublicKey().Bytes())

	dh, err := X25519SharedSecret(ephPriv, recipientKEMPub)
	if err != nil {
		return
	}
	defer clear(dh)

	hdrKey, hdrNonce, p0Key, p0NP, err := derive0RTTKeys(clearHdr[:], dh)
	if err != nil {
		clear(outMsgID[:])
		return
	}
	defer clear(hdrKey[:])
	defer clear(hdrNonce[:])

	sigInput, err := BuildZeroRTTSigInput(clearHdr[:], senderKeys.DeviceIDRaw, recipientIDRaw, createdAt, manifestSHA256)
	if err != nil {
		clear(p0Key[:])
		clear(p0NP[:])
		clear(outMsgID[:])
		return
	}
	senderSig := ed25519.Sign(senderKeys.SignPriv, sigInput[:])

	var boxPT [SealedBoxPlaintextSize]byte
	copy(boxPT[0:16], senderKeys.DeviceIDRaw[:])
	copy(boxPT[16:32], recipientIDRaw[:])
	binary.BigEndian.PutUint64(boxPT[32:40], uint64(createdAt))
	copy(boxPT[40:72], manifestSHA256[:])
	copy(boxPT[72:136], senderSig)
	defer clear(boxPT[:])

	sealedBox, err := aesGCMSeal(hdrKey[:], hdrNonce[:], boxPT[:], clearHdr[:])
	if err != nil {
		clear(p0Key[:])
		clear(p0NP[:])
		clear(outMsgID[:])
		return
	}
	copy(sealedHeader[0:ClearHeaderSize], clearHdr[:])
	copy(sealedHeader[ClearHeaderSize:SealedHeaderSize], sealedBox)
	part0Key = p0Key
	part0NP = p0NP
	return
}

// ParseClearHeaderMsgID extracts msg_id from a 208-byte SealedHeader before decryption
// (useful for fast seen_msg_ids replay checks).
func ParseClearHeaderMsgID(sealedHeader []byte) ([16]byte, string, error) {
	var id [16]byte
	if len(sealedHeader) != SealedHeaderSize {
		return id, "", ErrInvalidSealedHeader
	}
	if string(sealedHeader[0:4]) != sealedHeaderMagic ||
		sealedHeader[4] != sealedMode0RTT ||
		sealedHeader[5] != 0x00 ||
		sealedHeader[6] != 0x00 ||
		sealedHeader[7] != 0x00 {
		return id, "", ErrInvalidSealedHeader
	}
	copy(id[:], sealedHeader[8:24])
	return id, hex.EncodeToString(id[:]), nil
}

// SenderPubKeyLookup resolves a trusted, non-revoked sender device's 32-byte Ed25519 public key.
// Return nil (or error) when unknown or revoked.
type SenderPubKeyLookup func(senderDeviceID string) (ed25519.PublicKey, error)

// Open0RTTHeader decrypts and fully authenticates a 208-byte Flow 2 SealedHeader per CRYPTO_AND_AUTH.md §5.3.
func Open0RTTHeader(
	recipientKeys *DeviceKeys,
	sealedHeader []byte,
	lookupSender SenderPubKeyLookup,
) (*SealedHeaderOpenResult, error) {
	if recipientKeys == nil || lookupSender == nil {
		return nil, ErrInvalidKeyLength
	}
	msgIDRaw, msgIDHex, err := ParseClearHeaderMsgID(sealedHeader)
	if err != nil {
		return nil, err
	}
	clearHdr := sealedHeader[0:ClearHeaderSize]
	sealedBox := sealedHeader[ClearHeaderSize:SealedHeaderSize]
	ephPub := clearHdr[24:56]

	dh, err := X25519SharedSecret(recipientKeys.KEMPriv, ephPub)
	if err != nil {
		return nil, err
	}
	defer clear(dh)

	hdrKey, hdrNonce, p0Key, p0NP, err := derive0RTTKeys(clearHdr, dh)
	if err != nil {
		return nil, err
	}
	defer clear(hdrKey[:])
	defer clear(hdrNonce[:])
	wipePart0 := func() {
		clear(p0Key[:])
		clear(p0NP[:])
	}

	boxPT, err := aesGCMOpen(hdrKey[:], hdrNonce[:], sealedBox, clearHdr)
	if err != nil {
		wipePart0()
		return nil, err
	}
	defer clear(boxPT)

	if len(boxPT) != SealedBoxPlaintextSize {
		wipePart0()
		return nil, ErrInvalidSealedHeader
	}

	var senderIDRaw, recipIDRaw [16]byte
	copy(senderIDRaw[:], boxPT[0:16])
	copy(recipIDRaw[:], boxPT[16:32])
	rawCreatedAt := binary.BigEndian.Uint64(boxPT[32:40])
	if rawCreatedAt > math.MaxInt64 {
		wipePart0()
		return nil, ErrInvalidSealedHeader
	}
	createdAt := int64(rawCreatedAt)
	var manifestSHA [32]byte
	copy(manifestSHA[:], boxPT[40:72])
	var senderSig [64]byte
	copy(senderSig[:], boxPT[72:136])

	if subtle.ConstantTimeCompare(recipIDRaw[:], recipientKeys.DeviceIDRaw[:]) != 1 {
		wipePart0()
		return nil, ErrRecipientMismatch
	}

	senderIDHex := hex.EncodeToString(senderIDRaw[:])
	senderSignPK, err := lookupSender(senderIDHex)
	if err != nil || len(senderSignPK) != ed25519.PublicKeySize {
		wipePart0()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUntrustedSender, err)
		}
		return nil, ErrUntrustedSender
	}
	if IsSmallOrderOrNonCanonicalEd25519PK(senderSignPK) {
		wipePart0()
		return nil, ErrInvalidSignature
	}
	if _, derivedSenderHex := DeriveDeviceID(senderSignPK); subtle.ConstantTimeCompare([]byte(derivedSenderHex), []byte(senderIDHex)) != 1 {
		wipePart0()
		return nil, ErrDeviceIDMismatch
	}

	sigInput, err := BuildZeroRTTSigInput(clearHdr, senderIDRaw, recipIDRaw, createdAt, manifestSHA)
	if err != nil {
		wipePart0()
		return nil, err
	}
	if !ed25519.Verify(senderSignPK, sigInput[:], senderSig[:]) {
		wipePart0()
		return nil, ErrInvalidSignature
	}

	res := &SealedHeaderOpenResult{
		MsgIDRaw:          msgIDRaw,
		MsgID:             msgIDHex,
		SenderDeviceIDRaw: senderIDRaw,
		SenderDeviceID:    senderIDHex,
		RecipientIDRaw:    recipIDRaw,
		RecipientDeviceID: hex.EncodeToString(recipIDRaw[:]),
		CreatedAt:         createdAt,
		ManifestSHA256:    manifestSHA,
		SenderSig:         senderSig,
		Part0Key:          p0Key,
		Part0NoncePrefix:  p0NP,
	}
	copy(res.EphemeralPK[:], ephPub)
	return res, nil
}

func derive0RTTKeys(clearHdr, dh []byte) (hdrKey [32]byte, hdrNonce [12]byte, part0Key [32]byte, part0NP [7]byte, err error) {
	prk, err := hkdfExtract(clearHdr, dh)
	if err != nil {
		return
	}
	defer clear(prk)

	hk, err := hkdfExpand(prk, []byte(info0RTTHdrKey), 32)
	if err != nil {
		return
	}
	defer clear(hk)

	hn, err := hkdfExpand(prk, []byte(info0RTTHdrNonce), 12)
	if err != nil {
		return
	}
	defer clear(hn)
	pk, err := hkdfExpand(prk, []byte(info0RTTPart0Key), 32)
	if err != nil {
		return
	}
	defer clear(pk)

	pn, err := hkdfExpand(prk, []byte(info0RTTPart0NP), 7)
	if err != nil {
		return
	}
	defer clear(pn)
	copy(hdrKey[:], hk)
	copy(hdrNonce[:], hn)
	copy(part0Key[:], pk)
	copy(part0NP[:], pn)
	return
}

// ComputeDirectAckMAC computes HMAC-SHA256(part0_key, "synctool-v1/direct-ack" || msg_id(16B))
// to prevent a malicious relay from forging Mode A direct completion acknowledgements.
func ComputeDirectAckMAC(part0Key [32]byte, msgIDRaw [16]byte) [32]byte {
	msg := make([]byte, len(prefixDirectAck)+MsgIDRawSize)
	defer clear(msg)
	copy(msg, prefixDirectAck)
	copy(msg[len(prefixDirectAck):], msgIDRaw[:])
	mac := computeHMACSHA256(part0Key[:], msg)
	defer clear(mac)
	var out [32]byte
	copy(out[:], mac)
	return out
}

// VerifyDirectAckMAC checks a Mode A direct_ack MAC in constant time.
func VerifyDirectAckMAC(part0Key [32]byte, msgIDRaw [16]byte, got []byte) error {
	expected := ComputeDirectAckMAC(part0Key, msgIDRaw)
	defer clear(expected[:])
	if len(got) != 32 || subtle.ConstantTimeCompare(expected[:], got) != 1 {
		return ErrMACMismatch
	}
	return nil
}
