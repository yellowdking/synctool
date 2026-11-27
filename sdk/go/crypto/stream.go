package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// ChunkPlaintextMax is the atomic STREAM AEAD plaintext block size (64 KiB).
	ChunkPlaintextMax = 65536
	// AEADTagLen is the AES-256-GCM authentication tag size (16 bytes).
	AEADTagLen = 16
	// ChunkCiphertextMax is the atomic STREAM AEAD ciphertext block size (65,552 bytes).
	ChunkCiphertextMax = ChunkPlaintextMax + AEADTagLen
	// ChunkAADLen is the exact fixed-length binary AAD size (46 bytes).
	ChunkAADLen = 46

	// ManifestPadBucket is the 4 KiB padding bucket size for part_id=0 Manifest.
	ManifestPadBucket = 4096
	// ManifestMaxRawBytes is the hard maximum UTF-8 byte length of Manifest JSON (128 KiB).
	ManifestMaxRawBytes = 131072
	// MaxPartID is the maximum allowed part_id (0..63).
	MaxPartID = 63

	prefixChunkAAD   = "synctool-chunk-v1"
	infoBlobEncKey   = "synctool-v1/blob-enc-key"
	infoBlobNoncePfx = "synctool-v1/blob-nonce-prefix"
)

var (
	ErrStreamTruncated  = errors.New("stream truncated: missing authenticated final block")
	ErrInvalidPadding   = errors.New("invalid manifest 4 KiB padding")
	ErrInvalidBlockSize = errors.New("invalid ciphertext block length")
	ErrInvalidPartID    = errors.New("part_id out of range 0..63")
)

// DeriveBlobPartKeys derives per-blob (enc_key, nonce_prefix) for part_id >= 1 per CRYPTO_AND_AUTH.md §6.2:
// part_prk = HKDF-Extract(salt = msg_id(16B) || uint32_be(part_id), ikm = blob_key(32B)).
func DeriveBlobPartKeys(msgIDRaw [16]byte, partID uint32, blobKey []byte) ([32]byte, [7]byte, error) {
	var encKey [32]byte
	var np [7]byte
	if partID == 0 || partID > MaxPartID {
		return encKey, np, ErrInvalidPartID
	}
	if len(blobKey) != 32 {
		return encKey, np, ErrInvalidKeyLength
	}
	var salt [20]byte
	copy(salt[0:16], msgIDRaw[:])
	binary.BigEndian.PutUint32(salt[16:20], partID)

	prk, err := hkdfExtract(salt[:], blobKey)
	if err != nil {
		return encKey, np, err
	}
	defer clear(prk)

	ek, err := hkdfExpand(prk, []byte(infoBlobEncKey), 32)
	if err != nil {
		return encKey, np, err
	}
	defer clear(ek)

	p, err := hkdfExpand(prk, []byte(infoBlobNoncePfx), 7)
	if err != nil {
		return encKey, np, err
	}
	copy(encKey[:], ek)
	copy(np[:], p)
	return encKey, np, nil
}

// BuildChunkNonce constructs the 12-byte deterministic STREAM nonce:
// nonce_prefix(7B) || uint32_be(block_idx)(4B) || uint8(is_final)(1B).
func BuildChunkNonce(noncePrefix [7]byte, blockIdx uint32, isFinal bool) [12]byte {
	var nonce [12]byte
	copy(nonce[0:7], noncePrefix[:])
	binary.BigEndian.PutUint32(nonce[7:11], blockIdx)
	if isFinal {
		nonce[11] = 0x01
	} else {
		nonce[11] = 0x00
	}
	return nonce
}

// BuildChunkAAD constructs the fixed 46-byte binary STREAM AAD:
// "synctool-chunk-v1"(17B) || msg_id(16B) || uint32_be(part_id)(4B) || uint32_be(block_idx)(4B) || uint8(is_final)(1B) || uint32_be(plaintext_len)(4B).
func BuildChunkAAD(msgIDRaw [16]byte, partID, blockIdx uint32, isFinal bool, plaintextLen uint32) [ChunkAADLen]byte {
	var aad [ChunkAADLen]byte
	copy(aad[0:17], prefixChunkAAD)
	copy(aad[17:33], msgIDRaw[:])
	binary.BigEndian.PutUint32(aad[33:37], partID)
	binary.BigEndian.PutUint32(aad[37:41], blockIdx)
	if isFinal {
		aad[41] = 0x01
	} else {
		aad[41] = 0x00
	}
	binary.BigEndian.PutUint32(aad[42:46], plaintextLen)
	return aad
}

// TotalBlocks returns the exact number of STREAM AEAD atomic blocks for plaintextLen bytes.
// Empty parts (0 bytes) produce 1 block (plaintext_len=0, is_final=0x01, ciphertext=16B).
func TotalBlocks(plaintextLen int64) uint32 {
	if plaintextLen <= 0 {
		return 1
	}
	return uint32((plaintextLen + ChunkPlaintextMax - 1) / ChunkPlaintextMax)
}

// EncryptedPartSize returns the exact ciphertext byte size for plaintextLen bytes.
func EncryptedPartSize(plaintextLen int64) int64 {
	if plaintextLen <= 0 {
		return AEADTagLen
	}
	blocks := (plaintextLen + ChunkPlaintextMax - 1) / ChunkPlaintextMax
	return plaintextLen + blocks*AEADTagLen
}

// TransportChunkCount returns how many HTTP transport chunks are needed for encryptedSize
// when each transport chunk packs blocksPerChunk atomic blocks.
func TransportChunkCount(encryptedSize int64, blocksPerChunk int) int {
	if blocksPerChunk <= 0 {
		blocksPerChunk = 16
	}
	chunkCap := int64(blocksPerChunk) * ChunkCiphertextMax
	if encryptedSize <= 0 {
		return 1
	}
	return int((encryptedSize + chunkCap - 1) / chunkCap)
}

// SealBlock encrypts a single STREAM AEAD atomic block (0..65536 bytes).
func SealBlock(encKey [32]byte, noncePrefix [7]byte, msgIDRaw [16]byte, partID, blockIdx uint32, isFinal bool, plaintext []byte) ([]byte, error) {
	if len(plaintext) > ChunkPlaintextMax {
		return nil, ErrInvalidBlockSize
	}
	if !isFinal && len(plaintext) != ChunkPlaintextMax {
		return nil, ErrInvalidBlockSize
	}
	nonce := BuildChunkNonce(noncePrefix, blockIdx, isFinal)
	aad := BuildChunkAAD(msgIDRaw, partID, blockIdx, isFinal, uint32(len(plaintext)))
	return aesGCMSeal(encKey[:], nonce[:], plaintext, aad[:])
}

// OpenBlock decrypts and authenticates a single STREAM AEAD atomic block (16..65552 bytes).
func OpenBlock(encKey [32]byte, noncePrefix [7]byte, msgIDRaw [16]byte, partID, blockIdx uint32, isFinal bool, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < AEADTagLen || len(ciphertext) > ChunkCiphertextMax {
		return nil, ErrInvalidBlockSize
	}
	ptLen := len(ciphertext) - AEADTagLen
	if !isFinal && ptLen != ChunkPlaintextMax {
		return nil, ErrInvalidBlockSize
	}
	nonce := BuildChunkNonce(noncePrefix, blockIdx, isFinal)
	aad := BuildChunkAAD(msgIDRaw, partID, blockIdx, isFinal, uint32(ptLen))
	return aesGCMOpen(encKey[:], nonce[:], ciphertext, aad[:])
}

// StreamCipher holds a reusable AES-256-GCM AEAD instance for constant-memory streaming encryption/decryption.
type StreamCipher struct {
	aead        cipher.AEAD
	noncePrefix [7]byte
	msgIDRaw    [16]byte
	partID      uint32
}

// NewStreamCipher constructs a StreamCipher for a given part_id and key material.
func NewStreamCipher(encKey [32]byte, noncePrefix [7]byte, msgIDRaw [16]byte, partID uint32) (*StreamCipher, error) {
	if partID > MaxPartID {
		return nil, ErrInvalidPartID
	}
	block, err := aes.NewCipher(encKey[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &StreamCipher{
		aead:        aead,
		noncePrefix: noncePrefix,
		msgIDRaw:    msgIDRaw,
		partID:      partID,
	}, nil
}

// SealBlockAt encrypts one atomic block using the pre-initialized cipher.
func (s *StreamCipher) SealBlockAt(blockIdx uint32, isFinal bool, plaintext, dst []byte) ([]byte, error) {
	if len(plaintext) > ChunkPlaintextMax || (!isFinal && len(plaintext) != ChunkPlaintextMax) {
		return nil, ErrInvalidBlockSize
	}
	nonce := BuildChunkNonce(s.noncePrefix, blockIdx, isFinal)
	aad := BuildChunkAAD(s.msgIDRaw, s.partID, blockIdx, isFinal, uint32(len(plaintext)))
	return s.aead.Seal(dst, nonce[:], plaintext, aad[:]), nil
}

// OpenBlockAt decrypts one atomic block using the pre-initialized cipher.
func (s *StreamCipher) OpenBlockAt(blockIdx uint32, isFinal bool, ciphertext, dst []byte) ([]byte, error) {
	if len(ciphertext) < AEADTagLen || len(ciphertext) > ChunkCiphertextMax {
		return nil, ErrInvalidBlockSize
	}
	ptLen := len(ciphertext) - AEADTagLen
	if !isFinal && ptLen != ChunkPlaintextMax {
		return nil, ErrInvalidBlockSize
	}
	nonce := BuildChunkNonce(s.noncePrefix, blockIdx, isFinal)
	aad := BuildChunkAAD(s.msgIDRaw, s.partID, blockIdx, isFinal, uint32(ptLen))
	pt, err := s.aead.Open(dst, nonce[:], ciphertext, aad[:])
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return pt, nil
}

// EncryptPartStream streams plaintext from r and writes contiguous STREAM AEAD ciphertext blocks to w
// using O(1) memory (~128 KiB). Returns total plaintext bytes read and total ciphertext bytes written.
func EncryptPartStream(r io.Reader, w io.Writer, encKey [32]byte, noncePrefix [7]byte, msgIDRaw [16]byte, partID uint32) (ptTotal int64, ctTotal int64, err error) {
	sc, err := NewStreamCipher(encKey, noncePrefix, msgIDRaw, partID)
	if err != nil {
		return 0, 0, err
	}
	// Read up to 64 KiB + 1 byte lookahead to know whether EOF is reached on exact multiples of 64 KiB.
	buf := make([]byte, ChunkPlaintextMax+1)
	ctBuf := make([]byte, 0, ChunkCiphertextMax)
	var blockIdx uint32
	carry := 0

	for {
		n, rerr := io.ReadFull(r, buf[carry:])
		have := carry + n
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			return ptTotal, ctTotal, rerr
		}
		eof := rerr == io.EOF || rerr == io.ErrUnexpectedEOF

		if have == 0 && eof {
			// Only happens for a 0-byte empty part on blockIdx == 0.
			ct, err := sc.SealBlockAt(0, true, nil, ctBuf[:0])
			if err != nil {
				return ptTotal, ctTotal, err
			}
			nw, werr := w.Write(ct)
			ctTotal += int64(nw)
			return ptTotal, ctTotal, werr
		}

		if have <= ChunkPlaintextMax {
			// Must be EOF (final block).
			pt := buf[:have]
			ct, err := sc.SealBlockAt(blockIdx, true, pt, ctBuf[:0])
			if err != nil {
				return ptTotal, ctTotal, err
			}
			nw, werr := w.Write(ct)
			ptTotal += int64(len(pt))
			ctTotal += int64(nw)
			return ptTotal, ctTotal, werr
		}

		// have == ChunkPlaintextMax + 1: emit full non-final block and shift 1 lookahead byte.
		pt := buf[:ChunkPlaintextMax]
		ct, err := sc.SealBlockAt(blockIdx, false, pt, ctBuf[:0])
		if err != nil {
			return ptTotal, ctTotal, err
		}
		nw, werr := w.Write(ct)
		if werr != nil {
			return ptTotal, ctTotal, werr
		}
		ptTotal += int64(len(pt))
		ctTotal += int64(nw)
		blockIdx++
		buf[0] = buf[ChunkPlaintextMax]
		carry = 1
	}
}

// DecryptPartStream streams contiguous STREAM AEAD ciphertext blocks from r and writes verified plaintext to w
// using O(1) memory (~128 KiB). Rejects truncated streams lacking an authenticated is_final=0x01 block.
func DecryptPartStream(r io.Reader, w io.Writer, encKey [32]byte, noncePrefix [7]byte, msgIDRaw [16]byte, partID uint32) (ptTotal int64, err error) {
	sc, err := NewStreamCipher(encKey, noncePrefix, msgIDRaw, partID)
	if err != nil {
		return 0, err
	}
	buf := make([]byte, ChunkCiphertextMax+1)
	ptBuf := make([]byte, 0, ChunkPlaintextMax)
	var blockIdx uint32
	carry := 0

	for {
		n, rerr := io.ReadFull(r, buf[carry:])
		have := carry + n
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			return ptTotal, rerr
		}
		eof := rerr == io.EOF || rerr == io.ErrUnexpectedEOF

		if have == 0 && eof {
			return ptTotal, ErrStreamTruncated
		}

		if have <= ChunkCiphertextMax {
			// Final block MUST authenticate with is_final=0x01.
			pt, err := sc.OpenBlockAt(blockIdx, true, buf[:have], ptBuf[:0])
			if err != nil {
				// If a non-final block was truncated at EOF, decryption with is_final=0x01 fails.
				return ptTotal, fmt.Errorf("%w: %v", ErrStreamTruncated, err)
			}
			if len(pt) > 0 {
				nw, werr := w.Write(pt)
				ptTotal += int64(nw)
				if werr != nil {
					return ptTotal, werr
				}
			}
			return ptTotal, nil
		}

		// have == ChunkCiphertextMax + 1: non-final full block.
		pt, err := sc.OpenBlockAt(blockIdx, false, buf[:ChunkCiphertextMax], ptBuf[:0])
		if err != nil {
			return ptTotal, err
		}
		nw, werr := w.Write(pt)
		ptTotal += int64(nw)
		if werr != nil {
			return ptTotal, werr
		}
		blockIdx++
		buf[0] = buf[ChunkCiphertextMax]
		carry = 1
	}
}

// PadManifest wraps manifest UTF-8 JSON bytes into the 4 KiB-aligned format (CRYPTO_AND_AUTH.md §6.3):
// uint32_be(L) || manifest_utf8_bytes(L) || (0x00 * pad_len).
func PadManifest(raw []byte) ([]byte, error) {
	l := len(raw)
	if l == 0 || l > ManifestMaxRawBytes {
		return nil, ErrInvalidPadding
	}
	need := 4 + l
	totalLen := ((need + ManifestPadBucket - 1) / ManifestPadBucket) * ManifestPadBucket
	out := make([]byte, totalLen)
	binary.BigEndian.PutUint32(out[0:4], uint32(l))
	copy(out[4:4+l], raw)
	// Trailing bytes are already zeroed by make.
	return out, nil
}

// UnpadManifest validates 4 KiB alignment, length prefix, and strictly-zero trailing padding bytes.
func UnpadManifest(padded []byte) ([]byte, error) {
	if len(padded) < ManifestPadBucket || len(padded)%ManifestPadBucket != 0 {
		return nil, ErrInvalidPadding
	}
	l := binary.BigEndian.Uint32(padded[0:4])
	if l == 0 || l > ManifestMaxRawBytes || int(4+l) > len(padded) {
		return nil, ErrInvalidPadding
	}
	// Verify all trailing padding bytes are strictly 0x00.
	var nonZero byte
	for i := int(4 + l); i < len(padded); i++ {
		nonZero |= padded[i]
	}
	if nonZero != 0 {
		return nil, ErrInvalidPadding
	}
	out := make([]byte, l)
	copy(out, padded[4:4+l])
	return out, nil
}
