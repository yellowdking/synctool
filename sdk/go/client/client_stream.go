package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"

	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

const (
	maxSealedHeaderFutureSkewSec = int64(600)
	recvCheckpointTTLSec         = int64(7 * 86400)
)

type replayWatermarkKeyStore interface {
	GetReplayWatermark() (int64, error)
}

// --- Parcel preparation & streaming chunk engine ---

type preparedBlob struct {
	PartID  uint32
	BlobKey [32]byte
	Desc    envelope.BlobDescriptor
	Input   envelope.BlobInput
}

type preparedParcel struct {
	MsgIDRaw     [16]byte
	MsgID        string
	CreatedAt    int64
	Manifest     envelope.Manifest
	ManifestUTF8 []byte
	ManifestPad  []byte
	ManifestSHA  [32]byte
	Blobs        []preparedBlob
	Parts        []envelope.PartLayout
	TotalEnc     int64
}

func (p *preparedParcel) Zero() {
	if p == nil {
		return
	}
	for i := range p.Blobs {
		clear(p.Blobs[i].BlobKey[:])
	}
	clear(p.ManifestUTF8)
	clear(p.ManifestPad)
}

func (c *Client) prepareParcel(input envelope.ParcelInput, blocksPerChunk int) (*preparedParcel, error) {
	if len(input.Blobs) > envelope.MaxBlobs {
		return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, fmt.Sprintf("blobs count exceeds max %d", envelope.MaxBlobs), nil)
	}
	if blocksPerChunk <= 0 {
		blocksPerChunk = 16
	}
	msgIDSlice, err := synccrypto.GenerateRandomBytes(synccrypto.MsgIDRawSize)
	if err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "generate msg_id", err)
	}
	var msgIDRaw [16]byte
	copy(msgIDRaw[:], msgIDSlice)
	clear(msgIDSlice)
	msgIDHex := hex.EncodeToString(msgIDRaw[:])

	appID := input.AppID
	if appID == "" {
		appID = c.appID
	}
	schema := input.Schema
	if schema == "" {
		schema = "generic.parcel.v1"
	}
	// ST-P1-6: Strictly use local wall clock for signed Manifest.CreatedAt & SealedHeader.CreatedAt (never relay-adjusted X-Sync-TS).
	createdAt := time.Now().Unix()

	blobs := make([]preparedBlob, 0, len(input.Blobs))
	wipeBlobs := func() {
		for i := range blobs {
			clear(blobs[i].BlobKey[:])
		}
	}
	descs := make([]envelope.BlobDescriptor, 0, len(input.Blobs))
	for i, bi := range input.Blobs {
		partID := uint32(i + 1)
		rc, size, err := bi.OpenStream()
		if err != nil {
			wipeBlobs()
			return nil, err
		}
		h := sha256.New()
		n, copyErr := io.CopyBuffer(h, rc, make([]byte, 64*1024))
		_ = rc.Close()
		if copyErr != nil {
			wipeBlobs()
			return nil, envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "hash blob stream", copyErr)
		}
		if size >= 0 && n != size {
			size = n
		}
		bkSlice, err := synccrypto.GenerateRandomBytes(32)
		if err != nil {
			wipeBlobs()
			return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "generate blob key", err)
		}
		var bk [32]byte
		copy(bk[:], bkSlice)
		clear(bkSlice)

		role := bi.Role
		if role == "" {
			role = "file"
		}
		name := bi.Name
		if name == "" && bi.FilePath != "" {
			name = filepath.Base(bi.FilePath)
		}
		if name == "" {
			name = fmt.Sprintf("part_%d.bin", partID)
		}
		mimeType := bi.MIME
		if mimeType == "" {
			mimeType = "application/octet-stream"
		}
		enc := bi.Encoding
		if enc == "" {
			enc = "identity"
		}
		desc := envelope.BlobDescriptor{
			PartID:   partID,
			Role:     role,
			Name:     name,
			MIME:     mimeType,
			Size:     size,
			SHA256:   hex.EncodeToString(h.Sum(nil)),
			Key:      base64.RawURLEncoding.EncodeToString(bk[:]),
			Encoding: enc,
			Meta:     bi.Meta,
		}
		blobs = append(blobs, preparedBlob{PartID: partID, BlobKey: bk, Desc: desc, Input: bi})
		descs = append(descs, desc)
	}

	manifest := envelope.Manifest{
		EnvelopeVersion: envelope.EnvelopeVersion,
		MsgID:           msgIDHex,
		AppID:           appID,
		Schema:          schema,
		CreatedAt:       createdAt,
		Sender: envelope.SenderInfo{
			DeviceID: c.deviceKeys.DeviceID,
			Label:    c.deviceLabel,
			Platform: c.platform,
		},
		InlinePayload: input.InlinePayload,
		Blobs:         descs,
	}
	manifestUTF8, err := envelope.MarshalManifest(&manifest)
	if err != nil {
		wipeBlobs()
		return nil, err
	}
	manifestPad, err := synccrypto.PadManifest(manifestUTF8)
	if err != nil {
		clear(manifestUTF8)
		wipeBlobs()
		return nil, envelope.WrapError(envelope.ErrCodeManifestInvalid, false, 0, "pad manifest", err)
	}
	manifestSHA := sha256.Sum256(manifestUTF8)

	parts := make([]envelope.PartLayout, 0, 1+len(blobs))
	p0Enc := synccrypto.EncryptedPartSize(int64(len(manifestPad)))
	parts = append(parts, envelope.PartLayout{
		PartID:     0,
		TotalBytes: p0Enc,
		ChunkCount: synccrypto.TransportChunkCount(p0Enc, blocksPerChunk),
	})
	totalEnc := p0Enc
	for _, b := range blobs {
		encSz := synccrypto.EncryptedPartSize(b.Desc.Size)
		parts = append(parts, envelope.PartLayout{
			PartID:     b.PartID,
			TotalBytes: encSz,
			ChunkCount: synccrypto.TransportChunkCount(encSz, blocksPerChunk),
		})
		totalEnc += encSz
	}

	return &preparedParcel{
		MsgIDRaw:     msgIDRaw,
		MsgID:        msgIDHex,
		CreatedAt:    createdAt,
		Manifest:     manifest,
		ManifestUTF8: manifestUTF8,
		ManifestPad:  manifestPad,
		ManifestSHA:  manifestSHA,
		Blobs:        blobs,
		Parts:        parts,
		TotalEnc:     totalEnc,
	}, nil
}

// streamUploadPart reads plaintext sequentially in 64 KiB atomic blocks, packs blocksPerChunk blocks
// into each transport chunk buffer (<= 2 MiB), and invokes putChunk(txIdx, chunkBytes).
// Memory stays strictly O(blocksPerChunk * 64 KiB) even for multi-GB videos.
func streamUploadPart(
	r io.Reader,
	plaintextSize int64,
	encKey [32]byte,
	noncePrefix [7]byte,
	msgIDRaw [16]byte,
	partID uint32,
	blocksPerChunk int,
	startTxIdx int,
	putChunk func(txIdx int, chunkBytes []byte) error,
) error {
	sc, err := synccrypto.NewStreamCipher(encKey, noncePrefix, msgIDRaw, partID)
	if err != nil {
		return envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "init stream cipher", err)
	}
	totalBlocks := synccrypto.TotalBlocks(plaintextSize)
	ptBuf := make([]byte, synccrypto.ChunkPlaintextMax)
	defer clear(ptBuf)
	chunkBuf := make([]byte, 0, blocksPerChunk*synccrypto.ChunkCiphertextMax)

	var blockIdx uint32
	txIdx := 0
	for blockIdx < totalBlocks {
		isFinal := blockIdx == totalBlocks-1
		wantPT := synccrypto.ChunkPlaintextMax
		if isFinal {
			if plaintextSize == 0 {
				wantPT = 0
			} else {
				wantPT = int(((plaintextSize - 1) % synccrypto.ChunkPlaintextMax) + 1)
			}
		}
		var ptSlice []byte
		if wantPT > 0 {
			if _, err := io.ReadFull(r, ptBuf[:wantPT]); err != nil {
				return envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "read blob plaintext block", err)
			}
			ptSlice = ptBuf[:wantPT]
		}
		if txIdx >= startTxIdx {
			ct, err := sc.SealBlockAt(blockIdx, isFinal, ptSlice, nil)
			if err != nil {
				return envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "seal block", err)
			}
			chunkBuf = append(chunkBuf, ct...)
		}
		blockIdx++
		atBoundary := (int(blockIdx)%blocksPerChunk == 0) || blockIdx == totalBlocks
		if atBoundary {
			if txIdx >= startTxIdx {
				if err := putChunk(txIdx, chunkBuf); err != nil {
					return err
				}
				chunkBuf = chunkBuf[:0]
			}
			txIdx++
		}
	}
	return nil
}

// decryptChunkIntoStream splits a transport chunk into 65,552 B atomic blocks, decrypts each block,
// enforces ST-P0-2 sawFinal & totalBlocks hard stops, and writes verified plaintext to w.
// When expectedPlaintextSize >= 0, the final block's exact ciphertext length is enforced before decryption.
func decryptChunkIntoStream(
	sc *synccrypto.StreamCipher,
	chunkBytes []byte,
	startBlockIdx uint32,
	totalBlocks uint32,
	expectedPlaintextSize int64,
	isLastTransportChunk bool,
	w io.Writer,
) (blocksDone uint32, bytesWritten int64, sawFinal bool, err error) {
	if len(chunkBytes) == 0 {
		return 0, 0, false, envelope.NewError(envelope.ErrCodeStreamTruncated, false, 0, "empty transport chunk", nil)
	}
	off := 0
	blk := startBlockIdx
	ptBuf := make([]byte, 0, synccrypto.ChunkPlaintextMax)
	defer func() {
		clear(ptBuf[:cap(ptBuf)])
	}()
	for off < len(chunkBytes) {
		if sawFinal {
			return blocksDone, bytesWritten, false, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "trailing bytes after authenticated final block", synccrypto.ErrIntegrityMismatch)
		}
		if totalBlocks > 0 && blk >= totalBlocks {
			return blocksDone, bytesWritten, false, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "stream block index exceeded declared total blocks", synccrypto.ErrIntegrityMismatch)
		}
		rem := len(chunkBytes) - off
		isFinal := false
		if totalBlocks > 0 {
			isFinal = (blk == totalBlocks-1)
		}
		take := synccrypto.ChunkCiphertextMax
		if isFinal && expectedPlaintextSize >= 0 {
			wantFinalPT := 0
			if expectedPlaintextSize > 0 {
				wantFinalPT = int(((expectedPlaintextSize - 1) % synccrypto.ChunkPlaintextMax) + 1)
			}
			wantFinalCT := wantFinalPT + synccrypto.AEADTagLen
			if rem < wantFinalCT {
				return blocksDone, bytesWritten, false, envelope.WrapError(envelope.ErrCodeStreamTruncated, false, 0, "truncated final stream block", synccrypto.ErrStreamTruncated)
			}
			take = wantFinalCT
		} else {
			if rem < take {
				take = rem
			}
			if totalBlocks == 0 && isLastTransportChunk && (off+take == len(chunkBytes)) {
				isFinal = true
			}
		}
		if !isFinal && blk == math.MaxUint32 {
			return blocksDone, bytesWritten, false, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "stream block counter overflow", synccrypto.ErrIntegrityMismatch)
		}
		pt, decErr := sc.OpenBlockAt(blk, isFinal, chunkBytes[off:off+take], ptBuf[:0])
		if decErr != nil {
			if isFinal {
				return blocksDone, bytesWritten, false, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decrypt final stream block", decErr)
			}
			return blocksDone, bytesWritten, false, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decrypt stream block", decErr)
		}
		if isFinal && off+take < len(chunkBytes) {
			return blocksDone, bytesWritten, false, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "trailing bytes after authenticated final block", synccrypto.ErrIntegrityMismatch)
		}
		if len(pt) > 0 {
			nw, werr := w.Write(pt)
			bytesWritten += int64(nw)
			if werr != nil {
				return blocksDone, bytesWritten, false, envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "write decrypted block", werr)
			}
		}
		off += take
		if isFinal {
			sawFinal = true
			blocksDone++
			break
		}
		blk++
		blocksDone++
	}
	return blocksDone, bytesWritten, sawFinal, nil
}

func (c *Client) openAndVerifySealedHeader(hdrBytes []byte) (*synccrypto.SealedHeaderOpenResult, error) {
	_, msgIDHex, err := synccrypto.ParseClearHeaderMsgID(hdrBytes)
	if err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeCryptoSignatureInvalid, false, 0, "parse sealed_header", err)
	}
	seen, err := c.keyStore.HasSeenMsgID(msgIDHex)
	if err != nil {
		return nil, err
	}
	if seen {
		return nil, envelope.NewError(envelope.ErrCodeMsgReplayDetected, false, 0, "msg_id already processed (replay rejected)", map[string]any{"msg_id": msgIDHex})
	}
	opened, err := synccrypto.Open0RTTHeader(c.deviceKeys, hdrBytes, func(senderID string) (ed25519.PublicKey, error) {
		card, err := c.keyStore.GetDevice(senderID)
		if err != nil || card == nil || card.Revoked {
			return nil, synccrypto.ErrUntrustedSender
		}
		pk, err := base64.RawURLEncoding.DecodeString(card.SignPK)
		if err != nil || len(pk) != ed25519.PublicKeySize {
			return nil, synccrypto.ErrInvalidKeyLength
		}
		return ed25519.PublicKey(pk), nil
	})
	if err != nil {
		if errors.Is(err, synccrypto.ErrUntrustedSender) {
			return nil, envelope.WrapError(envelope.ErrCodeDeviceUntrusted, false, 0, "sender device untrusted or revoked", err)
		}
		if errors.Is(err, synccrypto.ErrDecryptFailed) {
			return nil, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decrypt sealed_header", err)
		}
		return nil, envelope.WrapError(envelope.ErrCodeCryptoSignatureInvalid, false, 0, "verify sealed_header", err)
	}

	// ST-P1-7: Enforce Flow 2 SealedHeader.CreatedAt freshness window [max(localNow - 30*86400, watermark), localNow + 600].
	localNow := time.Now().Unix()
	minAllowed := localNow - int64(envelope.DefaultSeenMsgRetentionDays)*86400
	if wms, ok := c.keyStore.(replayWatermarkKeyStore); ok {
		if wm, werr := wms.GetReplayWatermark(); werr == nil && wm > minAllowed {
			minAllowed = wm
		}
	}
	maxAllowed := localNow + maxSealedHeaderFutureSkewSec
	if opened.CreatedAt < minAllowed || opened.CreatedAt > maxAllowed {
		opened.Zero()
		return nil, envelope.NewError(envelope.ErrCodeMsgReplayDetected, false, 0,
			"sealed_header created_at outside allowed freshness window",
			map[string]any{
				"msg_id":      opened.MsgID,
				"created_at":  opened.CreatedAt,
				"min_allowed": minAllowed,
				"max_allowed": maxAllowed,
			})
	}
	return opened, nil
}

// --- Shared decryption & verification helpers ---

func (c *Client) pullAndVerifyManifest(
	msgIDRaw [16]byte,
	msgIDHex string,
	p0Key [32]byte,
	p0NP [7]byte,
	p0Layout envelope.PartLayout,
	opened *synccrypto.SealedHeaderOpenResult,
	fetchChunk func(txIdx int) ([]byte, error),
) (*envelope.Manifest, [32]byte, error) {
	var zeroSHA [32]byte
	// Anti-OOM hard cap before allocating or downloading any part_id=0 chunks.
	if p0Layout.TotalBytes <= 0 || p0Layout.TotalBytes > envelope.MaxEncryptedManifestBytes || p0Layout.ChunkCount < 1 || p0Layout.ChunkCount > envelope.MaxManifestChunks {
		return nil, zeroSHA, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, fmt.Sprintf("part_id=0 layout out of bounds (bytes=%d chunks=%d)", p0Layout.TotalBytes, p0Layout.ChunkCount), nil)
	}
	sc, err := synccrypto.NewStreamCipher(p0Key, p0NP, msgIDRaw, 0)
	if err != nil {
		return nil, zeroSHA, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "init manifest stream cipher", err)
	}
	var padded bytes.Buffer
	defer func() {
		clear(padded.Bytes())
	}()
	var blkIdx uint32
	var encRead int64
	sawFinal := false
	for tx := 0; tx < p0Layout.ChunkCount; tx++ {
		if sawFinal {
			return nil, zeroSHA, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "manifest stream has trailing chunks after final block", synccrypto.ErrIntegrityMismatch)
		}
		chunkBytes, err := fetchChunk(tx)
		if err != nil {
			return nil, zeroSHA, err
		}
		encRead += int64(len(chunkBytes))
		if encRead > p0Layout.TotalBytes || encRead > envelope.MaxEncryptedManifestBytes {
			return nil, zeroSHA, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, "part_id=0 stream exceeded declared or maximum manifest byte budget", nil)
		}
		nBlk, _, isFin, err := decryptChunkIntoStream(sc, chunkBytes, blkIdx, 0, -1, tx == p0Layout.ChunkCount-1, &padded)
		if err != nil {
			return nil, zeroSHA, err
		}
		blkIdx += nBlk
		if isFin {
			sawFinal = true
			if tx != p0Layout.ChunkCount-1 {
				return nil, zeroSHA, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "manifest final block arrived before declared chunk_count", synccrypto.ErrIntegrityMismatch)
			}
		}
	}
	if !sawFinal {
		return nil, zeroSHA, envelope.NewError(envelope.ErrCodeStreamTruncated, false, 0, "manifest stream missing final block", nil)
	}
	if encRead != p0Layout.TotalBytes {
		return nil, zeroSHA, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, "part_id=0 encrypted byte total mismatch", nil)
	}
	rawManifest, err := synccrypto.UnpadManifest(padded.Bytes())
	if err != nil {
		return nil, zeroSHA, envelope.WrapError(envelope.ErrCodeStreamTruncated, false, 0, "unpad manifest", err)
	}
	rawSHA := sha256.Sum256(rawManifest)
	if opened != nil {
		if rawSHA != opened.ManifestSHA256 {
			clear(rawManifest)
			return nil, zeroSHA, envelope.NewError(envelope.ErrCodeCryptoSignatureInvalid, false, 0, "manifest SHA-256 does not match signed SealedHeader", nil)
		}
	}
	manifest, err := envelope.ParseManifest(rawManifest)
	clear(rawManifest)
	if err != nil {
		return nil, zeroSHA, err
	}
	if manifest.MsgID != msgIDHex {
		return nil, zeroSHA, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, "manifest msg_id mismatch", nil)
	}
	if opened != nil {
		if manifest.Sender.DeviceID != opened.SenderDeviceID {
			return nil, zeroSHA, envelope.NewError(envelope.ErrCodeCryptoSignatureInvalid, false, 0, "manifest sender.device_id does not match SealedHeader", nil)
		}
		if manifest.CreatedAt != opened.CreatedAt {
			return nil, zeroSHA, envelope.NewError(envelope.ErrCodeCryptoSignatureInvalid, false, 0, "manifest created_at does not match SealedHeader", nil)
		}
	}
	return manifest, rawSHA, nil
}

func ensureSafeRealDir(dir string) error {
	if fi, err := os.Lstat(dir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return envelope.NewError(envelope.ErrCodeStorageIO, false, 0, "temp directory must be a real directory, not a symlink", nil)
		}
	} else if !os.IsNotExist(err) {
		return envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "lstat temp dir", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "create temp dir", err)
	}
	_ = os.Chmod(dir, 0o700)
	return nil
}

func verifyFileSizeAndSHA256(path string, wantSize int64, wantSHAHex string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() != wantSize {
		return false
	}
	rf, err := os.Open(path)
	if err != nil {
		return false
	}
	defer rf.Close()
	h := sha256.New()
	gotSize, err := io.CopyBuffer(h, rf, make([]byte, 64*1024))
	if err != nil || gotSize != wantSize {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == wantSHAHex
}

func (c *Client) pullAndVerifyBlobs(
	ctx context.Context,
	itemID string,
	msgIDRaw [16]byte,
	manifest *envelope.Manifest,
	partMap map[uint32]envelope.PartLayout,
	blocksPerChunk int,
	totalBytes int64,
	doneBytes *int64,
	mode string,
	fetchChunk func(partID uint32, txIdx int) ([]byte, error),
	onProgress func(envelope.TransferEvent),
) ([]envelope.ReceivedBlob, error) {
	if len(manifest.Blobs) == 0 {
		return nil, nil
	}

	// ST-P0-2: Validate ALL wire PartLayouts against signed Manifest.Blobs[i] BEFORE creating files or streaming chunks!
	for _, blob := range manifest.Blobs {
		layout, ok := partMap[blob.PartID]
		if !ok {
			return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, fmt.Sprintf("missing part layout for part_id=%d", blob.PartID), nil)
		}
		wantEnc := synccrypto.EncryptedPartSize(blob.Size)
		totalBlocks := synccrypto.TotalBlocks(blob.Size)
		if layout.TotalBytes != wantEnc {
			return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0,
				fmt.Sprintf("part_id=%d wire total_bytes (%d) does not match signed manifest size (%d -> %d)", blob.PartID, layout.TotalBytes, blob.Size, wantEnc), nil)
		}
		if layout.ChunkCount < 1 || int64(layout.ChunkCount) > int64(totalBlocks) {
			return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0,
				fmt.Sprintf("part_id=%d wire chunk_count (%d) out of valid range 1..%d", blob.PartID, layout.ChunkCount, totalBlocks), nil)
		}
		if blocksPerChunk > 0 {
			wantChunks := synccrypto.TransportChunkCount(wantEnc, blocksPerChunk)
			if layout.ChunkCount != wantChunks {
				return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0,
					fmt.Sprintf("part_id=%d wire chunk_count (%d) does not match expected %d", blob.PartID, layout.ChunkCount, wantChunks), nil)
			}
		}
	}

	if err := ensureSafeRealDir(c.tempDir); err != nil {
		return nil, err
	}
	msgDir := filepath.Join(c.tempDir, manifest.MsgID)
	if err := ensureSafeRealDir(msgDir); err != nil {
		return nil, err
	}
	c.trackMsgDir(msgDir)

	out := make([]envelope.ReceivedBlob, 0, len(manifest.Blobs))
	for _, blob := range manifest.Blobs {
		if err := ctx.Err(); err != nil {
			return nil, envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "download cancelled", err)
		}
		layout := partMap[blob.PartID]
		wantEnc := synccrypto.EncryptedPartSize(blob.Size)
		totalBlocks := synccrypto.TotalBlocks(blob.Size)

		partPath := filepath.Join(msgDir, fmt.Sprintf("part_%d.part", blob.PartID))
		verifiedPath := filepath.Join(msgDir, fmt.Sprintf("part_%d.verified", blob.PartID))

		// ST-P1-13: On multi-part Mode B resume, skip re-downloading blobs already verified on disk!
		if mode == "spool" && verifyFileSizeAndSHA256(verifiedPath, blob.Size, blob.SHA256) {
			_ = c.keyStore.DeleteCheckpoint("recv", manifest.MsgID, blob.PartID)
			*doneBytes += layout.TotalBytes
			if onProgress != nil {
				onProgress(envelope.TransferEvent{
					Type:           "event",
					Event:          "transfer_progress",
					Stage:          "transferring",
					Direction:      "recv",
					Mode:           mode,
					MsgID:          manifest.MsgID,
					PartID:         blob.PartID,
					PartsTotal:     len(partMap),
					BytesDone:      *doneBytes,
					BytesTotal:     totalBytes,
					PartBytesDone:  layout.TotalBytes,
					PartBytesTotal: layout.TotalBytes,
					Resumed:        true,
					TS:             time.Now().Unix(),
				})
			}
			out = append(out, envelope.ReceivedBlob{
				Descriptor: blob,
				SafePath:   verifiedPath,
				SafeName:   envelope.SanitizeFilename(blob.Name),
			})
			continue
		}

		rawKey, err := base64.RawURLEncoding.DecodeString(blob.Key)
		if err != nil || len(rawKey) != 32 {
			clear(rawKey)
			_ = os.RemoveAll(msgDir)
			return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, "invalid blob key", nil)
		}
		encKey, np, err := synccrypto.DeriveBlobPartKeys(msgIDRaw, blob.PartID, rawKey)
		clear(rawKey)
		if err != nil {
			_ = os.RemoveAll(msgDir)
			return nil, err
		}
		sc, err := synccrypto.NewStreamCipher(encKey, np, msgIDRaw, blob.PartID)
		clear(encKey[:])
		if err != nil {
			_ = os.RemoveAll(msgDir)
			return nil, err
		}

		if fi, lerr := os.Lstat(partPath); lerr == nil && !fi.Mode().IsRegular() {
			_ = os.RemoveAll(msgDir)
			return nil, envelope.NewError(envelope.ErrCodeStorageIO, false, 0, "refusing non-regular temp part file", nil)
		}

		// ST-P2-12 & ST-Opt-5: Check resumable checkpoint (strictly NextTxIdx < ChunkCount; promote directly if complete).
		startTx := 0
		var blkIdx uint32
		resumed := false
		if mode == "spool" {
			if cp, _ := c.keyStore.GetCheckpoint("recv", manifest.MsgID, blob.PartID); cp != nil && (cp.ItemID == "" || cp.ItemID == itemID) {
				if cp.NextTxIdx == layout.ChunkCount && verifyFileSizeAndSHA256(partPath, blob.Size, blob.SHA256) {
					_ = c.keyStore.DeleteCheckpoint("recv", manifest.MsgID, blob.PartID)
					_ = os.Remove(verifiedPath)
					if err := envelope.RenameWithRetry(partPath, verifiedPath); err != nil {
						_ = os.RemoveAll(msgDir)
						return nil, envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "atomic finalize verified blob", err)
					}
					*doneBytes += layout.TotalBytes
					if onProgress != nil {
						onProgress(envelope.TransferEvent{
							Type:           "event",
							Event:          "transfer_progress",
							Stage:          "transferring",
							Direction:      "recv",
							Mode:           mode,
							MsgID:          manifest.MsgID,
							PartID:         blob.PartID,
							PartsTotal:     len(partMap),
							BytesDone:      *doneBytes,
							BytesTotal:     totalBytes,
							PartBytesDone:  layout.TotalBytes,
							PartBytesTotal: layout.TotalBytes,
							Resumed:        true,
							TS:             time.Now().Unix(),
						})
					}
					out = append(out, envelope.ReceivedBlob{
						Descriptor: blob,
						SafePath:   verifiedPath,
						SafeName:   envelope.SanitizeFilename(blob.Name),
					})
					continue
				}
				if cp.NextTxIdx > 0 && cp.NextTxIdx < layout.ChunkCount && cp.NextBlockIdx > 0 && cp.NextBlockIdx < totalBlocks {
					if st, statErr := os.Stat(partPath); statErr == nil && st.Mode().IsRegular() && st.Size() == int64(cp.NextBlockIdx)*synccrypto.ChunkPlaintextMax {
						startTx = cp.NextTxIdx
						blkIdx = cp.NextBlockIdx
						resumed = true
					}
				}
			}
		}

		openFlags := os.O_CREATE | os.O_WRONLY
		if !resumed {
			openFlags |= os.O_TRUNC
		}
		f, err := os.OpenFile(partPath, openFlags, 0o600)
		if err != nil {
			return nil, envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "open temp blob file", err)
		}
		_ = f.Chmod(0o600)
		if resumed {
			if _, err := f.Seek(0, io.SeekEnd); err != nil {
				_ = f.Close()
				return nil, envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "seek temp blob file", err)
			}
		}

		sawFinal := false
		var partDone int64
		if resumed {
			// ST-Opt-5: Seed resumed progress counters with already-verified ciphertext blocks.
			partDone = int64(blkIdx) * synccrypto.ChunkCiphertextMax
			*doneBytes += partDone
		}

		for tx := startTx; tx < layout.ChunkCount; tx++ {
			if sawFinal {
				_ = f.Close()
				_ = os.RemoveAll(msgDir)
				_ = c.keyStore.DeleteCheckpoint("recv", manifest.MsgID, blob.PartID)
				return nil, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "blob stream has trailing chunks after final block", synccrypto.ErrIntegrityMismatch)
			}
			chunkBytes, err := fetchChunk(blob.PartID, tx)
			if err != nil {
				_ = f.Close()
				if mode == "spool" && tx > 0 {
					return nil, envelope.WrapError(envelope.ErrCodeInterruptedResumable, true, 0, "blob download interrupted with checkpoint saved", err)
				}
				return nil, err
			}
			if partDone+int64(len(chunkBytes)) > wantEnc {
				_ = f.Close()
				_ = os.RemoveAll(msgDir)
				_ = c.keyStore.DeleteCheckpoint("recv", manifest.MsgID, blob.PartID)
				return nil, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "blob stream exceeded declared encrypted byte size", synccrypto.ErrIntegrityMismatch)
			}
			nBlk, _, isFin, err := decryptChunkIntoStream(sc, chunkBytes, blkIdx, totalBlocks, blob.Size, tx == layout.ChunkCount-1, f)
			if err != nil {
				_ = f.Close()
				_ = os.RemoveAll(msgDir)
				_ = c.keyStore.DeleteCheckpoint("recv", manifest.MsgID, blob.PartID)
				return nil, err
			}
			blkIdx += nBlk
			partDone += int64(len(chunkBytes))
			*doneBytes += int64(len(chunkBytes))

			if isFin {
				sawFinal = true
				if tx != layout.ChunkCount-1 {
					_ = f.Close()
					_ = os.RemoveAll(msgDir)
					_ = c.keyStore.DeleteCheckpoint("recv", manifest.MsgID, blob.PartID)
					return nil, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "blob final block arrived before declared chunk_count", synccrypto.ErrIntegrityMismatch)
				}
			}
			if mode == "spool" && tx+1 < layout.ChunkCount {
				_ = c.keyStore.PutCheckpoint(envelope.TransferCheckpoint{
					Direction:    "recv",
					MsgID:        manifest.MsgID,
					ItemID:       itemID,
					PartID:       blob.PartID,
					NextTxIdx:    tx + 1,
					NextBlockIdx: blkIdx,
					ExpiresAt:    time.Now().Unix() + recvCheckpointTTLSec,
				})
			}
			if onProgress != nil {
				onProgress(envelope.TransferEvent{
					Type:           "event",
					Event:          "transfer_progress",
					Stage:          "transferring",
					Direction:      "recv",
					Mode:           mode,
					MsgID:          manifest.MsgID,
					PartID:         blob.PartID,
					PartsTotal:     len(partMap),
					BytesDone:      *doneBytes,
					BytesTotal:     totalBytes,
					PartBytesDone:  partDone,
					PartBytesTotal: layout.TotalBytes,
					Resumed:        resumed,
					TS:             time.Now().Unix(),
				})
			}
		}
		_ = f.Close()
		if !sawFinal || partDone != wantEnc || blkIdx != totalBlocks {
			_ = os.RemoveAll(msgDir)
			_ = c.keyStore.DeleteCheckpoint("recv", manifest.MsgID, blob.PartID)
			return nil, envelope.NewError(envelope.ErrCodeStreamTruncated, false, 0, "blob stream missing authenticated final block or incomplete", nil)
		}

		// Verify exact plaintext size and SHA-256 on disk BEFORE exposing verified SafePath via atomic rename!
		if !verifyFileSizeAndSHA256(partPath, blob.Size, blob.SHA256) {
			_ = os.RemoveAll(msgDir)
			_ = c.keyStore.DeleteCheckpoint("recv", manifest.MsgID, blob.PartID)
			return nil, envelope.NewError(envelope.ErrCodeHashMismatch, false, 0, fmt.Sprintf("part_id=%d size/sha256 mismatch", blob.PartID), nil)
		}
		_ = c.keyStore.DeleteCheckpoint("recv", manifest.MsgID, blob.PartID)
		_ = os.Remove(verifiedPath)
		if err := envelope.RenameWithRetry(partPath, verifiedPath); err != nil {
			_ = os.RemoveAll(msgDir)
			return nil, envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "atomic finalize verified blob", err)
		}

		out = append(out, envelope.ReceivedBlob{
			Descriptor: blob,
			SafePath:   verifiedPath,
			SafeName:   envelope.SanitizeFilename(blob.Name),
		})
	}
	return out, nil
}
