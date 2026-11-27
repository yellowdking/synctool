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
	"os"
	"path/filepath"
	"time"

	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

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
	msgIDHex := hex.EncodeToString(msgIDRaw[:])

	appID := input.AppID
	if appID == "" {
		appID = c.appID
	}
	schema := input.Schema
	if schema == "" {
		schema = "generic.parcel.v1"
	}
	createdAt := c.effectiveUnixNow()

	blobs := make([]preparedBlob, 0, len(input.Blobs))
	descs := make([]envelope.BlobDescriptor, 0, len(input.Blobs))
	for i, bi := range input.Blobs {
		partID := uint32(i + 1)
		rc, size, err := bi.OpenStream()
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		n, copyErr := io.CopyBuffer(h, rc, make([]byte, 64*1024))
		_ = rc.Close()
		if copyErr != nil {
			return nil, envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "hash blob stream", copyErr)
		}
		if size >= 0 && n != size {
			size = n
		}
		bkSlice, err := synccrypto.GenerateRandomBytes(32)
		if err != nil {
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
		return nil, err
	}
	manifestPad, err := synccrypto.PadManifest(manifestUTF8)
	if err != nil {
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
// verifies is_final on the final block, and writes verified plaintext to w.
func decryptChunkIntoStream(
	sc *synccrypto.StreamCipher,
	chunkBytes []byte,
	startBlockIdx uint32,
	totalBlocks uint32,
	isLastTransportChunk bool,
	w io.Writer,
) (blocksDone uint32, bytesWritten int64, sawFinal bool, err error) {
	if len(chunkBytes) == 0 {
		return 0, 0, false, envelope.NewError(envelope.ErrCodeStreamTruncated, false, 0, "empty transport chunk", nil)
	}
	off := 0
	blk := startBlockIdx
	ptBuf := make([]byte, 0, synccrypto.ChunkPlaintextMax)
	for off < len(chunkBytes) {
		rem := len(chunkBytes) - off
		take := synccrypto.ChunkCiphertextMax
		if rem < take {
			take = rem
		}
		isFinal := false
		if totalBlocks > 0 {
			isFinal = (blk == totalBlocks-1)
		} else if isLastTransportChunk && (off+take == len(chunkBytes)) {
			isFinal = true
		}
		pt, decErr := sc.OpenBlockAt(blk, isFinal, chunkBytes[off:off+take], ptBuf[:0])
		if decErr != nil {
			if isFinal {
				return blocksDone, bytesWritten, false, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decrypt final stream block", decErr)
			}
			return blocksDone, bytesWritten, false, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decrypt stream block", decErr)
		}
		if len(pt) > 0 {
			nw, werr := w.Write(pt)
			bytesWritten += int64(nw)
			if werr != nil {
				return blocksDone, bytesWritten, false, envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "write decrypted block", werr)
			}
		}
		if isFinal {
			sawFinal = true
		}
		off += take
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
	var blkIdx uint32
	sawFinal := false
	for tx := 0; tx < p0Layout.ChunkCount; tx++ {
		chunkBytes, err := fetchChunk(tx)
		if err != nil {
			return nil, zeroSHA, err
		}
		if int64(padded.Len()+len(chunkBytes)) > envelope.MaxEncryptedManifestBytes {
			return nil, zeroSHA, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, "part_id=0 stream exceeded maximum manifest byte budget", nil)
		}
		nBlk, _, isFin, err := decryptChunkIntoStream(sc, chunkBytes, blkIdx, 0, tx == p0Layout.ChunkCount-1, &padded)
		if err != nil {
			return nil, zeroSHA, err
		}
		blkIdx += nBlk
		if isFin {
			sawFinal = true
		}
	}
	if !sawFinal {
		return nil, zeroSHA, envelope.NewError(envelope.ErrCodeStreamTruncated, false, 0, "manifest stream missing final block", nil)
	}
	rawManifest, err := synccrypto.UnpadManifest(padded.Bytes())
	if err != nil {
		return nil, zeroSHA, envelope.WrapError(envelope.ErrCodeStreamTruncated, false, 0, "unpad manifest", err)
	}
	rawSHA := sha256.Sum256(rawManifest)
	if opened != nil {
		if rawSHA != opened.ManifestSHA256 {
			return nil, zeroSHA, envelope.NewError(envelope.ErrCodeCryptoSignatureInvalid, false, 0, "manifest SHA-256 does not match signed SealedHeader", nil)
		}
	}
	manifest, err := envelope.ParseManifest(rawManifest)
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

func (c *Client) pullAndVerifyBlobs(
	ctx context.Context,
	itemID string,
	msgIDRaw [16]byte,
	manifest *envelope.Manifest,
	partMap map[uint32]envelope.PartLayout,
	totalBytes int64,
	doneBytes *int64,
	mode string,
	fetchChunk func(partID uint32, txIdx int) ([]byte, error),
	onProgress func(envelope.TransferEvent),
) ([]envelope.ReceivedBlob, error) {
	if len(manifest.Blobs) == 0 {
		return nil, nil
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
		layout, ok := partMap[blob.PartID]
		if !ok || layout.ChunkCount <= 0 {
			_ = os.RemoveAll(msgDir)
			return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, fmt.Sprintf("missing part layout for part_id=%d", blob.PartID), nil)
		}
		rawKey, err := base64.RawURLEncoding.DecodeString(blob.Key)
		if err != nil || len(rawKey) != 32 {
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

		partPath := filepath.Join(msgDir, fmt.Sprintf("part_%d.part", blob.PartID))
		verifiedPath := filepath.Join(msgDir, fmt.Sprintf("part_%d.verified", blob.PartID))
		if fi, lerr := os.Lstat(partPath); lerr == nil && !fi.Mode().IsRegular() {
			_ = os.RemoveAll(msgDir)
			return nil, envelope.NewError(envelope.ErrCodeStorageIO, false, 0, "refusing non-regular temp part file", nil)
		}
		// Check resumable checkpoint (Mode B spool).
		startTx := 0
		var blkIdx uint32
		resumed := false
		if mode == "spool" {
			if cp, _ := c.keyStore.GetCheckpoint("recv", manifest.MsgID, blob.PartID); cp != nil && cp.NextTxIdx > 0 && cp.NextTxIdx <= layout.ChunkCount {
				if st, statErr := os.Stat(partPath); statErr == nil && st.Size() == int64(cp.NextBlockIdx)*synccrypto.ChunkPlaintextMax {
					startTx = cp.NextTxIdx
					blkIdx = cp.NextBlockIdx
					resumed = true
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

		totalBlocks := synccrypto.TotalBlocks(blob.Size)
		sawFinal := false
		var partDone int64
		for tx := startTx; tx < layout.ChunkCount; tx++ {
			chunkBytes, err := fetchChunk(blob.PartID, tx)
			if err != nil {
				_ = f.Close()
				if mode == "spool" && tx > 0 {
					return nil, envelope.WrapError(envelope.ErrCodeInterruptedResumable, true, 0, "blob download interrupted with checkpoint saved", err)
				}
				return nil, err
			}
			nBlk, _, isFin, err := decryptChunkIntoStream(sc, chunkBytes, blkIdx, totalBlocks, tx == layout.ChunkCount-1, f)
			if err != nil {
				_ = f.Close()
				_ = os.RemoveAll(msgDir)
				_ = c.keyStore.DeleteCheckpoint("recv", manifest.MsgID, blob.PartID)
				return nil, err
			}
			blkIdx += nBlk
			if isFin {
				sawFinal = true
			}
			partDone += int64(len(chunkBytes))
			*doneBytes += int64(len(chunkBytes))
			if mode == "spool" {
				_ = c.keyStore.PutCheckpoint(envelope.TransferCheckpoint{
					Direction:    "recv",
					MsgID:        manifest.MsgID,
					ItemID:       itemID,
					PartID:       blob.PartID,
					NextTxIdx:    tx + 1,
					NextBlockIdx: blkIdx,
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
		if !sawFinal {
			_ = os.RemoveAll(msgDir)
			return nil, envelope.NewError(envelope.ErrCodeStreamTruncated, false, 0, "blob stream missing authenticated final block", nil)
		}

		// Verify exact plaintext size and SHA-256 on disk BEFORE exposing verified SafePath via atomic rename!
		rf, err := os.Open(partPath)
		if err != nil {
			return nil, envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "reopen blob for sha256 verify", err)
		}
		h := sha256.New()
		gotSize, copyErr := io.CopyBuffer(h, rf, make([]byte, 64*1024))
		_ = rf.Close()
		if copyErr != nil {
			return nil, envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "hash verified blob", copyErr)
		}
		gotSHA := hex.EncodeToString(h.Sum(nil))
		if gotSize != blob.Size || gotSHA != blob.SHA256 {
			_ = os.RemoveAll(msgDir)
			_ = c.keyStore.DeleteCheckpoint("recv", manifest.MsgID, blob.PartID)
			return nil, envelope.NewError(envelope.ErrCodeHashMismatch, false, 0, fmt.Sprintf("part_id=%d size/sha256 mismatch", blob.PartID), nil)
		}
		_ = c.keyStore.DeleteCheckpoint("recv", manifest.MsgID, blob.PartID)
		_ = os.Remove(verifiedPath)
		if err := os.Rename(partPath, verifiedPath); err != nil {
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
