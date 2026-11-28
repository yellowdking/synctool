package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

const (
	maxInitialPipePeerTimeouts   = 12
	maxMidStreamPipePeerTimeouts = 2
)

// --- Room signaling helpers ---

type roomCreateResp struct {
	RoomID      string `json:"room_id"`
	PipeID      string `json:"pipe_id"`
	SenderToken string `json:"sender_token"`
	ExpiresAt   int64  `json:"expires_at"`
	Seq         int    `json:"seq"`
}

type roomMessageWire struct {
	Seq    int    `json:"seq"`
	From   string `json:"from"`
	Kind   string `json:"kind"`
	MsgB64 string `json:"msg_b64"`
}

type roomJoinResp struct {
	RoomID        string            `json:"room_id"`
	PipeID        string            `json:"pipe_id"`
	ReceiverToken string            `json:"receiver_token"`
	ExpiresAt     int64             `json:"expires_at"`
	Seq           int               `json:"seq"`
	Messages      []roomMessageWire `json:"messages"`
}

type roomPollResp struct {
	State    string            `json:"state"`
	Seq      int               `json:"seq"`
	Messages []roomMessageWire `json:"messages"`
	Reason   string            `json:"reason"`
}

func (c *Client) createRoom(ctx context.Context, roomID string, ttlSec int, initialMsg []byte) (*roomCreateResp, error) {
	if ttlSec <= 0 {
		ttlSec = 300
	}
	body := map[string]any{
		"room_id": roomID,
		"ttl_sec": ttlSec,
	}
	if len(initialMsg) > 0 {
		body["initial_msg_b64"] = base64.RawURLEncoding.EncodeToString(initialMsg)
	}
	resp, err := c.doControl(ctx, http.MethodPost, "/v1/rooms", body, reqOptions{})
	if err != nil {
		return nil, err
	}
	var out roomCreateResp
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeBadRequest, false, resp.StatusCode, "decode room create", err)
	}
	return &out, nil
}

func (c *Client) joinRoom(ctx context.Context, roomID string) (*roomJoinResp, error) {
	resp, err := c.doControl(ctx, http.MethodPost, "/v1/rooms/"+roomID+"/join", map[string]any{}, reqOptions{})
	if err != nil {
		return nil, err
	}
	var out roomJoinResp
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeBadRequest, false, resp.StatusCode, "decode room join", err)
	}
	return &out, nil
}

func (c *Client) postRoomMessage(ctx context.Context, roomID, roomToken, kind string, payload []byte) (int, error) {
	body := map[string]string{
		"kind":    kind,
		"msg_b64": base64.RawURLEncoding.EncodeToString(payload),
	}
	resp, err := c.doControl(ctx, http.MethodPost, "/v1/rooms/"+roomID+"/messages", body, reqOptions{
		RoomToken: roomToken,
	})
	if err != nil {
		return 0, err
	}
	var out struct {
		Seq int `json:"seq"`
	}
	_ = json.Unmarshal(resp.Body, &out)
	return out.Seq, nil
}

func (c *Client) closeRoom(ctx context.Context, roomID, roomToken, reason string) {
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, _ = c.doControl(closeCtx, http.MethodPost, "/v1/rooms/"+roomID+"/close", map[string]string{
		"reason": reason,
	}, reqOptions{RoomToken: roomToken})
}

func classifyRoomCtxErr(ctx context.Context, closeCtx context.Context) error {
	if ctx != nil && ctx.Err() == context.DeadlineExceeded {
		return envelope.WrapError(envelope.ErrCodeHandshakeTimeout, true, 0, "timed out waiting for peer in room", context.DeadlineExceeded)
	}
	if closeCtx != nil && closeCtx.Err() != nil {
		return envelope.NewError(envelope.ErrCodeCancelled, false, 0, "client closed", nil)
	}
	if ctx != nil && ctx.Err() != nil {
		return envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "waiting for peer cancelled", ctx.Err())
	}
	return nil
}

// waitForPeerRoomMessage waits via SSE (with transparent Long-Poll fallback, 60s SSE idle timeout,
// 250ms..5s backoff, and immediate security/auth error rethrow) for the next message from expectedFrom.
func (c *Client) waitForPeerRoomMessage(ctx context.Context, roomID, roomToken, expectedFrom string, sinceSeq int) (roomMessageWire, int, error) {
	curSince := sinceSeq
	usePoll := false
	backoffAttempt := 0
	var lastFastReconnect time.Time

	for {
		if cerr := classifyRoomCtxErr(ctx, c.closeCtx); cerr != nil {
			return roomMessageWire{}, curSince, cerr
		}
		if !usePoll {
			path := fmt.Sprintf("/v1/rooms/%s/events?since=%d&mode=sse", roomID, curSince)
			streamBody, err := c.openSSEStreamWithIdleTimeout(ctx, path, reqOptions{
				RoomToken: roomToken,
			})
			if err != nil {
				if cerr := classifyRoomCtxErr(ctx, c.closeCtx); cerr != nil {
					return roomMessageWire{}, curSince, cerr
				}
				if isFatalWatchOrRoomErr(err) {
					return roomMessageWire{}, curSince, err
				}
				if se, ok := envelope.AsSyncError(err); ok && (se.Code == envelope.ErrCodeRoomBurned || se.Code == envelope.ErrCodeNotFound || se.Code == envelope.ErrCodeInvalidState) {
					return roomMessageWire{}, curSince, se
				}
				if serr := sleepWithBackoff(ctx, backoffAttempt, err); serr != nil {
					return roomMessageWire{}, curSince, classifyRoomCtxErr(ctx, c.closeCtx)
				}
				backoffAttempt++
				usePoll = true
				continue
			}

			var found *roomMessageWire
			var termErr error
			sawReconnect := false
			sawAnyEvent := false
			parseErr := parseSSEStream(streamBody, func(ev sseEvent) error {
				sawAnyEvent = true
				switch ev.Event {
				case "message":
					var m roomMessageWire
					if err := json.Unmarshal([]byte(ev.Data), &m); err != nil {
						return nil
					}
					if m.Seq > curSince {
						curSince = m.Seq
					}
					if m.From == expectedFrom {
						found = &m
						return errStopSSE
					}
				case "burned":
					termErr = envelope.NewError(envelope.ErrCodeRoomBurned, false, 410, "room burned by peer", nil)
					return errStopSSE
				case "closed":
					termErr = envelope.NewError(envelope.ErrCodeNotFound, false, 404, "room closed by peer", nil)
					return errStopSSE
				case "reconnect":
					sawReconnect = true
					return errStopSSE
				}
				return nil
			})
			_ = streamBody.Close()

			if found != nil {
				return *found, curSince, nil
			}
			if termErr != nil {
				return roomMessageWire{}, curSince, termErr
			}
			if cerr := classifyRoomCtxErr(ctx, c.closeCtx); cerr != nil {
				return roomMessageWire{}, curSince, cerr
			}
			if sawReconnect {
				backoffAttempt = 0
				now := time.Now()
				if !lastFastReconnect.IsZero() && now.Sub(lastFastReconnect) < 100*time.Millisecond {
					if serr := sleepWithBackoff(ctx, 0, nil); serr != nil {
						return roomMessageWire{}, curSince, classifyRoomCtxErr(ctx, c.closeCtx)
					}
				}
				lastFastReconnect = now
				continue
			}
			// Immediate unexpected EOF or stream error -> backoff and try Long-Poll fallback.
			if parseErr != nil || !sawAnyEvent {
				usePoll = true
			}
			if serr := sleepWithBackoff(ctx, backoffAttempt, parseErr); serr != nil {
				return roomMessageWire{}, curSince, classifyRoomCtxErr(ctx, c.closeCtx)
			}
			backoffAttempt++
			continue
		}

		// Long-poll fallback
		path := fmt.Sprintf("/v1/rooms/%s/events?since=%d&mode=poll&wait_sec=20", roomID, curSince)
		resp, err := c.doControl(ctx, http.MethodGet, path, nil, reqOptions{RoomToken: roomToken})
		if err != nil {
			if cerr := classifyRoomCtxErr(ctx, c.closeCtx); cerr != nil {
				return roomMessageWire{}, curSince, cerr
			}
			if isFatalWatchOrRoomErr(err) {
				return roomMessageWire{}, curSince, err
			}
			if se, ok := envelope.AsSyncError(err); ok && (se.Code == envelope.ErrCodeRoomBurned || se.Code == envelope.ErrCodeNotFound || se.Code == envelope.ErrCodeInvalidState || !se.Retryable) {
				return roomMessageWire{}, curSince, se
			}
			if serr := sleepWithBackoff(ctx, backoffAttempt, err); serr != nil {
				return roomMessageWire{}, curSince, classifyRoomCtxErr(ctx, c.closeCtx)
			}
			backoffAttempt++
			continue
		}
		backoffAttempt = 0
		var pr roomPollResp
		if err := json.Unmarshal(resp.Body, &pr); err != nil {
			return roomMessageWire{}, curSince, envelope.WrapError(envelope.ErrCodeBadRequest, false, resp.StatusCode, "decode room poll", err)
		}
		for _, m := range pr.Messages {
			if m.Seq > curSince {
				curSince = m.Seq
			}
			if m.From == expectedFrom {
				return m, curSince, nil
			}
		}
		if pr.State == "burned" {
			return roomMessageWire{}, curSince, envelope.NewError(envelope.ErrCodeRoomBurned, false, 410, "room burned: "+pr.Reason, nil)
		}
		if pr.State == "closed" {
			return roomMessageWire{}, curSince, envelope.NewError(envelope.ErrCodeNotFound, false, 404, "room closed: "+pr.Reason, nil)
		}
		// Try SSE again on next cycle if poll returned cleanly with no messages yet.
		usePoll = false
	}
}

var errStopSSE = errors.New("stop sse")

// --- Flow 1 One-Shot Send & Receive (Mode A Zero-Disk Streaming) ---

// StartOneShotSend runs a Flow 1 one-shot transfer over Mode A streaming pipe.
func (c *Client) StartOneShotSend(ctx context.Context, parcel envelope.ParcelInput, opts PairOptions) (*SendResult, error) {
	done, err := c.beginOp()
	if err != nil {
		return nil, err
	}
	defer done()

	caps, err := c.capabilitiesInternal(ctx)
	if err != nil {
		return nil, err
	}
	blocksPerChunk := caps.Streaming.BlocksPerChunk
	if blocksPerChunk <= 0 {
		blocksPerChunk = 16
	}
	prep, err := c.prepareParcel(parcel, blocksPerChunk)
	if err != nil {
		return nil, err
	}
	defer prep.Zero()

	sess, err := c.runInitiatorHandshake(ctx, synccrypto.PurposeOneshot, opts)
	if err != nil {
		return nil, err
	}
	defer sess.HS.Zero()

	p0Key, p0NP, err := synccrypto.DeriveOneshotPart0Keys(sess.HS.SessionKey[:], prep.MsgIDRaw[:])
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "cancelled")
		return nil, err
	}
	defer clear(p0Key[:])

	ctrlKey, ctrlNP, err := synccrypto.DerivePipeCtrlKeys(sess.HS.TH[:], sess.HS.SessionKey[:])
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "cancelled")
		return nil, err
	}
	defer clear(ctrlKey[:])

	// Send encrypted pipe_start (ctrl_seq = 0)
	startCmd, _ := json.Marshal(envelope.PipeStartPayload{
		Op:             "pipe_start",
		MsgID:          prep.MsgID,
		BlocksPerChunk: blocksPerChunk,
		Parts:          prep.Parts,
	})
	startCT, err := synccrypto.SealPipeCtrl(ctrlKey, ctrlNP, sess.HS.TH[:], 0, startCmd)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "cancelled")
		return nil, err
	}
	ctrlFrame, _ := json.Marshal(pipeCtrlWire{CtrlSeq: 0, CT: base64.RawURLEncoding.EncodeToString(startCT)})
	seq, err := c.postRoomMessage(ctx, sess.RoomID, sess.Token, "control", ctrlFrame)
	if err != nil {
		return nil, err
	}
	sess.LastSeq = seq

	if err := c.uploadAllPipeParts(ctx, sess.PipeID, sess.Token, prep, p0Key, p0NP, blocksPerChunk, opts.OnProgress); err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "cancelled")
		return nil, err
	}

	// Wait for receiver's encrypted pipe_ack (ctrl_seq = 1)
	ackWire, _, err := c.waitForPeerRoomMessage(ctx, sess.RoomID, sess.Token, "receiver", sess.LastSeq)
	if err != nil {
		return nil, err
	}
	ackRaw, err := base64.RawURLEncoding.DecodeString(ackWire.MsgB64)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decode pipe_ack", nil)
	}
	var cw pipeCtrlWire
	if err := json.Unmarshal(ackRaw, &cw); err != nil || cw.CtrlSeq != 1 {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "invalid pipe_ack ctrl_seq", nil)
	}
	ctBytes, err := base64.RawURLEncoding.DecodeString(cw.CT)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decode pipe_ack ct", nil)
	}
	ptAck, err := synccrypto.OpenPipeCtrl(ctrlKey, ctrlNP, sess.HS.TH[:], cw.CtrlSeq, ctBytes)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decrypt pipe_ack", err)
	}
	var ack envelope.PipeAckPayload
	if err := json.Unmarshal(ptAck, &ack); err != nil || ack.Op != "pipe_ack" || ack.MsgID != prep.MsgID {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "invalid pipe_ack payload", nil)
	}
	c.closeRoom(ctx, sess.RoomID, sess.Token, "completed")
	return &SendResult{
		Mode:       "pipe",
		MsgID:      prep.MsgID,
		RoomID:     sess.RoomID,
		TotalBytes: prep.TotalEnc,
	}, nil
}

func (c *Client) uploadAllPipeParts(
	ctx context.Context,
	pipeID, senderToken string,
	prep *preparedParcel,
	p0Key [32]byte,
	p0NP [7]byte,
	blocksPerChunk int,
	onProgress func(envelope.TransferEvent),
) error {
	var totalSent int64
	emitProgress := func(partID uint32, partDone, partTotal int64) {
		if onProgress == nil {
			return
		}
		onProgress(envelope.TransferEvent{
			Type:           "event",
			Event:          "transfer_progress",
			Stage:          "transferring",
			Direction:      "send",
			Mode:           "pipe",
			MsgID:          prep.MsgID,
			PartID:         partID,
			PartsTotal:     len(prep.Parts),
			BytesDone:      totalSent,
			BytesTotal:     prep.TotalEnc,
			PartBytesDone:  partDone,
			PartBytesTotal: partTotal,
			TS:             time.Now().Unix(),
		})
	}

	putPipeChunk := func(partID uint32, txIdx int, data []byte) error {
		path := fmt.Sprintf("/v1/pipe/%s/parts/%d/chunks/%d", pipeID, partID, txIdx)
		chunkCopy := data
		maxRetries := maxMidStreamPipePeerTimeouts
		if partID == 0 && txIdx == 0 {
			maxRetries = maxInitialPipePeerTimeouts
		}
		timeouts := 0
		for {
			_, err := c.doSignedWithSkewRetry(ctx, http.MethodPut, path, nil, reqOptions{
				ContentType: "application/octet-stream",
				RoomToken:   senderToken,
				IsStream:    true,
				StreamLen:   int64(len(chunkCopy)),
				StreamFactory: func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(chunkCopy)), nil
				},
			})
			if err != nil && envelope.IsCode(err, envelope.ErrCodePipePeerTimeout) && ctx.Err() == nil && timeouts < maxRetries {
				timeouts++
				select {
				case <-ctx.Done():
					return envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "pipe upload cancelled", ctx.Err())
				case <-time.After(50 * time.Millisecond):
					continue
				}
			}
			return err
		}
	}

	// Upload part_id = 0 (Manifest)
	var p0Done int64
	p0Total := prep.Parts[0].TotalBytes
	if err := streamUploadPart(bytes.NewReader(prep.ManifestPad), int64(len(prep.ManifestPad)), p0Key, p0NP, prep.MsgIDRaw, 0, blocksPerChunk, 0, func(txIdx int, chunk []byte) error {
		if err := putPipeChunk(0, txIdx, chunk); err != nil {
			return err
		}
		p0Done += int64(len(chunk))
		totalSent += int64(len(chunk))
		emitProgress(0, p0Done, p0Total)
		return nil
	}); err != nil {
		return err
	}

	// Upload part_id = 1..N (Blobs)
	for i, b := range prep.Blobs {
		encKey, np, err := synccrypto.DeriveBlobPartKeys(prep.MsgIDRaw, b.PartID, b.BlobKey[:])
		if err != nil {
			return err
		}
		rc, _, err := b.Input.OpenStream()
		if err != nil {
			clear(encKey[:])
			return err
		}
		var partDone int64
		partTotal := prep.Parts[i+1].TotalBytes
		upErr := streamUploadPart(rc, b.Desc.Size, encKey, np, prep.MsgIDRaw, b.PartID, blocksPerChunk, 0, func(txIdx int, chunk []byte) error {
			if err := putPipeChunk(b.PartID, txIdx, chunk); err != nil {
				return err
			}
			partDone += int64(len(chunk))
			totalSent += int64(len(chunk))
			emitProgress(b.PartID, partDone, partTotal)
			return nil
		})
		_ = rc.Close()
		clear(encKey[:])
		if upErr != nil {
			return upErr
		}
	}
	return nil
}

// ReceiveFromRoom auto-dispatches Mode A receiving for Flow 1 oneshot (m=1/2) AND Flow 2 direct (m=0).
func (c *Client) ReceiveFromRoom(ctx context.Context, pairInput string, handler ParcelHandler, opts ReceiveOptions) (*envelope.Manifest, error) {
	done, err := c.beginOp()
	if err != nil {
		return nil, err
	}
	defer done()

	roomID, oob, err := parseRoomInput(pairInput)
	if err != nil {
		return nil, err
	}
	defer clear(oob)

	joined, rawM1, err := c.joinAndReadRawM1(ctx, roomID)
	if err != nil {
		return nil, err
	}
	var probe struct {
		ProtoV  int    `json:"proto_v"`
		Mode    int    `json:"mode"`
		Purpose string `json:"purpose"`
	}
	if err := json.Unmarshal(rawM1, &probe); err != nil {
		c.closeRoom(ctx, roomID, joined.ReceiverToken, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "invalid room M1 frame", nil)
	}
	if probe.ProtoV > 1 {
		c.closeRoom(ctx, roomID, joined.ReceiverToken, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeUnsupportedVersion, false, 0, fmt.Sprintf("unsupported room M1 proto_v %d", probe.ProtoV), map[string]any{"proto_v": probe.ProtoV, "supported_proto_v": 1})
	}
	if probe.ProtoV != 1 {
		c.closeRoom(ctx, roomID, joined.ReceiverToken, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "invalid room M1 frame", nil)
	}
	if probe.Mode == synccrypto.ModeDirect && probe.Purpose == synccrypto.PurposeDirect {
		var initPayload envelope.DirectRoomInitPayload
		if err := json.Unmarshal(rawM1, &initPayload); err != nil {
			c.closeRoom(ctx, roomID, joined.ReceiverToken, "verify_failed")
			return nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "invalid direct M1 payload", nil)
		}
		return c.receiveDirectJoined(ctx, joined, initPayload, handler, opts)
	}
	var m1 hsM1Wire
	if err := json.Unmarshal(rawM1, &m1); err != nil || m1.Purpose != synccrypto.PurposeOneshot {
		c.closeRoom(ctx, roomID, joined.ReceiverToken, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeInvalidState, false, 0, "unexpected room purpose for receive", nil)
	}
	return c.receiveOneShotJoined(ctx, joined, m1, oob, handler, opts)
}

// ReceiveOneShot receives a Flow 1 oneshot Mode A transfer.
func (c *Client) ReceiveOneShot(ctx context.Context, pairInput string, handler ParcelHandler, opts ReceiveOptions) (*envelope.Manifest, error) {
	return c.ReceiveFromRoom(ctx, pairInput, handler, opts)
}

// ReceiveDirect receives a Flow 2 Mode A direct transfer (m=0&p=direct).
func (c *Client) ReceiveDirect(ctx context.Context, pairInput string, handler ParcelHandler, opts ReceiveOptions) (*envelope.Manifest, error) {
	return c.ReceiveFromRoom(ctx, pairInput, handler, opts)
}

func (c *Client) receiveOneShotJoined(ctx context.Context, joined *roomJoinResp, m1 hsM1Wire, oob []byte, handler ParcelHandler, opts ReceiveOptions) (*envelope.Manifest, error) {
	sess, err := c.runResponderHandshake(ctx, joined, m1, oob, opts.OnSASDisplay, opts.OnSASConfirm)
	if err != nil {
		return nil, err
	}
	defer sess.HS.Zero()

	ctrlKey, ctrlNP, err := synccrypto.DerivePipeCtrlKeys(sess.HS.TH[:], sess.HS.SessionKey[:])
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "cancelled")
		return nil, err
	}
	defer clear(ctrlKey[:])

	// Wait for sender's encrypted pipe_start (ctrl_seq = 0)
	startWire, nextSeq, err := c.waitForPeerRoomMessage(ctx, sess.RoomID, sess.Token, "sender", sess.LastSeq)
	if err != nil {
		return nil, err
	}
	sess.LastSeq = nextSeq
	startRaw, err := base64.RawURLEncoding.DecodeString(startWire.MsgB64)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decode pipe_start", nil)
	}
	var cw pipeCtrlWire
	if err := json.Unmarshal(startRaw, &cw); err != nil || cw.CtrlSeq != 0 {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "invalid pipe_start ctrl_seq", nil)
	}
	ctBytes, err := base64.RawURLEncoding.DecodeString(cw.CT)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decode pipe_start ct", nil)
	}
	ptStart, err := synccrypto.OpenPipeCtrl(ctrlKey, ctrlNP, sess.HS.TH[:], cw.CtrlSeq, ctBytes)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decrypt pipe_start", err)
	}
	var startCmd envelope.PipeStartPayload
	if err := json.Unmarshal(ptStart, &startCmd); err != nil || startCmd.Op != "pipe_start" {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "invalid pipe_start payload", nil)
	}
	msgIDSlice, err := hex.DecodeString(startCmd.MsgID)
	if err != nil || len(msgIDSlice) != 16 {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, "invalid pipe_start msg_id", nil)
	}
	var msgIDRaw [16]byte
	copy(msgIDRaw[:], msgIDSlice)

	p0Key, p0NP, err := synccrypto.DeriveOneshotPart0Keys(sess.HS.SessionKey[:], msgIDRaw[:])
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "cancelled")
		return nil, err
	}
	defer clear(p0Key[:])

	manifest, err := c.downloadAndDeliverPipeParcel(ctx, sess.PipeID, sess.Token, msgIDRaw, startCmd.MsgID, p0Key, p0NP, nil, startCmd.BlocksPerChunk, startCmd.Parts, handler, opts.OnProgress)
	if err != nil {
		reason := "cancelled"
		if envelope.IsSecurityAlert(err) || envelope.IsCode(err, envelope.ErrCodeManifestInvalid) {
			reason = "verify_failed"
		}
		c.closeRoom(ctx, sess.RoomID, sess.Token, reason)
		return nil, err
	}

	ackCmd, _ := json.Marshal(envelope.PipeAckPayload{Op: "pipe_ack", MsgID: startCmd.MsgID})
	ackCT, err := synccrypto.SealPipeCtrl(ctrlKey, ctrlNP, sess.HS.TH[:], 1, ackCmd)
	if err != nil {
		return nil, err
	}
	ackFrame, _ := json.Marshal(pipeCtrlWire{CtrlSeq: 1, CT: base64.RawURLEncoding.EncodeToString(ackCT)})
	if _, err := c.postRoomMessage(ctx, sess.RoomID, sess.Token, "control", ackFrame); err != nil {
		return nil, err
	}
	return manifest, nil
}

func (c *Client) receiveDirectJoined(ctx context.Context, joined *roomJoinResp, initPayload envelope.DirectRoomInitPayload, handler ParcelHandler, opts ReceiveOptions) (*envelope.Manifest, error) {
	roomID := joined.RoomID
	token := joined.ReceiverToken

	hdrBytes, err := base64.RawURLEncoding.DecodeString(initPayload.SealedHeader)
	if err != nil || len(hdrBytes) != synccrypto.SealedHeaderSize {
		c.closeRoom(ctx, roomID, token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoSignatureInvalid, false, 0, "invalid sealed_header length", nil)
	}
	opened, err := c.openAndVerifySealedHeader(hdrBytes)
	if err != nil {
		c.closeRoom(ctx, roomID, token, "verify_failed")
		return nil, err
	}
	defer opened.Zero()

	releaseMsg, claimed := c.claimInFlightMsgID(opened.MsgID)
	if !claimed {
		c.closeRoom(ctx, roomID, token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeMsgReplayDetected, false, 0, "msg_id is already being processed concurrently", map[string]any{"msg_id": opened.MsgID})
	}
	defer releaseMsg()

	if seen, err := c.keyStore.HasSeenMsgID(opened.MsgID); err != nil {
		c.closeRoom(ctx, roomID, token, "cancelled")
		return nil, err
	} else if seen {
		c.closeRoom(ctx, roomID, token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeMsgReplayDetected, false, 0, "msg_id already processed (replay rejected)", map[string]any{"msg_id": opened.MsgID})
	}

	// ST-P2-14: Always close/burn the direct room if verification or delivery fails so sender never hangs until TTL!
	manifest, err := c.downloadAndDeliverPipeParcel(ctx, joined.PipeID, token, opened.MsgIDRaw, opened.MsgID, opened.Part0Key, opened.Part0NoncePrefix, opened, initPayload.BlocksPerChunk, initPayload.Parts, handler, opts.OnProgress)
	if err != nil {
		reason := "cancelled"
		if envelope.IsSecurityAlert(err) || envelope.IsCode(err, envelope.ErrCodeManifestInvalid) {
			reason = "verify_failed"
		}
		c.closeRoom(ctx, roomID, token, reason)
		return nil, err
	}
	if err := c.keyStore.MarkSeenMsgID(opened.MsgID, opened.CreatedAt, time.Now().Unix()); err != nil {
		c.closeRoom(ctx, roomID, token, "cancelled")
		return nil, err
	}

	ackMAC := synccrypto.ComputeDirectAckMAC(opened.Part0Key, opened.MsgIDRaw)
	ackPayload, _ := json.Marshal(envelope.PipeAckPayload{
		Op:     "pipe_ack",
		MsgID:  opened.MsgID,
		AckMAC: base64.RawURLEncoding.EncodeToString(ackMAC[:]),
	})
	if _, err := c.postRoomMessage(ctx, roomID, token, "control", ackPayload); err != nil {
		return nil, err
	}
	return manifest, nil
}

func (c *Client) downloadAndDeliverPipeParcel(
	ctx context.Context,
	pipeID, recvToken string,
	msgIDRaw [16]byte,
	msgIDHex string,
	p0Key [32]byte,
	p0NP [7]byte,
	opened *synccrypto.SealedHeaderOpenResult,
	blocksPerChunk int,
	parts []envelope.PartLayout,
	handler ParcelHandler,
	onProgress func(envelope.TransferEvent),
) (*envelope.Manifest, error) {
	partMap := make(map[uint32]envelope.PartLayout, len(parts))
	var totalBytes int64
	for _, p := range parts {
		if _, dup := partMap[p.PartID]; dup {
			return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, fmt.Sprintf("duplicate part_id=%d in wire layout", p.PartID), nil)
		}
		if p.TotalBytes <= 0 || p.ChunkCount <= 0 {
			return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, fmt.Sprintf("invalid part_id=%d layout", p.PartID), nil)
		}
		partMap[p.PartID] = p
		totalBytes += p.TotalBytes
	}
	p0Layout, ok := partMap[0]
	if !ok || p0Layout.ChunkCount <= 0 {
		return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, "missing part_id=0 layout", nil)
	}

	getPipeChunk := func(partID uint32, txIdx int) ([]byte, error) {
		path := fmt.Sprintf("/v1/pipe/%s/parts/%d/chunks/%d", pipeID, partID, txIdx)
		maxRetries := maxMidStreamPipePeerTimeouts
		if partID == 0 && txIdx == 0 {
			maxRetries = maxInitialPipePeerTimeouts
		}
		timeouts := 0
		for {
			resp, err := c.doSignedWithSkewRetry(ctx, http.MethodGet, path, nil, reqOptions{
				RoomToken:     recvToken,
				MaxRespBytes:  maxChunkRespBytes,
				IsBinaryChunk: true,
			})
			if err != nil {
				if envelope.IsCode(err, envelope.ErrCodePipePeerTimeout) && ctx.Err() == nil && timeouts < maxRetries {
					timeouts++
					select {
					case <-ctx.Done():
						return nil, envelope.WrapError(envelope.ErrCodeCancelled, false, 0, "pipe download cancelled", ctx.Err())
					case <-time.After(50 * time.Millisecond):
						continue
					}
				}
				return nil, err
			}
			return resp.Body, nil
		}
	}

	manifest, _, err := c.pullAndVerifyManifest(msgIDRaw, msgIDHex, p0Key, p0NP, p0Layout, opened, func(txIdx int) ([]byte, error) {
		return getPipeChunk(0, txIdx)
	})
	if err != nil {
		return nil, err
	}
	if len(partMap) != 1+len(manifest.Blobs) {
		return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, "wire parts count does not match signed manifest blobs count", nil)
	}

	var doneBytes int64 = p0Layout.TotalBytes
	receivedBlobs, err := c.pullAndVerifyBlobs(ctx, "", msgIDRaw, manifest, partMap, blocksPerChunk, totalBytes, &doneBytes, "pipe", func(partID uint32, txIdx int) ([]byte, error) {
		return getPipeChunk(partID, txIdx)
	}, onProgress)
	if err != nil {
		return nil, err
	}

	if handler != nil {
		if err := handler(envelope.ReceivedParcel{
			Manifest: *manifest,
			Blobs:    receivedBlobs,
		}); err != nil {
			return nil, err
		}
	}
	return manifest, nil
}

func (c *Client) sendDirectViaPipe(
	ctx context.Context,
	prep *preparedParcel,
	sealedB64 string,
	p0Key [32]byte,
	p0NP [7]byte,
	blocksPerChunk int,
	opts SendOptions,
) (*SendResult, error) {
	roomID, err := synccrypto.GenerateRoomID()
	if err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "generate room_id", err)
	}
	m1Bytes, _ := json.Marshal(envelope.DirectRoomInitPayload{
		ProtoV:         1,
		Mode:           synccrypto.ModeDirect,
		Purpose:        synccrypto.PurposeDirect,
		SealedHeader:   sealedB64,
		BlocksPerChunk: blocksPerChunk,
		Parts:          prep.Parts,
	})
	created, err := c.createRoom(ctx, roomID, opts.TTLSec, m1Bytes)
	if err != nil {
		return nil, err
	}

	offer := &envelope.PairOffer{
		Version:   1,
		RoomID:    roomID,
		Mode:      synccrypto.ModeDirect,
		Purpose:   synccrypto.PurposeDirect,
		ExpiresAt: created.ExpiresAt,
	}
	if opts.IncludeRelay {
		offer.Endpoint = c.profile.Endpoint
		offer.SPKISHA256 = c.profile.SPKISHA256
		offer.SPKIPin = c.profile.SPKIPin
		offer.SPKIPins = append([]string(nil), c.profile.SPKIPins...)
		offer.AccessKey = c.profile.AccessKey
	}
	pairURI, err := envelope.FormatPairURI(offer)
	if err != nil {
		c.closeRoom(ctx, roomID, created.SenderToken, "cancelled")
		return nil, err
	}
	dispCode, _ := synccrypto.FormatRoomID(roomID)
	if opts.OnOfferReady != nil {
		opts.OnOfferReady(OfferReadyInfo{
			RoomID:      roomID,
			DisplayCode: dispCode,
			Mode:        synccrypto.ModeDirect,
			Purpose:     synccrypto.PurposeDirect,
			PairURI:     pairURI,
			ExpiresAt:   created.ExpiresAt,
		})
	}

	if err := c.uploadAllPipeParts(ctx, created.PipeID, created.SenderToken, prep, p0Key, p0NP, blocksPerChunk, opts.OnProgress); err != nil {
		c.closeRoom(ctx, roomID, created.SenderToken, "cancelled")
		return nil, err
	}

	// Wait for receiver's direct pipe_ack with HMAC ack_mac
	ackWire, _, err := c.waitForPeerRoomMessage(ctx, roomID, created.SenderToken, "receiver", created.Seq)
	if err != nil {
		return nil, err
	}
	ackRaw, err := base64.RawURLEncoding.DecodeString(ackWire.MsgB64)
	if err != nil {
		c.closeRoom(ctx, roomID, created.SenderToken, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decode direct pipe_ack", nil)
	}
	var ack envelope.PipeAckPayload
	if err := json.Unmarshal(ackRaw, &ack); err != nil || ack.Op != "pipe_ack" || ack.MsgID != prep.MsgID {
		c.closeRoom(ctx, roomID, created.SenderToken, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoSignatureInvalid, false, 0, "invalid direct pipe_ack payload", nil)
	}
	macBytes, err := base64.RawURLEncoding.DecodeString(ack.AckMAC)
	if err != nil || synccrypto.VerifyDirectAckMAC(p0Key, prep.MsgIDRaw, macBytes) != nil {
		c.closeRoom(ctx, roomID, created.SenderToken, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoSignatureInvalid, false, 0, "direct pipe_ack MAC verification failed", nil)
	}
	c.closeRoom(ctx, roomID, created.SenderToken, "completed")
	return &SendResult{
		Mode:       "pipe",
		MsgID:      prep.MsgID,
		RoomID:     roomID,
		TotalBytes: prep.TotalEnc,
	}, nil
}

func parseRoomInput(input string) (roomID string, oobSecret []byte, err error) {
	trimmed := strings.TrimSpace(input)
	if strings.HasPrefix(strings.ToLower(trimmed), "synctool://") {
		offer, err := envelope.ParsePairURI(trimmed)
		if err != nil {
			return "", nil, err
		}
		return offer.RoomID, offer.OOBSecret, nil
	}
	roomID, err = synccrypto.NormalizeRoomID(trimmed)
	if err != nil {
		return "", nil, envelope.NewError(envelope.ErrCodeURIInvalid, false, 0, "invalid pair URI or 8-char room code", nil)
	}
	return roomID, nil, nil
}

func (c *Client) joinAndReadRawM1(ctx context.Context, roomID string) (*roomJoinResp, []byte, error) {
	joined, err := c.joinRoom(ctx, roomID)
	if err != nil {
		return nil, nil, err
	}
	if len(joined.Messages) == 0 {
		m1Wire, nextSeq, err := c.waitForPeerRoomMessage(ctx, roomID, joined.ReceiverToken, "sender", joined.Seq)
		if err != nil {
			return nil, nil, err
		}
		joined.Seq = nextSeq
		joined.Messages = append(joined.Messages, m1Wire)
	}
	rawM1, err := base64.RawURLEncoding.DecodeString(joined.Messages[0].MsgB64)
	if err != nil {
		c.closeRoom(ctx, roomID, joined.ReceiverToken, "verify_failed")
		return nil, nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "decode M1 b64", nil)
	}
	return joined, rawM1, nil
}

func (c *Client) joinAndReadM1(ctx context.Context, roomID string) (*roomJoinResp, hsM1Wire, error) {
	joined, rawM1, err := c.joinAndReadRawM1(ctx, roomID)
	if err != nil {
		return nil, hsM1Wire{}, err
	}
	var m1 hsM1Wire
	if err := json.Unmarshal(rawM1, &m1); err != nil {
		c.closeRoom(ctx, roomID, joined.ReceiverToken, "verify_failed")
		return nil, hsM1Wire{}, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "invalid M1 json", nil)
	}
	if m1.ProtoV > 1 {
		c.closeRoom(ctx, roomID, joined.ReceiverToken, "verify_failed")
		return nil, hsM1Wire{}, envelope.NewError(envelope.ErrCodeUnsupportedVersion, false, 0, fmt.Sprintf("unsupported M1 proto_v %d", m1.ProtoV), map[string]any{"proto_v": m1.ProtoV, "supported_proto_v": 1})
	}
	if m1.ProtoV != 1 {
		c.closeRoom(ctx, roomID, joined.ReceiverToken, "verify_failed")
		return nil, hsM1Wire{}, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "invalid M1 json", nil)
	}
	return joined, m1, nil
}
