package relay

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type pipeSlotKey struct {
	pipeID string
	partID int
	txIdx  uint32
}

type pipeCopyResult struct {
	bytes int64
	err   error
}

type pipeSender struct {
	body       io.Reader
	contentLen int64
	rc         *http.ResponseController
	ctx        context.Context
	ip         netip.Addr
	done       chan pipeCopyResult
}

type pipeReceiver struct {
	w   http.ResponseWriter
	rc  *http.ResponseController
	ctx context.Context
	ip  netip.Addr
}

type pipeSlot struct {
	sender   *pipeSender
	receiver *pipeReceiver
	matched  chan struct{}
}

type PipeHub struct {
	mu                sync.Mutex
	slots             map[pipeSlotKey]*pipeSlot
	bufPool           sync.Pool
	bufSize           int
	rendezvousTimeout time.Duration
	stallTimeout      time.Duration
	maxChunkDuration  time.Duration
	gate              *TransferGate
	bw                *BandwidthLimiter
}

func NewPipeHub(bufSize int, rendezvousTimeout, stallTimeout time.Duration, gate *TransferGate, bw *BandwidthLimiter) *PipeHub {
	return NewPipeHubWithMaxDuration(bufSize, rendezvousTimeout, stallTimeout, MaxChunkTransferDuration, gate, bw)
}

func NewPipeHubWithMaxDuration(bufSize int, rendezvousTimeout, stallTimeout, maxChunkDuration time.Duration, gate *TransferGate, bw *BandwidthLimiter) *PipeHub {
	if bufSize <= 0 {
		bufSize = 64 << 10
	}
	if rendezvousTimeout <= 0 {
		rendezvousTimeout = RendezvousTimeout
	}
	if stallTimeout <= 0 {
		stallTimeout = StallTimeout
	}
	if maxChunkDuration <= 0 {
		maxChunkDuration = MaxChunkTransferDuration
	}
	ph := &PipeHub{
		slots:             make(map[pipeSlotKey]*pipeSlot, 32),
		bufSize:           bufSize,
		rendezvousTimeout: rendezvousTimeout,
		stallTimeout:      stallTimeout,
		maxChunkDuration:  maxChunkDuration,
		gate:              gate,
		bw:                bw,
	}
	ph.bufPool.New = func() any {
		b := make([]byte, ph.bufSize)
		return &b
	}
	return ph
}

func (ph *PipeHub) PutChunk(
	ctx context.Context,
	roomCtx context.Context,
	pipeID string,
	partID int,
	txIdx uint32,
	contentLen int64,
	body io.Reader,
	rc *http.ResponseController,
	clientIP netip.Addr,
) (int64, error) {
	key := pipeSlotKey{pipeID: pipeID, partID: partID, txIdx: txIdx}
	sender := &pipeSender{
		body:       body,
		contentLen: contentLen,
		rc:         rc,
		ctx:        ctx,
		ip:         clientIP,
		done:       make(chan pipeCopyResult, 1),
	}

	ph.mu.Lock()
	slot, exists := ph.slots[key]
	if exists {
		if slot.sender != nil {
			ph.mu.Unlock()
			return 0, newAPIError(409, "ERR_CONFLICT", "concurrent duplicate pipe PUT for same chunk", false)
		}
		// Receiver is already waiting! Pair immediately and hand off copy to receiver goroutine.
		slot.sender = sender
		delete(ph.slots, key)
		close(slot.matched)
		ph.mu.Unlock()

		// Wait for receiver goroutine to finish streaming from sender.body.
		res := <-sender.done
		return res.bytes, res.err
	}

	// Sender arrived first; register and wait for Receiver.
	slot = &pipeSlot{
		sender:  sender,
		matched: make(chan struct{}),
	}
	ph.slots[key] = slot
	ph.mu.Unlock()

	timer := time.NewTimer(ph.rendezvousTimeout)
	defer timer.Stop()

	select {
	case <-slot.matched:
		res := <-sender.done
		return res.bytes, res.err
	case <-timer.C:
		if ph.removeIfUnmatched(key, slot) {
			return 0, newAPIError(504, "ERR_PIPE_PEER_TIMEOUT", "receiver did not join chunk within rendezvous timeout", true)
		}
		res := <-sender.done
		return res.bytes, res.err
	case <-roomCtx.Done():
		if ph.removeIfUnmatched(key, slot) {
			return 0, newAPIError(410, "ERR_ROOM_BURNED", "room closed or burned while waiting for peer", false)
		}
		res := <-sender.done
		return res.bytes, res.err
	case <-ctx.Done():
		if ph.removeIfUnmatched(key, slot) {
			return 0, ctx.Err()
		}
		res := <-sender.done
		return res.bytes, res.err
	}
}

func (ph *PipeHub) GetChunk(
	ctx context.Context,
	roomCtx context.Context,
	pipeID string,
	partID int,
	txIdx uint32,
	w http.ResponseWriter,
	rc *http.ResponseController,
	clientIP netip.Addr,
) error {
	key := pipeSlotKey{pipeID: pipeID, partID: partID, txIdx: txIdx}
	recv := &pipeReceiver{
		w:   w,
		rc:  rc,
		ctx: ctx,
		ip:  clientIP,
	}

	ph.mu.Lock()
	slot, exists := ph.slots[key]
	if exists {
		if slot.receiver != nil {
			ph.mu.Unlock()
			return newAPIError(409, "ERR_CONFLICT", "concurrent duplicate pipe GET for same chunk", false)
		}
		// Sender is already waiting! Pair immediately and stream on this goroutine.
		slot.receiver = recv
		sender := slot.sender
		delete(ph.slots, key)
		close(slot.matched)
		ph.mu.Unlock()

		return ph.streamBridge(roomCtx, sender, recv)
	}

	// Receiver arrived first; register and wait for Sender.
	slot = &pipeSlot{
		receiver: recv,
		matched:  make(chan struct{}),
	}
	ph.slots[key] = slot
	ph.mu.Unlock()

	timer := time.NewTimer(ph.rendezvousTimeout)
	defer timer.Stop()

	select {
	case <-slot.matched:
		return ph.streamBridge(roomCtx, slot.sender, recv)
	case <-timer.C:
		if ph.removeIfUnmatched(key, slot) {
			return newAPIError(504, "ERR_PIPE_PEER_TIMEOUT", "sender did not join chunk within rendezvous timeout", true)
		}
		return ph.streamBridge(roomCtx, slot.sender, recv)
	case <-roomCtx.Done():
		if ph.removeIfUnmatched(key, slot) {
			return newAPIError(410, "ERR_ROOM_BURNED", "room closed or burned while waiting for peer", false)
		}
		return ph.streamBridge(roomCtx, slot.sender, recv)
	case <-ctx.Done():
		if ph.removeIfUnmatched(key, slot) {
			return ctx.Err()
		}
		return ph.streamBridge(roomCtx, slot.sender, recv)
	}
}

func (ph *PipeHub) removeIfUnmatched(key pipeSlotKey, expected *pipeSlot) bool {
	ph.mu.Lock()
	defer ph.mu.Unlock()
	if cur, ok := ph.slots[key]; ok && cur == expected {
		delete(ph.slots, key)
		return true
	}
	return false
}

func flushPipeReceiver(rc *http.ResponseController, w http.ResponseWriter) error {
	if rc != nil {
		if err := rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return err
		}
		return nil
	}
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	return nil
}

func (ph *PipeHub) streamBridge(roomCtx context.Context, sender *pipeSender, recv *pipeReceiver) error {
	// Acquire L7 concurrency semaphore before copying bytes; abort early if either peer or room cancels.
	if ph.gate != nil {
		waitCtx, waitCancel := context.WithCancel(recv.ctx)
		stopWatch := make(chan struct{})
		go func() {
			select {
			case <-sender.ctx.Done():
				waitCancel()
			case <-roomCtx.Done():
				waitCancel()
			case <-stopWatch:
			}
		}()
		release, ok := ph.gate.Acquire(waitCtx, sender.ip, TransferSemWait)
		close(stopWatch)
		waitCancel()
		if !ok {
			if roomCtx.Err() != nil {
				burnErr := newAPIError(410, "ERR_ROOM_BURNED", "room closed while acquiring transfer slot", false)
				sender.done <- pipeCopyResult{bytes: 0, err: burnErr}
				return burnErr
			}
			if recv.ctx.Err() != nil || sender.ctx.Err() != nil {
				abortErr := errors.New("peer cancelled before stream start")
				sender.done <- pipeCopyResult{bytes: 0, err: abortErr}
				return abortErr
			}
			rateErr := newAPIError(429, "ERR_RATE_LIMITED", "concurrent transfer stream limit reached", true)
			sender.done <- pipeCopyResult{bytes: 0, err: rateErr}
			return rateErr
		}
		defer release()
	}

	bufPtr := ph.bufPool.Get().(*[]byte)
	buf := *bufPtr
	defer func() {
		clear(buf)
		ph.bufPool.Put(bufPtr)
	}()

	// Enforce 5-minute per-chunk total ceiling AND bind to roomCtx deadline if tighter.
	chunkDeadline := time.Now().Add(ph.maxChunkDuration)
	if roomDead, hasRoomDead := roomCtx.Deadline(); hasRoomDead && roomDead.Before(chunkDeadline) {
		chunkDeadline = roomDead
	}

	// Write response headers on receiver side before copying first byte.
	h := recv.w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Length", strconv.FormatInt(sender.contentLen, 10))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Accel-Buffering", "no")
	initWriteDL := time.Now().Add(ph.stallTimeout)
	if chunkDeadline.Before(initWriteDL) {
		initWriteDL = chunkDeadline
	}
	if recv.rc != nil {
		_ = recv.rc.SetWriteDeadline(initWriteDL)
	}
	recv.w.WriteHeader(http.StatusOK)

	var reader io.Reader = io.LimitReader(sender.body, sender.contentLen)
	if ph.bw != nil {
		reader = &rateLimitedReader{ctx: recv.ctx, r: reader, bl: ph.bw}
	}

	// Immediately unblock stalled Read/Write sockets if roomCtx cancels mid-chunk (e.g. SAS verify_failed).
	bridgeDone := make(chan struct{})
	watchExited := make(chan struct{})
	go func() {
		defer close(watchExited)
		select {
		case <-roomCtx.Done():
			abortNow := time.Now()
			if sender.rc != nil {
				_ = sender.rc.SetReadDeadline(abortNow)
			}
			if recv.rc != nil {
				_ = recv.rc.SetWriteDeadline(abortNow)
			}
		case <-bridgeDone:
		}
	}()

	var total int64
	var copyErr error
	for total < sender.contentLen {
		if roomCtx.Err() != nil {
			copyErr = newAPIError(410, "ERR_ROOM_BURNED", "room closed during transfer", false)
			break
		}
		if recv.ctx.Err() != nil {
			copyErr = recv.ctx.Err()
			break
		}
		if sender.ctx.Err() != nil {
			copyErr = sender.ctx.Err()
			break
		}
		nowIter := time.Now()
		if !nowIter.Before(chunkDeadline) {
			copyErr = errors.New("pipe chunk transfer exceeded max duration")
			break
		}

		// Refresh rolling stall deadlines on both ends, bounded by chunkDeadline.
		deadline := nowIter.Add(ph.stallTimeout)
		if chunkDeadline.Before(deadline) {
			deadline = chunkDeadline
		}
		if sender.rc != nil {
			_ = sender.rc.SetReadDeadline(deadline)
		}
		if recv.rc != nil {
			_ = recv.rc.SetWriteDeadline(deadline)
		}

		nr, rerr := reader.Read(buf)
		if nr > 0 {
			nw, werr := recv.w.Write(buf[:nr])
			total += int64(nw)
			ferr := flushPipeReceiver(recv.rc, recv.w)
			if werr != nil {
				copyErr = werr
				break
			}
			if nw != nr {
				copyErr = io.ErrShortWrite
				break
			}
			if ferr != nil {
				copyErr = ferr
				break
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			copyErr = rerr
			break
		}
	}

	close(bridgeDone)
	<-watchExited

	if copyErr != nil && roomCtx.Err() != nil {
		copyErr = newAPIError(410, "ERR_ROOM_BURNED", "room closed during transfer", false)
	}
	if copyErr == nil && total != sender.contentLen {
		copyErr = io.ErrUnexpectedEOF
	}
	if copyErr == nil {
		if ferr := flushPipeReceiver(recv.rc, recv.w); ferr != nil {
			copyErr = ferr
		}
	}

	// Clear rolling deadlines after chunk completes.
	if sender.rc != nil {
		_ = sender.rc.SetReadDeadline(time.Time{})
	}
	if recv.rc != nil {
		_ = recv.rc.SetWriteDeadline(time.Time{})
	}

	sender.done <- pipeCopyResult{bytes: total, err: copyErr}
	if copyErr != nil {
		// Headers were already sent on recv.w (200 OK); never return an *apiError to GetChunk
		// so handlePipeGet never corrupts the binary stream with a trailing JSON body.
		return errors.New("pipe stream aborted after headers sent")
	}
	return nil
}
