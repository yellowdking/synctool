package relay

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

type RoomState string

const (
	RoomWaiting RoomState = "waiting"
	RoomJoined  RoomState = "joined"
	RoomClosed  RoomState = "closed"
	RoomBurned  RoomState = "burned"
)

type RoomMessage struct {
	Seq    int    `json:"seq"`
	From   string `json:"from"`
	Kind   string `json:"kind"`
	MsgB64 string `json:"msg_b64"`
}

type storedRoomMsg struct {
	seq  int
	from string
	kind string
	raw  []byte
}

func (m storedRoomMsg) toWire() RoomMessage {
	return RoomMessage{
		Seq:    m.seq,
		From:   m.from,
		Kind:   m.kind,
		MsgB64: base64.RawURLEncoding.EncodeToString(m.raw),
	}
}

type Room struct {
	ID             string
	PipeID         string
	SenderToken    string
	ReceiverToken  string
	State          RoomState
	Reason         string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	TombstoneUntil time.Time

	Seq           int
	HandshakeMsgs []storedRoomMsg
	ControlMsgs   []storedRoomMsg
	NotifyCh      chan struct{}
	PipeCtx       context.Context
	PipeCancel    context.CancelFunc
}

type RoomCreateResult struct {
	RoomID      string `json:"room_id"`
	PipeID      string `json:"pipe_id"`
	SenderToken string `json:"sender_token"`
	ExpiresAt   int64  `json:"expires_at"`
	Seq         int    `json:"seq"`
}

type RoomJoinResult struct {
	RoomID        string        `json:"room_id"`
	PipeID        string        `json:"pipe_id"`
	ReceiverToken string        `json:"receiver_token"`
	ExpiresAt     int64         `json:"expires_at"`
	Seq           int           `json:"seq"`
	Messages      []RoomMessage `json:"messages"`
}

type RoomEventsSnapshot struct {
	State    RoomState     `json:"state"`
	Seq      int           `json:"seq"`
	Messages []RoomMessage `json:"messages"`
	Reason   string        `json:"reason"`
}

type RoomManager struct {
	mu             sync.Mutex
	maxActiveRooms int
	rooms          map[string]*Room
	byPipe         map[string]*Room
	onActivity     func()
}

func NewRoomManager(maxActiveRooms int, onActivity func()) *RoomManager {
	if maxActiveRooms <= 0 {
		maxActiveRooms = 128
	}
	return &RoomManager{
		maxActiveRooms: maxActiveRooms,
		rooms:          make(map[string]*Room, 32),
		byPipe:         make(map[string]*Room, 32),
		onActivity:     onActivity,
	}
}

func randomHex16() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomB64u32() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	defer clear(b)
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func decodeRoomMsgB64(s string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, newAPIError(400, "ERR_BAD_REQUEST", "msg_b64 must be valid unpadded base64url", false)
	}
	if len(raw) == 0 || len(raw) > MaxRoomMsgBytes {
		clear(raw)
		return nil, newAPIError(400, "ERR_BAD_REQUEST", "msg_b64 decoded length must be 1..4096 bytes", false)
	}
	return raw, nil
}

func (rm *RoomManager) Create(roomID string, ttlSec int64, initialMsgB64 string, now time.Time) (RoomCreateResult, error) {
	if !isValidRoomID(roomID) {
		return RoomCreateResult{}, newAPIError(400, "ERR_BAD_REQUEST", "room_id must be 8 uppercase Crockford Base32 chars", false)
	}
	if ttlSec < 0 {
		return RoomCreateResult{}, newAPIError(400, "ERR_BAD_REQUEST", "ttl_sec must be non-negative", false)
	}
	if ttlSec == 0 {
		ttlSec = RoomTTLDefaultSec
	} else if ttlSec < RoomTTLMinSec {
		ttlSec = RoomTTLMinSec
	} else if ttlSec > RoomTTLMaxSec {
		ttlSec = RoomTTLMaxSec
	}

	var initRaw []byte
	if initialMsgB64 != "" {
		var err error
		initRaw, err = decodeRoomMsgB64(initialMsgB64)
		if err != nil {
			return RoomCreateResult{}, err
		}
	}

	pipeID, err := randomHex16()
	if err != nil {
		clear(initRaw)
		return RoomCreateResult{}, err
	}
	senderToken, err := randomB64u32()
	if err != nil {
		clear(initRaw)
		return RoomCreateResult{}, err
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.sweepLocked(now)

	if _, exists := rm.rooms[roomID]; exists {
		clear(initRaw)
		return RoomCreateResult{}, newAPIError(409, "ERR_CONFLICT", "room_id already exists", false)
	}
	if len(rm.rooms) >= rm.maxActiveRooms {
		clear(initRaw)
		return RoomCreateResult{}, newAPIError(429, "ERR_RATE_LIMITED", "active room capacity reached", true)
	}

	ttlDur := time.Duration(ttlSec) * time.Second
	pipeCtx, pipeCancel := context.WithTimeout(context.Background(), ttlDur)
	room := &Room{
		ID:          roomID,
		PipeID:      pipeID,
		SenderToken: senderToken,
		State:       RoomWaiting,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttlDur),
		NotifyCh:    make(chan struct{}),
		PipeCtx:     pipeCtx,
		PipeCancel:  pipeCancel,
	}
	if len(initRaw) > 0 {
		room.Seq = 1
		room.HandshakeMsgs = append(room.HandshakeMsgs, storedRoomMsg{
			seq:  1,
			from: "sender",
			kind: "handshake",
			raw:  initRaw,
		})
	}
	rm.rooms[roomID] = room
	rm.byPipe[pipeID] = room

	if rm.onActivity != nil {
		rm.onActivity()
	}

	return RoomCreateResult{
		RoomID:      room.ID,
		PipeID:      room.PipeID,
		SenderToken: room.SenderToken,
		ExpiresAt:   room.ExpiresAt.Unix(),
		Seq:         room.Seq,
	}, nil
}

func (rm *RoomManager) Join(roomID, msgB64 string, now time.Time) (RoomJoinResult, error) {
	if !isValidRoomID(roomID) {
		return RoomJoinResult{}, newAPIError(400, "ERR_BAD_REQUEST", "invalid room_id", false)
	}
	var joinRaw []byte
	if msgB64 != "" {
		var err error
		joinRaw, err = decodeRoomMsgB64(msgB64)
		if err != nil {
			return RoomJoinResult{}, err
		}
	}

	recvToken, err := randomB64u32()
	if err != nil {
		clear(joinRaw)
		return RoomJoinResult{}, err
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.sweepLocked(now)

	room, ok := rm.rooms[roomID]
	if !ok {
		clear(joinRaw)
		return RoomJoinResult{}, newAPIError(404, "ERR_NOT_FOUND", "room not found or expired", false)
	}
	if room.State == RoomBurned {
		clear(joinRaw)
		return RoomJoinResult{}, newAPIError(410, "ERR_ROOM_BURNED", "room has been burned", false)
	}
	if room.State == RoomClosed {
		clear(joinRaw)
		return RoomJoinResult{}, newAPIError(404, "ERR_NOT_FOUND", "room already closed", false)
	}
	if room.State == RoomJoined {
		clear(joinRaw)
		return RoomJoinResult{}, newAPIError(409, "ERR_ROOM_BUSY", "room already claimed by another receiver", false)
	}

	// Snapshot existing sender messages BEFORE optionally appending receiver's join message.
	existing := rm.collectMessagesLocked(room, 0)

	room.ReceiverToken = recvToken
	room.State = RoomJoined
	if len(joinRaw) > 0 {
		room.Seq++
		room.HandshakeMsgs = append(room.HandshakeMsgs, storedRoomMsg{
			seq:  room.Seq,
			from: "receiver",
			kind: "handshake",
			raw:  joinRaw,
		})
	}
	rm.broadcastLocked(room)

	return RoomJoinResult{
		RoomID:        room.ID,
		PipeID:        room.PipeID,
		ReceiverToken: room.ReceiverToken,
		ExpiresAt:     room.ExpiresAt.Unix(),
		Seq:           room.Seq,
		Messages:      existing,
	}, nil
}

func (rm *RoomManager) PostMessage(roomID, token, kind, msgB64 string, now time.Time) (int, error) {
	if !isValidRoomID(roomID) {
		return 0, newAPIError(400, "ERR_BAD_REQUEST", "invalid room_id", false)
	}
	if kind != "handshake" && kind != "control" {
		return 0, newAPIError(400, "ERR_BAD_REQUEST", "kind must be handshake or control", false)
	}
	raw, err := decodeRoomMsgB64(msgB64)
	if err != nil {
		return 0, err
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.sweepLocked(now)

	room, ok := rm.rooms[roomID]
	if !ok {
		clear(raw)
		return 0, newAPIError(404, "ERR_NOT_FOUND", "room not found or expired", false)
	}
	role, authOK := rm.matchRoleLocked(room, token)
	if !authOK {
		clear(raw)
		return 0, newAPIError(401, "ERR_UNAUTHORIZED_TOKEN", "invalid room token", false)
	}
	if room.State == RoomBurned {
		clear(raw)
		return 0, newAPIError(410, "ERR_ROOM_BURNED", "room has been burned", false)
	}
	if room.State == RoomClosed {
		clear(raw)
		return 0, newAPIError(404, "ERR_NOT_FOUND", "room is closed", false)
	}
	if room.State != RoomJoined {
		clear(raw)
		return 0, newAPIError(409, "ERR_INVALID_STATE", "room has not been joined yet", false)
	}

	if kind == "handshake" {
		if len(room.HandshakeMsgs) >= MaxHandshakeFrames {
			clear(raw)
			return 0, newAPIError(409, "ERR_INVALID_STATE", "max handshake frames (8) exceeded", false)
		}
		room.Seq++
		room.HandshakeMsgs = append(room.HandshakeMsgs, storedRoomMsg{
			seq:  room.Seq,
			from: role,
			kind: kind,
			raw:  raw,
		})
	} else {
		room.Seq++
		room.ControlMsgs = append(room.ControlMsgs, storedRoomMsg{
			seq:  room.Seq,
			from: role,
			kind: kind,
			raw:  raw,
		})
		if len(room.ControlMsgs) > MaxControlRingSize {
			clear(room.ControlMsgs[0].raw)
			room.ControlMsgs[0] = storedRoomMsg{}
			room.ControlMsgs = room.ControlMsgs[1:]
		}
	}

	rm.broadcastLocked(room)
	return room.Seq, nil
}

func (rm *RoomManager) Close(roomID, token, reason string, now time.Time) (RoomState, error) {
	if !isValidRoomID(roomID) {
		return "", newAPIError(400, "ERR_BAD_REQUEST", "invalid room_id", false)
	}
	switch reason {
	case "completed", "rejected", "verify_failed", "cancelled":
	default:
		return "", newAPIError(400, "ERR_BAD_REQUEST", "invalid close reason", false)
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.sweepLocked(now)

	room, ok := rm.rooms[roomID]
	if !ok {
		return "", newAPIError(404, "ERR_NOT_FOUND", "room not found or expired", false)
	}
	if _, authOK := rm.matchRoleLocked(room, token); !authOK {
		return "", newAPIError(401, "ERR_UNAUTHORIZED_TOKEN", "invalid room token", false)
	}

	// Preserve first terminal close state, reason, and TombstoneUntil idempotently (prevents reason spoofing & tombstone pinning).
	if room.State == RoomBurned || room.State == RoomClosed {
		return room.State, nil
	}

	// Wipe all buffered opaque messages immediately.
	rm.wipeMessagesLocked(room)
	if room.PipeCancel != nil {
		room.PipeCancel()
	}

	if reason == "verify_failed" || reason == "rejected" {
		room.State = RoomBurned
	} else {
		room.State = RoomClosed
	}
	room.Reason = reason
	room.TombstoneUntil = now.Add(RoomTombstoneDuration)
	rm.broadcastLocked(room)
	return room.State, nil
}

func (rm *RoomManager) SnapshotAndWatch(roomID, token string, since int, now time.Time) (RoomEventsSnapshot, <-chan struct{}, error) {
	if !isValidRoomID(roomID) {
		return RoomEventsSnapshot{}, nil, newAPIError(400, "ERR_BAD_REQUEST", "invalid room_id", false)
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.sweepLocked(now)

	room, ok := rm.rooms[roomID]
	if !ok {
		return RoomEventsSnapshot{}, nil, newAPIError(404, "ERR_NOT_FOUND", "room not found or expired", false)
	}
	if _, authOK := rm.matchRoleLocked(room, token); !authOK {
		return RoomEventsSnapshot{}, nil, newAPIError(401, "ERR_UNAUTHORIZED_TOKEN", "invalid room token", false)
	}

	msgs := rm.collectMessagesLocked(room, since)
	return RoomEventsSnapshot{
		State:    room.State,
		Seq:      room.Seq,
		Messages: msgs,
		Reason:   room.Reason,
	}, room.NotifyCh, nil
}

func (rm *RoomManager) AuthorizePipe(pipeID, token string, isSender bool, now time.Time) (context.Context, error) {
	if !isLowerHexLen(pipeID, 32) {
		return nil, newAPIError(400, "ERR_BAD_REQUEST", "invalid pipe_id", false)
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.sweepLocked(now)

	room, ok := rm.byPipe[pipeID]
	if !ok {
		return nil, newAPIError(404, "ERR_NOT_FOUND", "pipe not found or expired", false)
	}
	if room.State == RoomBurned {
		return nil, newAPIError(410, "ERR_ROOM_BURNED", "room has been burned", false)
	}
	if room.State == RoomClosed {
		return nil, newAPIError(404, "ERR_NOT_FOUND", "room is closed", false)
	}
	if isSender {
		if !ConstantTimeStringEqual(token, room.SenderToken) {
			return nil, newAPIError(401, "ERR_UNAUTHORIZED_TOKEN", "invalid sender room token", false)
		}
		// Flow 2 Mode A direct: sender may park PUT in rendezvous while room is still RoomWaiting.
		if room.State != RoomWaiting && room.State != RoomJoined {
			return nil, newAPIError(409, "ERR_INVALID_STATE", "room not open for pipe sender", false)
		}
	} else {
		if room.ReceiverToken == "" || !ConstantTimeStringEqual(token, room.ReceiverToken) {
			return nil, newAPIError(401, "ERR_UNAUTHORIZED_TOKEN", "invalid receiver room token", false)
		}
		if room.State != RoomJoined {
			return nil, newAPIError(409, "ERR_INVALID_STATE", "room not joined yet", false)
		}
	}
	return room.PipeCtx, nil
}

func (rm *RoomManager) HasActive() bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return len(rm.rooms) > 0
}

func (rm *RoomManager) SweepExpired(now time.Time) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.sweepLocked(now)
}

func (rm *RoomManager) sweepLocked(now time.Time) {
	for id, room := range rm.rooms {
		expired := false
		if room.State == RoomClosed || room.State == RoomBurned {
			if !now.Before(room.TombstoneUntil) {
				expired = true
			}
		} else if !now.Before(room.ExpiresAt) {
			expired = true
		}
		if expired {
			rm.wipeMessagesLocked(room)
			if room.PipeCancel != nil {
				room.PipeCancel()
			}
			rm.broadcastLocked(room)
			delete(rm.byPipe, room.PipeID)
			delete(rm.rooms, id)
		}
	}
}

func (rm *RoomManager) matchRoleLocked(room *Room, token string) (string, bool) {
	if token == "" {
		return "", false
	}
	if ConstantTimeStringEqual(token, room.SenderToken) {
		return "sender", true
	}
	if room.ReceiverToken != "" && ConstantTimeStringEqual(token, room.ReceiverToken) {
		return "receiver", true
	}
	return "", false
}

func (rm *RoomManager) wipeMessagesLocked(room *Room) {
	for i := range room.HandshakeMsgs {
		clear(room.HandshakeMsgs[i].raw)
	}
	room.HandshakeMsgs = nil
	for i := range room.ControlMsgs {
		clear(room.ControlMsgs[i].raw)
	}
	room.ControlMsgs = nil
}

func (rm *RoomManager) broadcastLocked(room *Room) {
	close(room.NotifyCh)
	room.NotifyCh = make(chan struct{})
}

func (rm *RoomManager) collectMessagesLocked(room *Room, since int) []RoomMessage {
	out := make([]RoomMessage, 0, len(room.HandshakeMsgs)+len(room.ControlMsgs))
	for _, m := range room.HandshakeMsgs {
		if m.seq > since {
			out = append(out, m.toWire())
		}
	}
	for _, m := range room.ControlMsgs {
		if m.seq > since {
			out = append(out, m.toWire())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}
