package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	synccrypto "github.com/yellowdking/synctool/sdk/go/crypto"
	"github.com/yellowdking/synctool/sdk/go/envelope"
)

// --- Flow 1 Handshake Execution (Shared by Pair & OneShot) ---

type hsM1Wire struct {
	ProtoV  int    `json:"proto_v"`
	Mode    int    `json:"mode"`
	Purpose string `json:"purpose"`
	EA      string `json:"e_a,omitempty"`
	NA      string `json:"n_a,omitempty"`
	CommitA string `json:"commit_a,omitempty"`
}

type hsM2Wire struct {
	ProtoV int    `json:"proto_v"`
	Mode   int    `json:"mode"`
	EB     string `json:"e_b"`
	NB     string `json:"n_b"`
	MacB   string `json:"mac_b,omitempty"`
}

type hsM3Wire struct {
	ProtoV int    `json:"proto_v"`
	Mode   int    `json:"mode"`
	EA     string `json:"e_a,omitempty"`
	NA     string `json:"n_a,omitempty"`
	MacA   string `json:"mac_a"`
}

type hsM4Wire struct {
	ProtoV int    `json:"proto_v"`
	Mode   int    `json:"mode"`
	MacB   string `json:"mac_b"`
}

type pairBindWire struct {
	ProtoV int    `json:"proto_v"`
	Op     string `json:"op"` // "pair_bind"
	CT     string `json:"ct"`
}

type pipeCtrlWire struct {
	CtrlSeq uint32 `json:"ctrl_seq"`
	CT      string `json:"ct"`
}

type activeRoomSession struct {
	RoomID  string
	PipeID  string
	Token   string
	LastSeq int
	HS      *synccrypto.HandshakeResult
}

func (c *Client) runInitiatorHandshake(ctx context.Context, purpose string, opts PairOptions) (*activeRoomSession, error) {
	mode := opts.Mode
	if mode == 0 {
		mode = synccrypto.ModeQROOB
	}
	if mode != synccrypto.ModeQROOB && mode != synccrypto.ModeCommitSAS {
		return nil, envelope.NewError(envelope.ErrCodeBadRequest, false, 0, "invalid handshake mode (use 1 or 2)", nil)
	}
	roomID, err := synccrypto.GenerateRoomID()
	if err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "generate room id", err)
	}
	ephA, err := synccrypto.GenerateEphemeralX25519()
	if err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "generate ephemeral x25519", err)
	}
	nA, err := synccrypto.GenerateRandomBytes(synccrypto.HSNonceSize)
	if err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "generate n_a", err)
	}
	pubA := ephA.PublicKey().Bytes()

	var oob []byte
	var commitA [32]byte
	var m1 hsM1Wire
	m1.ProtoV = synccrypto.ProtoVersion
	m1.Mode = mode
	m1.Purpose = purpose

	if mode == synccrypto.ModeQROOB {
		oob, err = synccrypto.GenerateRandomBytes(synccrypto.OOBSecretSize)
		if err != nil {
			return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "generate oob_secret", err)
		}
		defer clear(oob)
		m1.EA = base64.RawURLEncoding.EncodeToString(pubA)
		m1.NA = base64.RawURLEncoding.EncodeToString(nA)
	} else {
		commitA, err = synccrypto.ComputeCommitA(purpose, roomID, pubA, nA)
		if err != nil {
			return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "compute commit_a", err)
		}
		m1.CommitA = base64.RawURLEncoding.EncodeToString(commitA[:])
	}

	m1Bytes, _ := json.Marshal(m1)
	created, err := c.createRoom(ctx, roomID, opts.TTLSec, m1Bytes)
	if err != nil {
		return nil, err
	}
	lastSeq := created.Seq

	offer := &envelope.PairOffer{
		Version:   1,
		RoomID:    roomID,
		Mode:      mode,
		Purpose:   purpose,
		ExpiresAt: created.ExpiresAt,
		OOBSecret: oob,
	}
	if opts.IncludeRelay {
		offer.Endpoint = c.profile.Endpoint
		offer.SPKISHA256 = c.profile.SPKISHA256
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
			Mode:        mode,
			Purpose:     purpose,
			PairURI:     pairURI,
			ExpiresAt:   created.ExpiresAt,
		})
	}

	// Wait for M2 from receiver
	m2Wire, nextSeq, err := c.waitForPeerRoomMessage(ctx, roomID, created.SenderToken, "receiver", lastSeq)
	if err != nil {
		return nil, err
	}
	lastSeq = nextSeq
	m2Raw, err := base64.RawURLEncoding.DecodeString(m2Wire.MsgB64)
	if err != nil {
		c.closeRoom(ctx, roomID, created.SenderToken, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "decode M2 b64", nil)
	}
	var m2 hsM2Wire
	if err := json.Unmarshal(m2Raw, &m2); err != nil {
		c.closeRoom(ctx, roomID, created.SenderToken, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "invalid M2 payload", nil)
	}
	if m2.ProtoV > 1 {
		c.closeRoom(ctx, roomID, created.SenderToken, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeUnsupportedVersion, false, 0, fmt.Sprintf("unsupported peer proto_v %d", m2.ProtoV), map[string]any{"proto_v": m2.ProtoV, "supported_proto_v": 1})
	}
	if m2.ProtoV != 1 || m2.Mode != mode {
		c.closeRoom(ctx, roomID, created.SenderToken, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "invalid M2 payload", nil)
	}
	pubB, err1 := base64.RawURLEncoding.DecodeString(m2.EB)
	nB, err2 := base64.RawURLEncoding.DecodeString(m2.NB)
	if err1 != nil || err2 != nil || len(pubB) != 32 || len(nB) != synccrypto.HSNonceSize {
		c.closeRoom(ctx, roomID, created.SenderToken, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "invalid M2 e_b/n_b", nil)
	}

	var hs *synccrypto.HandshakeResult
	if mode == synccrypto.ModeQROOB {
		hs, err = synccrypto.DeriveQROOBSession(purpose, roomID, ephA, pubB, pubA, nA, pubB, nB, oob)
		if err != nil {
			c.closeRoom(ctx, roomID, created.SenderToken, "verify_failed")
			return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "derive qr_oob session", err)
		}
		macB, err := base64.RawURLEncoding.DecodeString(m2.MacB)
		if err != nil || synccrypto.VerifyMAC(hs.MacB, macB) != nil {
			hs.Zero()
			c.closeRoom(ctx, roomID, created.SenderToken, "verify_failed")
			return nil, envelope.NewError(envelope.ErrCodeSASMismatch, false, 0, "M2 mac_b verification failed (wrong oob_secret or MITM)", nil)
		}
		m3Bytes, _ := json.Marshal(hsM3Wire{
			ProtoV: 1,
			Mode:   mode,
			MacA:   base64.RawURLEncoding.EncodeToString(hs.MacA[:]),
		})
		seq, err := c.postRoomMessage(ctx, roomID, created.SenderToken, "handshake", m3Bytes)
		if err != nil {
			hs.Zero()
			return nil, err
		}
		lastSeq = seq
	} else {
		hs, err = synccrypto.DeriveSASSession(purpose, roomID, ephA, pubB, commitA[:], pubA, nA, pubB, nB)
		if err != nil {
			c.closeRoom(ctx, roomID, created.SenderToken, "verify_failed")
			return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "derive sas session", err)
		}
		// Reveal (E_a, n_a, mac_a) in M3
		m3Bytes, _ := json.Marshal(hsM3Wire{
			ProtoV: 1,
			Mode:   mode,
			EA:     base64.RawURLEncoding.EncodeToString(pubA),
			NA:     base64.RawURLEncoding.EncodeToString(nA),
			MacA:   base64.RawURLEncoding.EncodeToString(hs.MacA[:]),
		})
		seq, err := c.postRoomMessage(ctx, roomID, created.SenderToken, "handshake", m3Bytes)
		if err != nil {
			hs.Zero()
			return nil, err
		}
		lastSeq = seq

		// Wait for M4 (mac_b) from responder
		m4Wire, nextSeq, err := c.waitForPeerRoomMessage(ctx, roomID, created.SenderToken, "receiver", lastSeq)
		if err != nil {
			hs.Zero()
			return nil, err
		}
		lastSeq = nextSeq
		m4Raw, err := base64.RawURLEncoding.DecodeString(m4Wire.MsgB64)
		if err != nil {
			hs.Zero()
			c.closeRoom(ctx, roomID, created.SenderToken, "verify_failed")
			return nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "decode M4 b64", nil)
		}
		var m4 hsM4Wire
		if err := json.Unmarshal(m4Raw, &m4); err != nil || m4.ProtoV != 1 || m4.Mode != mode {
			hs.Zero()
			c.closeRoom(ctx, roomID, created.SenderToken, "verify_failed")
			return nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "invalid M4 payload", nil)
		}
		macB, err := base64.RawURLEncoding.DecodeString(m4.MacB)
		if err != nil || synccrypto.VerifyMAC(hs.MacB, macB) != nil {
			hs.Zero()
			c.closeRoom(ctx, roomID, created.SenderToken, "verify_failed")
			return nil, envelope.NewError(envelope.ErrCodeSASMismatch, false, 0, "M4 mac_b verification failed", nil)
		}

		// Anti-Blind-Click Gate: force user to enter responder's 6-digit SAS (up to 2 typo retries).
		if opts.OnSASInput == nil {
			hs.Zero()
			c.closeRoom(ctx, roomID, created.SenderToken, "cancelled")
			return nil, envelope.NewError(envelope.ErrCodeSASMismatch, false, 0, "mode=2 requires OnSASInput callback", nil)
		}
		matched := false
		for try := 0; try < 3; try++ {
			entered, err := opts.OnSASInput()
			if err != nil {
				hs.Zero()
				c.closeRoom(ctx, roomID, created.SenderToken, "rejected")
				return nil, envelope.WrapError(envelope.ErrCodeSASMismatch, false, 0, "SAS verification rejected", err)
			}
			if synccrypto.VerifySAS(hs.SASStr, entered) == nil {
				matched = true
				break
			}
		}
		if !matched {
			hs.Zero()
			c.closeRoom(ctx, roomID, created.SenderToken, "verify_failed")
			return nil, envelope.NewError(envelope.ErrCodeSASMismatch, false, 0, "SAS mismatch — room burned", nil)
		}
	}

	return &activeRoomSession{
		RoomID:  roomID,
		PipeID:  created.PipeID,
		Token:   created.SenderToken,
		LastSeq: lastSeq,
		HS:      hs,
	}, nil
}

func (c *Client) runResponderHandshake(ctx context.Context, joined *roomJoinResp, m1 hsM1Wire, oobSecret []byte, onSASDisplay func(string)) (*activeRoomSession, error) {
	roomID := joined.RoomID
	token := joined.ReceiverToken
	lastSeq := joined.Seq
	mode := m1.Mode
	purpose := m1.Purpose

	ephB, err := synccrypto.GenerateEphemeralX25519()
	if err != nil {
		c.closeRoom(ctx, roomID, token, "cancelled")
		return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "generate ephemeral x25519", err)
	}
	nB, err := synccrypto.GenerateRandomBytes(synccrypto.HSNonceSize)
	if err != nil {
		c.closeRoom(ctx, roomID, token, "cancelled")
		return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "generate n_b", err)
	}
	pubB := ephB.PublicKey().Bytes()

	var hs *synccrypto.HandshakeResult
	if mode == synccrypto.ModeQROOB {
		if len(oobSecret) != synccrypto.OOBSecretSize {
			c.closeRoom(ctx, roomID, token, "verify_failed")
			return nil, envelope.NewError(envelope.ErrCodeURIInvalid, false, 0, "mode=1 requires 16B oob_secret", nil)
		}
		pubA, err1 := base64.RawURLEncoding.DecodeString(m1.EA)
		nA, err2 := base64.RawURLEncoding.DecodeString(m1.NA)
		if err1 != nil || err2 != nil || len(pubA) != 32 || len(nA) != synccrypto.HSNonceSize {
			c.closeRoom(ctx, roomID, token, "verify_failed")
			return nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "invalid M1 e_a/n_a", nil)
		}
		hs, err = synccrypto.DeriveQROOBSession(purpose, roomID, ephB, pubA, pubA, nA, pubB, nB, oobSecret)
		if err != nil {
			c.closeRoom(ctx, roomID, token, "verify_failed")
			return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "derive qr_oob session", err)
		}
		m2Bytes, _ := json.Marshal(hsM2Wire{
			ProtoV: 1,
			Mode:   mode,
			EB:     base64.RawURLEncoding.EncodeToString(pubB),
			NB:     base64.RawURLEncoding.EncodeToString(nB),
			MacB:   base64.RawURLEncoding.EncodeToString(hs.MacB[:]),
		})
		seq, err := c.postRoomMessage(ctx, roomID, token, "handshake", m2Bytes)
		if err != nil {
			hs.Zero()
			return nil, err
		}
		lastSeq = seq

		m3Wire, nextSeq, err := c.waitForPeerRoomMessage(ctx, roomID, token, "sender", lastSeq)
		if err != nil {
			hs.Zero()
			return nil, err
		}
		lastSeq = nextSeq
		m3Raw, err := base64.RawURLEncoding.DecodeString(m3Wire.MsgB64)
		if err != nil {
			hs.Zero()
			c.closeRoom(ctx, roomID, token, "verify_failed")
			return nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "decode M3", nil)
		}
		var m3 hsM3Wire
		if err := json.Unmarshal(m3Raw, &m3); err != nil || m3.ProtoV != 1 || m3.Mode != mode {
			hs.Zero()
			c.closeRoom(ctx, roomID, token, "verify_failed")
			return nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "invalid M3", nil)
		}
		macA, err := base64.RawURLEncoding.DecodeString(m3.MacA)
		if err != nil || synccrypto.VerifyMAC(hs.MacA, macA) != nil {
			hs.Zero()
			c.closeRoom(ctx, roomID, token, "verify_failed")
			return nil, envelope.NewError(envelope.ErrCodeSASMismatch, false, 0, "M3 mac_a verification failed", nil)
		}
	} else {
		commitA, err := base64.RawURLEncoding.DecodeString(m1.CommitA)
		if err != nil || len(commitA) != 32 {
			c.closeRoom(ctx, roomID, token, "verify_failed")
			return nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "invalid M1 commit_a", nil)
		}
		// Post M2 (e_b, n_b) ONLY after locking M1 commit_a
		m2Bytes, _ := json.Marshal(hsM2Wire{
			ProtoV: 1,
			Mode:   mode,
			EB:     base64.RawURLEncoding.EncodeToString(pubB),
			NB:     base64.RawURLEncoding.EncodeToString(nB),
		})
		seq, err := c.postRoomMessage(ctx, roomID, token, "handshake", m2Bytes)
		if err != nil {
			return nil, err
		}
		lastSeq = seq

		// Wait for M3 reveal (e_a, n_a, mac_a)
		m3Wire, nextSeq, err := c.waitForPeerRoomMessage(ctx, roomID, token, "sender", lastSeq)
		if err != nil {
			return nil, err
		}
		lastSeq = nextSeq
		m3Raw, err := base64.RawURLEncoding.DecodeString(m3Wire.MsgB64)
		if err != nil {
			c.closeRoom(ctx, roomID, token, "verify_failed")
			return nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "decode M3", nil)
		}
		var m3 hsM3Wire
		if err := json.Unmarshal(m3Raw, &m3); err != nil || m3.ProtoV != 1 || m3.Mode != mode {
			c.closeRoom(ctx, roomID, token, "verify_failed")
			return nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "invalid M3", nil)
		}
		pubA, err1 := base64.RawURLEncoding.DecodeString(m3.EA)
		nA, err2 := base64.RawURLEncoding.DecodeString(m3.NA)
		macA, err3 := base64.RawURLEncoding.DecodeString(m3.MacA)
		if err1 != nil || err2 != nil || err3 != nil || len(pubA) != 32 || len(nA) != synccrypto.HSNonceSize {
			c.closeRoom(ctx, roomID, token, "verify_failed")
			return nil, envelope.NewError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "invalid M3 fields", nil)
		}
		hs, err = synccrypto.DeriveSASSession(purpose, roomID, ephB, pubA, commitA, pubA, nA, pubB, nB)
		if err != nil {
			c.closeRoom(ctx, roomID, token, "verify_failed")
			if errors.Is(err, synccrypto.ErrCommitMismatch) {
				return nil, envelope.NewError(envelope.ErrCodeSASMismatch, false, 0, "M3 commit_a mismatch — room burned", nil)
			}
			return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "derive sas session", err)
		}
		if synccrypto.VerifyMAC(hs.MacA, macA) != nil {
			hs.Zero()
			c.closeRoom(ctx, roomID, token, "verify_failed")
			return nil, envelope.NewError(envelope.ErrCodeSASMismatch, false, 0, "M3 mac_a mismatch — room burned", nil)
		}

		// Send M4 (mac_b) and display 6-digit SAS for initiator entry
		m4Bytes, _ := json.Marshal(hsM4Wire{
			ProtoV: 1,
			Mode:   mode,
			MacB:   base64.RawURLEncoding.EncodeToString(hs.MacB[:]),
		})
		seq, err = c.postRoomMessage(ctx, roomID, token, "handshake", m4Bytes)
		if err != nil {
			hs.Zero()
			return nil, err
		}
		lastSeq = seq
		if onSASDisplay != nil {
			onSASDisplay(hs.SASStr)
		}
	}

	return &activeRoomSession{
		RoomID:  roomID,
		PipeID:  joined.PipeID,
		Token:   token,
		LastSeq: lastSeq,
		HS:      hs,
	}, nil
}

// --- Flow 1 Device Binding (StartDeviceBind / AcceptDeviceBind) ---

func (c *Client) buildLocalPairBind(ctx context.Context, label string) (envelope.PairBindPayload, string, string, error) {
	if label == "" {
		label = c.deviceLabel
	}
	issuedAt := time.Now().Unix()
	cardSig, err := synccrypto.SignDeviceCard(c.deviceKeys.SignPriv, c.deviceKeys.KEMPubBytes[:], issuedAt)
	if err != nil {
		return envelope.PairBindPayload{}, "", "", envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "sign device card", err)
	}
	payload := envelope.PairBindPayload{
		DeviceCard: envelope.DeviceCardPayload{
			DeviceID: c.deviceKeys.DeviceID,
			SignPK:   base64.RawURLEncoding.EncodeToString(c.deviceKeys.SignPub),
			KEMPK:    base64.RawURLEncoding.EncodeToString(c.deviceKeys.KEMPubBytes[:]),
			IssuedAt: issuedAt,
			CardSig:  base64.RawURLEncoding.EncodeToString(cardSig),
			Label:    label,
			Platform: c.platform,
		},
	}

	caps, err := c.Capabilities(ctx)
	if err != nil {
		return envelope.PairBindPayload{}, "", "", err
	}
	var inboundTokenID, inboundTokenHash string
	if caps.Spool.Enabled {
		if err := c.EnsureMailboxRegistered(ctx); err != nil {
			return envelope.PairBindPayload{}, "", "", err
		}
		tokID, tokHash, rawTok, err := c.registerPeerDepositToken(ctx)
		if err != nil {
			return envelope.PairBindPayload{}, "", "", err
		}
		inboundTokenID = tokID
		inboundTokenHash = tokHash
		payload.Mailbox = &envelope.MailboxBindPayload{
			RelayOrigin:  c.profile.Endpoint,
			MailboxID:    c.mailboxKeys.MailboxID,
			DepositToken: rawTok,
		}
	}
	return payload, inboundTokenID, inboundTokenHash, nil
}

func (c *Client) verifyAndSavePeerBind(peerBind envelope.PairBindPayload, inboundTokenID, inboundTokenHash string) (*envelope.DeviceCard, error) {
	signPK, err1 := base64.RawURLEncoding.DecodeString(peerBind.DeviceCard.SignPK)
	kemPK, err2 := base64.RawURLEncoding.DecodeString(peerBind.DeviceCard.KEMPK)
	cardSig, err3 := base64.RawURLEncoding.DecodeString(peerBind.DeviceCard.CardSig)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, envelope.NewError(envelope.ErrCodeCryptoSignatureInvalid, false, 0, "invalid peer device card encoding", nil)
	}
	if err := synccrypto.VerifyDeviceCard(peerBind.DeviceCard.DeviceID, signPK, kemPK, peerBind.DeviceCard.IssuedAt, cardSig); err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeCryptoSignatureInvalid, false, 0, "peer device card signature invalid", err)
	}
	card := envelope.DeviceCard{
		DeviceID:         strings.ToLower(peerBind.DeviceCard.DeviceID),
		Label:            peerBind.DeviceCard.Label,
		Platform:         peerBind.DeviceCard.Platform,
		SignPK:           peerBind.DeviceCard.SignPK,
		KEMPK:            peerBind.DeviceCard.KEMPK,
		IssuedAt:         peerBind.DeviceCard.IssuedAt,
		CardSig:          peerBind.DeviceCard.CardSig,
		RelayOrigin:      c.profile.Endpoint,
		RelayID:          c.profile.RelayID,
		InboundTokenID:   inboundTokenID,
		InboundTokenHash: inboundTokenHash,
		PairedAt:         time.Now().Unix(),
	}
	if peerBind.Mailbox != nil {
		card.RelayOrigin = peerBind.Mailbox.RelayOrigin
		if canon, err := synccrypto.CanonicalRelayOrigin(peerBind.Mailbox.RelayOrigin); err == nil {
			card.RelayOrigin = canon
			card.RelayID = synccrypto.DeriveRelayID(canon)
		}
		card.MailboxID = peerBind.Mailbox.MailboxID
		card.OutboundDepositToken = peerBind.Mailbox.DepositToken
	}
	if err := c.keyStore.PutDevice(card); err != nil {
		return nil, err
	}
	return &card, nil
}

// StartDeviceBind initiates a Flow 1 bidirectional DeviceCard pairing (compatible with --spool=off).
func (c *Client) StartDeviceBind(ctx context.Context, opts PairOptions) (*envelope.DeviceCard, error) {
	sess, err := c.runInitiatorHandshake(ctx, synccrypto.PurposePair, opts)
	if err != nil {
		return nil, err
	}
	defer sess.HS.Zero()

	myBind, inboundTokenID, inboundTokenHash, err := c.buildLocalPairBind(ctx, opts.Label)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "cancelled")
		return nil, err
	}
	myJSON, _ := json.Marshal(myBind)
	ctA, err := synccrypto.SealPairBind(sess.HS.SessionKey, sess.HS.PRK[:], sess.HS.TH[:], true, myJSON)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "cancelled")
		return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "seal pair_bind A", err)
	}
	frameA, _ := json.Marshal(pairBindWire{
		ProtoV: 1,
		Op:     "pair_bind",
		CT:     base64.RawURLEncoding.EncodeToString(ctA),
	})
	seq, err := c.postRoomMessage(ctx, sess.RoomID, sess.Token, "handshake", frameA)
	if err != nil {
		return nil, err
	}
	sess.LastSeq = seq

	peerMsg, _, err := c.waitForPeerRoomMessage(ctx, sess.RoomID, sess.Token, "receiver", sess.LastSeq)
	if err != nil {
		return nil, err
	}
	peerRaw, err := base64.RawURLEncoding.DecodeString(peerMsg.MsgB64)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decode peer pair_bind", nil)
	}
	var pbWire pairBindWire
	if err := json.Unmarshal(peerRaw, &pbWire); err != nil || pbWire.Op != "pair_bind" {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "invalid peer pair_bind envelope", nil)
	}
	ctB, err := base64.RawURLEncoding.DecodeString(pbWire.CT)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decode peer pair_bind ct", nil)
	}
	ptB, err := synccrypto.OpenPairBind(sess.HS.SessionKey, sess.HS.PRK[:], sess.HS.TH[:], false, ctB)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decrypt peer pair_bind", err)
	}
	var peerBind envelope.PairBindPayload
	if err := json.Unmarshal(ptB, &peerBind); err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "parse peer pair_bind", err)
	}
	card, err := c.verifyAndSavePeerBind(peerBind, inboundTokenID, inboundTokenHash)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, err
	}
	c.closeRoom(ctx, sess.RoomID, sess.Token, "completed")
	return card, nil
}

// AcceptDeviceBind accepts a Flow 1 pairing offer (synctool://pair URI or 8-char room code).
func (c *Client) AcceptDeviceBind(ctx context.Context, pairInput string, opts PairOptions) (*envelope.DeviceCard, error) {
	roomID, oob, err := parseRoomInput(pairInput)
	if err != nil {
		return nil, err
	}
	joined, m1, err := c.joinAndReadM1(ctx, roomID)
	if err != nil {
		return nil, err
	}
	if m1.Purpose != synccrypto.PurposePair {
		c.closeRoom(ctx, roomID, joined.ReceiverToken, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeInvalidState, false, 0, "room purpose is not pair", nil)
	}
	sess, err := c.runResponderHandshake(ctx, joined, m1, oob, opts.OnSASDisplay)
	if err != nil {
		return nil, err
	}
	defer sess.HS.Zero()

	// Wait for Alice's encrypted PairBindPayload
	peerMsg, nextSeq, err := c.waitForPeerRoomMessage(ctx, sess.RoomID, sess.Token, "sender", sess.LastSeq)
	if err != nil {
		return nil, err
	}
	sess.LastSeq = nextSeq
	peerRaw, err := base64.RawURLEncoding.DecodeString(peerMsg.MsgB64)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decode peer pair_bind", nil)
	}
	var pbWire pairBindWire
	if err := json.Unmarshal(peerRaw, &pbWire); err != nil || pbWire.Op != "pair_bind" {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "invalid peer pair_bind envelope", nil)
	}
	ctA, err := base64.RawURLEncoding.DecodeString(pbWire.CT)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.NewError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decode peer pair_bind ct", nil)
	}
	ptA, err := synccrypto.OpenPairBind(sess.HS.SessionKey, sess.HS.PRK[:], sess.HS.TH[:], true, ctA)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "decrypt peer pair_bind", err)
	}
	var peerBind envelope.PairBindPayload
	if err := json.Unmarshal(ptA, &peerBind); err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, envelope.WrapError(envelope.ErrCodeCryptoDecryptFailed, false, 0, "parse peer pair_bind", err)
	}

	myBind, inboundTokenID, inboundTokenHash, err := c.buildLocalPairBind(ctx, opts.Label)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "cancelled")
		return nil, err
	}
	card, err := c.verifyAndSavePeerBind(peerBind, inboundTokenID, inboundTokenHash)
	if err != nil {
		c.closeRoom(ctx, sess.RoomID, sess.Token, "verify_failed")
		return nil, err
	}
	myJSON, _ := json.Marshal(myBind)
	ctB, err := synccrypto.SealPairBind(sess.HS.SessionKey, sess.HS.PRK[:], sess.HS.TH[:], false, myJSON)
	if err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeCryptoHandshakeFailed, false, 0, "seal pair_bind B", err)
	}
	frameB, _ := json.Marshal(pairBindWire{
		ProtoV: 1,
		Op:     "pair_bind",
		CT:     base64.RawURLEncoding.EncodeToString(ctB),
	})
	if _, err := c.postRoomMessage(ctx, sess.RoomID, sess.Token, "handshake", frameB); err != nil {
		return nil, err
	}
	return card, nil
}
