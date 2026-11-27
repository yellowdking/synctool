package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/yellowdking/synctool/sdk/go/envelope"
)

// Delivery mode constants for SendOptions / WithDeliveryMode.
const (
	DeliveryAuto  = "auto"
	DeliverySpool = "spool"
	DeliveryPipe  = "pipe"
)

// WithDeliveryMode builds a SendOptions with the specified delivery mode ("auto" | "spool" | "pipe").
func WithDeliveryMode(mode string) SendOptions {
	return SendOptions{DeliveryMode: mode}
}

// NewFromEnv constructs a Client populating missing fields from standard environment variables:
//   - SYNCTOOL_RELAY (or SYNCTOOL_RELAY_URI): synctool://relay?...#k=...
//   - SYNCTOOL_APP: application namespace (default "synctool.cli")
//   - SYNCTOOL_CONFIG: persistent FileKeyStore directory (falls back to in-memory KeyStore when unset)
func NewFromEnv(cfg Config) (*Client, error) {
	if cfg.KeyStore == nil {
		if cfgDir := strings.TrimSpace(os.Getenv("SYNCTOOL_CONFIG")); cfgDir != "" {
			ks, err := envelope.NewFileKeyStore(cfgDir)
			if err != nil {
				return nil, err
			}
			cfg.KeyStore = ks
		} else {
			cfg.KeyStore = envelope.NewMemoryKeyStore()
		}
	}
	if cfg.Relay == nil {
		rawEnv := strings.TrimSpace(os.Getenv("SYNCTOOL_RELAY"))
		if rawEnv == "" {
			rawEnv = strings.TrimSpace(os.Getenv("SYNCTOOL_RELAY_URI"))
		}
		if rawEnv != "" {
			if strings.HasPrefix(strings.ToLower(rawEnv), "synctool://") {
				prof, err := envelope.ParseRelayURI(rawEnv)
				if err != nil {
					return nil, err
				}
				cfg.Relay = prof
			} else if p, err := cfg.KeyStore.GetRelayProfile(rawEnv); err != nil {
				return nil, err
			} else if p != nil {
				cfg.Relay = p
			}
		}
		if cfg.Relay == nil {
			if p, err := cfg.KeyStore.GetDefaultRelayProfile(); err != nil {
				return nil, err
			} else if p != nil {
				cfg.Relay = p
			}
		}
		if cfg.Relay == nil {
			return nil, envelope.NewError(envelope.ErrCodeURIInvalid, false, 0, "no relay configured in Config.Relay, SYNCTOOL_RELAY, or KeyStore", nil)
		}
	}
	if cfg.AppID == "" {
		if envApp := strings.TrimSpace(os.Getenv("SYNCTOOL_APP")); envApp != "" {
			cfg.AppID = envApp
		}
	}
	return New(cfg)
}

// KeyStoreHint exposes the underlying KeyStore for helpers such as ResolveDeviceByIDOrLabel.
func (c *Client) KeyStoreHint() envelope.KeyStore {
	return c.keyStore
}

// SendText is a zero-boilerplate helper that resolves targetDeviceOrLabel and sends an encrypted UTF-8 text parcel.
func (c *Client) SendText(ctx context.Context, targetDeviceOrLabel, text string) (*SendResult, error) {
	card, err := ResolveDeviceByIDOrLabel(c.keyStore, targetDeviceOrLabel)
	if err != nil {
		return nil, err
	}
	return c.SendToDevice(ctx, card.DeviceID, envelope.ParcelText(c.appID, text), SendOptions{DeliveryMode: DeliveryAuto})
}

type mailboxDepositTokenSpec struct {
	TokenID      string `json:"token_id"`
	TokenHashHex string `json:"token_hash_hex"`
}

// SyncMailbox idempotently registers this device's blinded mailbox on the relay and restores all active
// per-peer inbound deposit token hashes recorded in KeyStore (enabling seamless zero-rebind self-healing
// when a nano memory-spool relay restarts). Compatible with both v1.0 and v1.1+ relays.
func (c *Client) SyncMailbox(ctx context.Context) error {
	cards, err := c.keyStore.ListDevices()
	if err != nil {
		return err
	}
	specs := make([]mailboxDepositTokenSpec, 0, len(cards))
	seenTok := make(map[string]struct{}, len(cards))
	for _, card := range cards {
		if card.Revoked || card.InboundTokenID == "" || len(card.InboundTokenHash) != 64 {
			continue
		}
		if card.RelayID != "" && card.RelayID != c.profile.RelayID {
			continue
		}
		if _, dup := seenTok[card.InboundTokenID]; dup {
			continue
		}
		seenTok[card.InboundTokenID] = struct{}{}
		specs = append(specs, mailboxDepositTokenSpec{
			TokenID:      card.InboundTokenID,
			TokenHashHex: strings.ToLower(card.InboundTokenHash),
		})
		if len(specs) >= 16 {
			break
		}
	}

	path := "/v1/mailboxes/" + c.mailboxKeys.MailboxID
	body := map[string]any{
		"auth_pk_b64": base64.RawURLEncoding.EncodeToString(c.mailboxKeys.AuthPub),
	}
	if len(specs) > 0 {
		body["deposit_tokens"] = specs
	}
	resp, err := c.doControl(ctx, http.MethodPut, path, body, reqOptions{
		MailboxID:     c.mailboxKeys.MailboxID,
		MailboxAuthSK: c.mailboxKeys.AuthPriv,
	})
	if envelope.IsCode(err, envelope.ErrCodeSpoolDisabled) {
		return nil
	}
	if err != nil {
		return err
	}

	var regOut struct {
		DepositTokenCount int `json:"deposit_token_count"`
	}
	_ = json.Unmarshal(resp.Body, &regOut)

	// Fallback for v0.1.0 relays / mocks that ignore "deposit_tokens" on PUT: restore individually.
	if len(specs) > 0 && regOut.DepositTokenCount < len(specs) {
		tokPath := "/v1/mailboxes/" + c.mailboxKeys.MailboxID + "/deposit-tokens"
		for _, sp := range specs {
			_, addErr := c.doControl(ctx, http.MethodPost, tokPath, sp, reqOptions{
				MailboxID:     c.mailboxKeys.MailboxID,
				MailboxAuthSK: c.mailboxKeys.AuthPriv,
			})
			if addErr != nil && !envelope.IsCode(addErr, envelope.ErrCodeConflict) && !envelope.IsCode(addErr, envelope.ErrCodeSpoolDisabled) {
				return addErr
			}
		}
	}
	return nil
}
