package envelope

import (
	"errors"
	"fmt"
)

// Frozen cross-language error codes (ENVELOPE_AND_SDK.md §4.2 & PROTOCOL.md §4).
const (
	// A. 15 Wire Error Codes (1-to-1 with PROTOCOL.md §4)
	ErrCodeBadRequest            = "ERR_BAD_REQUEST"
	ErrCodeReplayDetected        = "ERR_REPLAY_DETECTED"
	ErrCodeUnauthorizedToken     = "ERR_UNAUTHORIZED_TOKEN"
	ErrCodeSpoolDisabled         = "ERR_SPOOL_DISABLED"
	ErrCodeDownloadLimitExceeded = "ERR_DOWNLOAD_LIMIT_EXCEEDED"
	ErrCodeNotFound              = "ERR_NOT_FOUND"
	ErrCodeClockSkew             = "ERR_CLOCK_SKEW"
	ErrCodeRoomBusy              = "ERR_ROOM_BUSY"
	ErrCodeInvalidState          = "ERR_INVALID_STATE"
	ErrCodeConflict              = "ERR_CONFLICT"
	ErrCodeRoomBurned            = "ERR_ROOM_BURNED"
	ErrCodeChunkTooLarge         = "ERR_CHUNK_TOO_LARGE"
	ErrCodeOfflineQuotaExceeded  = "ERR_OFFLINE_QUOTA_EXCEEDED"
	ErrCodeRateLimited           = "ERR_RATE_LIMITED"
	ErrCodePipePeerTimeout       = "ERR_PIPE_PEER_TIMEOUT"

	// B. 19 Client, Crypto & Host Error Codes
	ErrCodeRelayUnreachable       = "ERR_RELAY_UNREACHABLE"
	ErrCodeTLSPinMismatch         = "ERR_TLS_PIN_MISMATCH"
	ErrCodeTLSCertInvalid         = "ERR_TLS_CERT_INVALID"
	ErrCodeAuthFailed             = "ERR_AUTH_FAILED"
	ErrCodeHandshakeTimeout       = "ERR_HANDSHAKE_TIMEOUT"
	ErrCodeSASMismatch            = "ERR_SAS_MISMATCH"
	ErrCodeCryptoHandshakeFailed  = "ERR_CRYPTO_HANDSHAKE_FAILED"
	ErrCodeCryptoDecryptFailed    = "ERR_CRYPTO_DECRYPT_FAILED"
	ErrCodeCryptoSignatureInvalid = "ERR_CRYPTO_SIGNATURE_INVALID"
	ErrCodeStreamTruncated        = "ERR_STREAM_TRUNCATED"
	ErrCodeMsgReplayDetected      = "ERR_MSG_REPLAY_DETECTED"
	ErrCodeHashMismatch           = "ERR_HASH_MISMATCH"
	ErrCodeManifestInvalid        = "ERR_MANIFEST_INVALID"
	ErrCodeDeviceUntrusted        = "ERR_DEVICE_UNTRUSTED"
	ErrCodeInterruptedResumable   = "ERR_INTERRUPTED_RESUMABLE"
	ErrCodeURIInvalid             = "ERR_URI_INVALID"
	ErrCodeKeystoreError          = "ERR_KEYSTORE_ERROR"
	ErrCodeStorageIO              = "ERR_STORAGE_IO"
	ErrCodeCancelled              = "ERR_CANCELLED"
)

// SyncError is the unified cross-language structured error envelope (ENVELOPE_AND_SDK.md §4.1).
type SyncError struct {
	Code       string         `json:"code"`
	Retryable  bool           `json:"retryable"`
	HTTPStatus int            `json:"http_status,omitempty"`
	Message    string         `json:"message"`
	Details    map[string]any `json:"details,omitempty"`
	Cause      error          `json:"-"`
}

func (e *SyncError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return e.Code
}

func (e *SyncError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// NewError constructs a SyncError without an underlying cause.
func NewError(code string, retryable bool, httpStatus int, msg string, details map[string]any) *SyncError {
	return &SyncError{
		Code:       code,
		Retryable:  retryable,
		HTTPStatus: httpStatus,
		Message:    msg,
		Details:    details,
	}
}

// WrapError constructs a SyncError wrapping an underlying cause.
func WrapError(code string, retryable bool, httpStatus int, msg string, cause error) *SyncError {
	if msg == "" && cause != nil {
		msg = cause.Error()
	}
	return &SyncError{
		Code:       code,
		Retryable:  retryable,
		HTTPStatus: httpStatus,
		Message:    msg,
		Cause:      cause,
	}
}

// AsSyncError extracts a *SyncError from err if present.
func AsSyncError(err error) (*SyncError, bool) {
	var se *SyncError
	if errors.As(err, &se) {
		return se, true
	}
	return nil, false
}

// IsCode reports whether err is a *SyncError matching code.
func IsCode(err error, code string) bool {
	se, ok := AsSyncError(err)
	return ok && se.Code == code
}

// ExitCode maps a SyncError to the frozen CLI exit codes 0..6 (ENVELOPE_AND_SDK.md §6.1).
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	se, ok := AsSyncError(err)
	if !ok {
		return 1
	}
	switch se.Code {
	case ErrCodeURIInvalid, ErrCodeBadRequest, ErrCodeManifestInvalid:
		return 2
	case ErrCodeRelayUnreachable, ErrCodeAuthFailed, ErrCodeRateLimited,
		ErrCodePipePeerTimeout, ErrCodeHandshakeTimeout, ErrCodeReplayDetected,
		ErrCodeClockSkew, ErrCodeRoomBusy, ErrCodeInvalidState, ErrCodeConflict,
		ErrCodeChunkTooLarge, ErrCodeDownloadLimitExceeded:
		return 3
	case ErrCodeTLSPinMismatch, ErrCodeTLSCertInvalid, ErrCodeSASMismatch,
		ErrCodeRoomBurned, ErrCodeCryptoHandshakeFailed, ErrCodeCryptoDecryptFailed,
		ErrCodeCryptoSignatureInvalid, ErrCodeStreamTruncated, ErrCodeHashMismatch,
		ErrCodeMsgReplayDetected, ErrCodeDeviceUntrusted, ErrCodeUnauthorizedToken:
		return 4
	case ErrCodeSpoolDisabled, ErrCodeOfflineQuotaExceeded, ErrCodeNotFound:
		return 5
	case ErrCodeInterruptedResumable:
		return 6
	default:
		return 1
	}
}
