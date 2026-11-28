package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/yellowdking/synctool/sdk/go/envelope"
)

const (
	envConfig   = "SYNCTOOL_CONFIG"
	envRelay    = "SYNCTOOL_RELAY"
	envRelayURI = "SYNCTOOL_RELAY_URI"
	envPairURI  = "SYNCTOOL_PAIR_URI"
	envApp      = "SYNCTOOL_APP"

	maxSafeFilenameBytes = 200
)

// scrubProcessArgs redacts any #fragment secrets present in os.Args in-place so
// in-process inspection cannot accidentally dump raw #k= or #s= credentials.
func scrubProcessArgs(procArgs []string) {
	for i := 1; i < len(procArgs); i++ {
		if containsURISecretFragment(procArgs[i]) {
			procArgs[i] = redactSecretsInText(procArgs[i])
		}
	}
}

// containsURISecretFragment reports whether s embeds a synctool URI fragment or accidental query carrying k= or s= secrets.
func containsURISecretFragment(s string) bool {
	lower := strings.ToLower(s)
	if idx := strings.IndexByte(lower, '#'); idx >= 0 && idx+1 < len(lower) {
		for _, kv := range strings.Split(lower[idx+1:], "&") {
			if strings.HasPrefix(kv, "k=") || strings.HasPrefix(kv, "s=") {
				return true
			}
		}
	}
	if strings.Contains(lower, "://") {
		if q := strings.IndexByte(lower, '?'); q >= 0 && q+1 < len(lower) {
			qPart := lower[q+1:]
			if h := strings.IndexByte(qPart, '#'); h >= 0 {
				qPart = qPart[:h]
			}
			for _, kv := range strings.Split(qPart, "&") {
				if strings.HasPrefix(kv, "k=") || strings.HasPrefix(kv, "s=") {
					return true
				}
			}
		}
	}
	return false
}

// warnSecretOnArgv emits a non-fatal security notice on stderr (never stdout, preserving --json)
// when a caller passes a secret-bearing URI directly on the command line.
func warnSecretOnArgv(opts globalOpts, stderr io.Writer, raw string) {
	if opts.quiet || stderr == nil || !containsURISecretFragment(raw) {
		return
	}
	_, _ = fmt.Fprintln(stderr, "warning: secret URI fragment passed via command-line arguments may be visible in local process listings; prefer --stdin or SYNCTOOL_RELAY / SYNCTOOL_PAIR_URI")
}

// redactSecretsInText delegates to envelope.RedactMessage so CLI and SDK share one authoritative redaction engine.
func redactSecretsInText(s string) string {
	return envelope.RedactMessage(s)
}

func hasCaseInsensitivePrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

func sanitizeSyncError(se *envelope.SyncError) *envelope.SyncError {
	if se == nil {
		return nil
	}
	cp := *se
	cp.Message = envelope.RedactMessage(cp.Message)
	cp.Details = envelope.RedactDetails(se.Details)
	return &cp
}

// ensurePrivateDir creates or tightens dir to mode 0700 and rejects symlinks.
func ensurePrivateDir(dir string) error {
	cleanDir := filepath.Clean(dir)
	if fi, err := os.Lstat(cleanDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return envelope.NewError(envelope.ErrCodeKeystoreError, false, 0, "refusing symlinked directory "+cleanDir, nil)
		}
		if !fi.IsDir() {
			return envelope.NewError(envelope.ErrCodeKeystoreError, false, 0, "path is not a directory: "+cleanDir, nil)
		}
	}
	if err := os.MkdirAll(cleanDir, 0o700); err != nil {
		return envelope.WrapError(envelope.ErrCodeKeystoreError, false, 0, "create private directory", err)
	}
	_ = os.Chmod(cleanDir, 0o700)
	return nil
}

// readBoundedBytes reads at most maxBytes from r and returns ERR_MANIFEST_INVALID if exceeded.
func readBoundedBytes(r io.Reader, maxBytes int64, exceedMsg string) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "read input", err)
	}
	if int64(len(raw)) > maxBytes {
		return nil, envelope.NewError(envelope.ErrCodeManifestInvalid, false, 0, exceedMsg, nil)
	}
	return raw, nil
}

// sanitizeOutputFilename delegates to envelope.SanitizeFilename (unified CONIN$/CONOUT$/Bidi/UTF-8 rules).
func sanitizeOutputFilename(name string) string {
	return envelope.SanitizeFilename(name)
}

// saveReceivedParcelToOutDir delegates to envelope.ReceivedBlob.SaveToDir so every saved attachment
// undergoes symlink/Lstat checks, non-clobbering O_EXCL creation, and mandatory out.Sync() (fsync) before ACK burn.
func saveReceivedParcelToOutDir(outDir string, p envelope.ReceivedParcel) ([]string, error) {
	if len(p.Blobs) == 0 {
		return []string{}, nil
	}
	saved := make([]string, 0, len(p.Blobs))
	for _, b := range p.Blobs {
		dst, err := b.SaveToDir(outDir)
		if err != nil {
			return nil, err
		}
		saved = append(saved, dst)
	}
	return saved, nil
}
