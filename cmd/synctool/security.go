package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

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

func redactQuerySecrets(rawQueryPart string) string {
	if rawQueryPart == "" {
		return ""
	}
	var out strings.Builder
	out.Grow(len(rawQueryPart))
	i := 0
	for i < len(rawQueryPart) {
		if (rawQueryPart[i] == '?' || rawQueryPart[i] == '&') && i+2 < len(rawQueryPart) {
			next2 := strings.ToLower(rawQueryPart[i+1 : i+3])
			if next2 == "k=" || next2 == "s=" {
				out.WriteString(rawQueryPart[i : i+3])
				out.WriteString("[REDACTED]")
				j := i + 3
				for j < len(rawQueryPart) && rawQueryPart[j] != '&' && rawQueryPart[j] != '#' {
					j++
				}
				i = j
				continue
			}
		}
		out.WriteByte(rawQueryPart[i])
		i++
	}
	return out.String()
}

// redactSecretsInText scrubs URI #fragments (synctool://...#... or standalone #k=/#s=),
// accidental ?k=/&s= query secrets, and URL userinfo credentials from diagnostic and error messages.
func redactSecretsInText(s string) string {
	if s == "" || !strings.ContainsAny(s, "#@?&") {
		return s
	}
	var out strings.Builder
	out.Grow(len(s))
	i := 0
	for i < len(s) {
		// Redact synctool://...#<fragment> (and any accidental ?k=/&s= in query)
		if hasCaseInsensitivePrefix(s[i:], "synctool://") {
			end := findTokenEnd(s, i)
			token := s[i:end]
			if h := strings.IndexByte(token, '#'); h >= 0 {
				out.WriteString(redactQuerySecrets(token[:h]))
				out.WriteString("#[REDACTED]")
			} else {
				out.WriteString(redactQuerySecrets(token))
			}
			i = end
			continue
		}
		// Redact http(s)://user:pass@host userinfo, accidental ?k=/&s=, and #fragment if present
		if hasCaseInsensitivePrefix(s[i:], "https://") || hasCaseInsensitivePrefix(s[i:], "http://") {
			end := findTokenEnd(s, i)
			token := s[i:end]
			schemeSep := strings.Index(token, "://") + 3
			rest := token[schemeSep:]
			slash := strings.IndexAny(rest, "/?#")
			authority := rest
			tail := ""
			if slash >= 0 {
				authority = rest[:slash]
				tail = rest[slash:]
			}
			if at := strings.LastIndexByte(authority, '@'); at >= 0 {
				authority = "[REDACTED]@" + authority[at+1:]
			}
			if h := strings.IndexByte(tail, '#'); h >= 0 {
				tail = redactQuerySecrets(tail[:h]) + "#[REDACTED]"
			} else {
				tail = redactQuerySecrets(tail)
			}
			out.WriteString(token[:schemeSep])
			out.WriteString(authority)
			out.WriteString(tail)
			i = end
			continue
		}
		// Redact standalone #k=... / #s=... fragments or ?k=... / &s=... query tokens
		if (s[i] == '#' || s[i] == '?' || s[i] == '&') && i+2 < len(s) {
			next2 := strings.ToLower(s[i+1 : i+3])
			if next2 == "k=" || next2 == "s=" {
				end := findTokenEnd(s, i)
				if s[i] == '#' {
					out.WriteString("#[REDACTED]")
					i = end
					continue
				}
				out.WriteString(s[i : i+3])
				out.WriteString("[REDACTED]")
				j := i + 3
				for j < end && s[j] != '&' && s[j] != '#' {
					j++
				}
				i = j
				continue
			}
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}

func hasCaseInsensitivePrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

func findTokenEnd(s string, start int) int {
	for j := start; j < len(s); j++ {
		switch s[j] {
		case ' ', '\t', '\r', '\n', '"', '\'', '<', '>', ')', ']':
			return j
		}
	}
	return len(s)
}

func sanitizeSyncError(se *envelope.SyncError) *envelope.SyncError {
	if se == nil {
		return nil
	}
	cp := *se
	cp.Message = redactSecretsInText(cp.Message)
	if len(se.Details) > 0 {
		det := make(map[string]any, len(se.Details))
		for k, v := range se.Details {
			if sv, ok := v.(string); ok {
				det[k] = redactSecretsInText(sv)
			} else {
				det[k] = v
			}
		}
		cp.Details = det
	}
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

func isBidiOrControlRune(r rune) bool {
	if r == 0 || unicode.IsControl(r) {
		return true
	}
	// Unicode BiDi override / embedding / isolate runes (defeat RLO extension spoofing).
	if r == 0x200E || r == 0x200F || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
		return true
	}
	return false
}

func isWindowsReservedDeviceStem(stem string) bool {
	s := strings.ToUpper(strings.TrimSpace(stem))
	switch s {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	for _, pfx := range []string{"COM", "LPT"} {
		if strings.HasPrefix(s, pfx) {
			rest := strings.TrimPrefix(s, pfx)
			if len(rest) == 1 && rest[0] >= '1' && rest[0] <= '9' {
				return true
			}
			// Windows also treats superscript digits ¹²³ (U+00B9, U+00B2, U+00B3) as device ports.
			if rest == "\u00b9" || rest == "\u00b2" || rest == "\u00b3" {
				return true
			}
		}
	}
	return false
}

func trimDotsAndSpaces(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return r == '.' || unicode.IsSpace(r)
	})
}

func truncateUTF8Safe(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	ext := ""
	stem := s
	if dot := strings.LastIndexByte(s, '.'); dot > 0 && len(s)-dot <= 16 {
		ext = s[dot:]
		stem = s[:dot]
	}
	budget := maxBytes - len(ext)
	if budget <= 0 {
		budget = maxBytes
		ext = ""
		stem = s
	}
	var b strings.Builder
	for len(stem) > 0 {
		r, sz := utf8.DecodeRuneInString(stem)
		if r == utf8.RuneError && sz == 1 {
			stem = stem[1:]
			continue
		}
		if b.Len()+sz > budget {
			break
		}
		b.WriteRune(r)
		stem = stem[sz:]
	}
	trimmedStem := trimDotsAndSpaces(b.String())
	if trimmedStem == "" {
		return "blob.bin"
	}
	return trimmedStem + ext
}

// sanitizeOutputFilename is an idempotent, cross-platform defense-in-depth filename sanitizer:
// strips path components, C0/C1 control & BiDi override runes, leading/trailing dots & spaces,
// prefixes Windows reserved device names (NUL, CON, COM1..9, LPT1..9, etc.) with '_',
// and truncates on valid UTF-8 rune boundaries (<= 200 bytes).
func sanitizeOutputFilename(name string) string {
	normalized := strings.ReplaceAll(name, "\\", "/")
	if idx := strings.LastIndexByte(normalized, '/'); idx >= 0 {
		normalized = normalized[idx+1:]
	}
	var b strings.Builder
	for len(normalized) > 0 {
		r, sz := utf8.DecodeRuneInString(normalized)
		normalized = normalized[sz:]
		if r == utf8.RuneError && sz == 1 {
			b.WriteByte('_')
			continue
		}
		if isBidiOrControlRune(r) {
			continue
		}
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	out := trimDotsAndSpaces(b.String())
	if out == "" || out == "." || out == ".." {
		return "blob.bin"
	}
	out = truncateUTF8Safe(out, maxSafeFilenameBytes)
	out = trimDotsAndSpaces(out)
	if out == "" || out == "." || out == ".." {
		return "blob.bin"
	}

	stem := out
	if dot := strings.IndexByte(out, '.'); dot >= 0 {
		stem = out[:dot]
	}
	if isWindowsReservedDeviceStem(stem) {
		out = "_" + out
		out = truncateUTF8Safe(out, maxSafeFilenameBytes)
	}
	return out
}

// saveReceivedParcelToOutDir safely materializes verified parcel attachments into outDir:
//   - rejects symlinked outDir;
//   - re-sanitizes filenames (traversal, control/BiDi chars, Windows reserved device names);
//   - opens destination exclusively with O_CREATE|O_EXCL (0600), NEVER following dangling symlinks
//     and NEVER clobbering existing files (auto-increments name_1.ext, name_2.ext on collision).
func saveReceivedParcelToOutDir(outDir string, p envelope.ReceivedParcel) ([]string, error) {
	if len(p.Blobs) == 0 {
		return []string{}, nil
	}
	cleanOut := filepath.Clean(outDir)
	if fi, err := os.Lstat(cleanOut); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, envelope.NewError(envelope.ErrCodeStorageIO, false, 0, "refusing symlinked output directory", nil)
		}
		if !fi.IsDir() {
			return nil, envelope.NewError(envelope.ErrCodeStorageIO, false, 0, "output path is not a directory", nil)
		}
	} else if !os.IsNotExist(err) {
		return nil, envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "stat out dir", err)
	}
	if err := os.MkdirAll(cleanOut, 0o700); err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "create out dir", err)
	}
	absOut, err := filepath.Abs(cleanOut)
	if err != nil {
		return nil, envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "resolve out dir", err)
	}

	saved := make([]string, 0, len(p.Blobs))
	for _, b := range p.Blobs {
		rawName := b.SafeName
		if rawName == "" {
			rawName = b.Descriptor.Name
		}
		safeBase := sanitizeOutputFilename(rawName)
		dst, err := writeExclusiveVerifiedBlob(absOut, cleanOut, safeBase, b.SafePath)
		if err != nil {
			return nil, err
		}
		saved = append(saved, dst)
	}
	return saved, nil
}

func splitStemExt(safeBase string) (stem, ext string) {
	if dot := strings.LastIndexByte(safeBase, '.'); dot > 0 {
		return safeBase[:dot], safeBase[dot:]
	}
	return safeBase, ""
}

func writeExclusiveVerifiedBlob(absOut, outDir, safeBase, srcPath string) (string, error) {
	srcInfo, err := os.Lstat(srcPath)
	if err != nil || !srcInfo.Mode().IsRegular() {
		return "", envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "verified temp blob missing or irregular", err)
	}
	in, err := os.Open(srcPath)
	if err != nil {
		return "", envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "open verified temp blob", err)
	}
	defer in.Close()

	stem, ext := splitStemExt(safeBase)
	var outFile *os.File
	var chosenPath string
	for attempt := 0; attempt < 10000; attempt++ {
		candName := safeBase
		if attempt > 0 {
			candName = truncateUTF8Safe(fmt.Sprintf("%s_%d%s", stem, attempt, ext), maxSafeFilenameBytes)
		}
		candPath := filepath.Join(outDir, candName)
		absCand, absErr := filepath.Abs(candPath)
		if absErr != nil {
			return "", envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "resolve output file path", absErr)
		}
		rel, relErr := filepath.Rel(absOut, absCand)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.Dir(rel) != "." {
			return "", envelope.NewError(envelope.ErrCodeStorageIO, false, 0, "refusing path escape outside output directory", nil)
		}
		if _, lerr := os.Lstat(candPath); lerr == nil {
			// Path or symlink (including dangling symlink) already exists; try next suffix.
			continue
		}
		f, oerr := os.OpenFile(candPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if oerr != nil {
			if os.IsExist(oerr) {
				continue
			}
			return "", envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "create output file", oerr)
		}
		outFile = f
		chosenPath = candPath
		break
	}
	if outFile == nil {
		return "", envelope.NewError(envelope.ErrCodeStorageIO, false, 0, "unable to allocate non-colliding output filename", nil)
	}

	if _, copyErr := io.Copy(outFile, in); copyErr != nil {
		_ = outFile.Close()
		_ = os.Remove(chosenPath)
		return "", envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "write output file", copyErr)
	}
	if closeErr := outFile.Close(); closeErr != nil {
		_ = os.Remove(chosenPath)
		return "", envelope.WrapError(envelope.ErrCodeStorageIO, false, 0, "close output file", closeErr)
	}
	_ = in.Close()
	_ = os.Remove(srcPath)
	return chosenPath, nil
}
