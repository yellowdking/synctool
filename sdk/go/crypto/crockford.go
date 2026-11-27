package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
)

const (
	// CrockfordAlphabet is the standard 32-character Crockford Base32 alphabet.
	CrockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	// RoomIDLength is the canonical length of a room_id (8 chars = 40 bits).
	RoomIDLength = 8
	// RoomIDRawBytes is the raw byte length of a room_id (5 bytes = 40 bits).
	RoomIDRawBytes = 5
)

var (
	// ErrInvalidRoomID indicates a malformed Crockford Base32 room_id.
	ErrInvalidRoomID = errors.New("invalid crockford base32 room_id")

	crockfordDecodeTable [256]int8
)

func init() {
	for i := range crockfordDecodeTable {
		crockfordDecodeTable[i] = -1
	}
	for i := 0; i < len(CrockfordAlphabet); i++ {
		c := CrockfordAlphabet[i]
		crockfordDecodeTable[c] = int8(i)
		if c >= 'A' && c <= 'Z' {
			crockfordDecodeTable[c+'a'-'A'] = int8(i)
		}
	}
	// Standard Crockford equivalences: O/o -> 0, I/i/L/l -> 1
	crockfordDecodeTable['O'] = 0
	crockfordDecodeTable['o'] = 0
	crockfordDecodeTable['I'] = 1
	crockfordDecodeTable['i'] = 1
	crockfordDecodeTable['L'] = 1
	crockfordDecodeTable['l'] = 1
}

// GenerateRoomID generates an 8-character canonical uppercase Crockford Base32 room_id
// from 5 CSPRNG bytes (40 bits, zero modulo bias).
func GenerateRoomID() (string, error) {
	var raw [RoomIDRawBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate room_id: %w", err)
	}
	return EncodeRoomID(raw), nil
}

// EncodeRoomID deterministically maps 5 raw bytes (40 bits, big-endian) to 8 uppercase
// standard Crockford Base32 characters.
func EncodeRoomID(raw [RoomIDRawBytes]byte) string {
	var val uint64
	for i := 0; i < RoomIDRawBytes; i++ {
		val = (val << 8) | uint64(raw[i])
	}
	var out [RoomIDLength]byte
	for i := RoomIDLength - 1; i >= 0; i-- {
		out[i] = CrockfordAlphabet[val&0x1f]
		val >>= 5
	}
	return string(out[:])
}

// NormalizeRoomID strips whitespace and hyphens, applies standard Crockford Base32
// normalization (case-insensitive, O->0, I/L->1), and validates exact 8-character length.
func NormalizeRoomID(input string) (string, error) {
	var out [RoomIDLength]byte
	n := 0
	for i := 0; i < len(input); i++ {
		c := input[i]
		if c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			continue
		}
		if c >= 128 {
			return "", ErrInvalidRoomID
		}
		v := crockfordDecodeTable[c]
		if v < 0 {
			return "", ErrInvalidRoomID
		}
		if n >= RoomIDLength {
			return "", ErrInvalidRoomID
		}
		out[n] = CrockfordAlphabet[v]
		n++
	}
	if n != RoomIDLength {
		return "", ErrInvalidRoomID
	}
	return string(out[:]), nil
}

// DecodeRoomID normalizes a Crockford Base32 room_id and decodes it back into its 5 raw bytes.
func DecodeRoomID(input string) ([RoomIDRawBytes]byte, error) {
	var raw [RoomIDRawBytes]byte
	norm, err := NormalizeRoomID(input)
	if err != nil {
		return raw, err
	}
	var val uint64
	for i := 0; i < RoomIDLength; i++ {
		v := crockfordDecodeTable[norm[i]]
		val = (val << 5) | uint64(v)
	}
	for i := RoomIDRawBytes - 1; i >= 0; i-- {
		raw[i] = byte(val & 0xff)
		val >>= 8
	}
	return raw, nil
}

// FormatRoomID formats a valid room_id for human display as "XXXX-XXXX".
func FormatRoomID(input string) (string, error) {
	norm, err := NormalizeRoomID(input)
	if err != nil {
		return "", err
	}
	return norm[:4] + "-" + norm[4:], nil
}

// IsCanonicalRoomID reports whether s is already an exact 8-char uppercase canonical Crockford Base32 string.
func IsCanonicalRoomID(s string) bool {
	if len(s) != RoomIDLength {
		return false
	}
	for i := 0; i < RoomIDLength; i++ {
		if !strings.ContainsRune(CrockfordAlphabet, rune(s[i])) {
			return false
		}
	}
	return true
}
