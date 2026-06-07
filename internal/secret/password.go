package secret

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// Password hashing in the "scrypt:32768:8:1$salt$hex" string format. Existing
// hashes use that format; we verify it (and pbkdf2:sha256:* as a safety net) and
// generate new hashes in the same scrypt format, so previously stored user-table
// hashes remain readable.

const (
	scryptN      = 32768
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 64
	saltLength   = 16
)

const saltAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// GeneratePasswordHash produces a hash using the scrypt method with default
// parameters.
func GeneratePasswordHash(password string) (string, error) {
	salt, err := randomSalt(saltLength)
	if err != nil {
		return "", err
	}
	dk, err := scrypt.Key([]byte(password), []byte(salt), scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("scrypt:%d:%d:%d$%s$%s", scryptN, scryptR, scryptP, salt, hex.EncodeToString(dk)), nil
}

// CheckPasswordHash verifies a password against a stored hash for the scrypt
// and pbkdf2:sha256 methods.
func CheckPasswordHash(stored, password string) bool {
	method, rest, ok := strings.Cut(stored, "$")
	if !ok {
		return false
	}
	salt, wantHex, ok := strings.Cut(rest, "$")
	if !ok {
		return false
	}

	var got []byte
	switch {
	case strings.HasPrefix(method, "scrypt:"):
		parts := strings.Split(method, ":")
		if len(parts) != 4 {
			return false
		}
		n, err1 := strconv.Atoi(parts[1])
		r, err2 := strconv.Atoi(parts[2])
		p, err3 := strconv.Atoi(parts[3])
		if err1 != nil || err2 != nil || err3 != nil {
			return false
		}
		dk, err := scrypt.Key([]byte(password), []byte(salt), n, r, p, len(wantHex)/2)
		if err != nil {
			return false
		}
		got = dk

	case strings.HasPrefix(method, "pbkdf2:sha256:"):
		parts := strings.Split(method, ":")
		if len(parts) != 3 {
			return false
		}
		iter, err := strconv.Atoi(parts[2])
		if err != nil {
			return false
		}
		dk, err := pbkdf2.Key(sha256.New, password, []byte(salt), iter, len(wantHex)/2)
		if err != nil {
			return false
		}
		got = dk

	default:
		return false
	}

	want, err := hex.DecodeString(wantHex)
	if err != nil {
		return false
	}
	return hmac.Equal(got, want)
}

func randomSalt(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, c := range b {
		out[i] = saltAlphabet[int(c)%len(saltAlphabet)]
	}
	return string(out), nil
}
