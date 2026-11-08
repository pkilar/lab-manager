// Package secret provides credential encryption (Fernet) and password hashing
// in the scrypt/pbkdf2 hash-string format, kept wire-compatible with existing
// stored data so an existing database keeps working unchanged.
package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// Fernet implements the subset of the Fernet spec this app relies on:
// AES-128-CBC + HMAC-SHA256 over a 32-byte key (first 16 bytes sign, last 16
// encrypt), with urlsafe-base64 tokens. It follows the standard Fernet token
// format, so credentials already stored in the database decrypt unchanged here,
// and credentials written here remain readable by any conforming Fernet reader.
type Fernet struct {
	signKey []byte // 16 bytes, HMAC-SHA256 key
	encKey  []byte // 16 bytes, AES-128 key
}

const fernetVersion = 0x80

var errInvalidToken = errors.New("invalid fernet token")

// NewFernet builds a cipher from a urlsafe-base64 32-byte key — the standard
// 44-character Fernet key string.
func NewFernet(keyB64 []byte) (*Fernet, error) {
	raw, err := base64.URLEncoding.DecodeString(string(bytes.TrimSpace(keyB64)))
	if err != nil {
		return nil, fmt.Errorf("decode fernet key: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("fernet key must decode to 32 bytes, got %d", len(raw))
	}
	return &Fernet{signKey: raw[:16], encKey: raw[16:]}, nil
}

// Decrypt verifies and decrypts a Fernet token. It enforces no ttl, so it does
// not reject old tokens — only the HMAC and padding are checked.
func (f *Fernet) Decrypt(token string) ([]byte, error) {
	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, errInvalidToken
	}
	// version(1) + timestamp(8) + iv(16) + ciphertext(>=16) + hmac(32)
	if len(data) < 1+8+16+16+32 {
		return nil, errInvalidToken
	}
	if data[0] != fernetVersion {
		return nil, errInvalidToken
	}

	macOffset := len(data) - 32
	mac := data[macOffset:]
	signed := data[:macOffset]

	h := hmac.New(sha256.New, f.signKey)
	h.Write(signed)
	if !hmac.Equal(mac, h.Sum(nil)) {
		return nil, errInvalidToken
	}

	iv := data[9:25]
	ciphertext := data[25:macOffset]
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errInvalidToken
	}

	block, err := aes.NewCipher(f.encKey)
	if err != nil {
		return nil, errInvalidToken
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	return pkcs7Unpad(plaintext, aes.BlockSize)
}

// Encrypt produces a Fernet token using a fresh random IV and the current time.
func (f *Fernet) Encrypt(plaintext []byte) (string, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	return f.encryptAt(plaintext, iv, time.Now().Unix())
}

func (f *Fernet) encryptAt(plaintext, iv []byte, ts int64) (string, error) {
	block, err := aes.NewCipher(f.encKey)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	body := make([]byte, 0, 1+8+len(iv)+len(ciphertext)+sha256.Size)
	body = append(body, fernetVersion)
	for i := 7; i >= 0; i-- {
		body = append(body, byte(ts>>(8*uint(i)))) //nolint:gosec // G115: deliberate truncation, one big-endian byte at a time
	}
	body = append(body, iv...)
	body = append(body, ciphertext...)

	h := hmac.New(sha256.New, f.signKey)
	h.Write(body)
	body = h.Sum(body)

	return base64.URLEncoding.EncodeToString(body), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad) //nolint:gosec // G115: pad is 1..blockSize (16)
	}
	return out
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errInvalidToken
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize || pad > len(data) {
		return nil, errInvalidToken
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, errInvalidToken
		}
	}
	return data[:len(data)-pad], nil
}

// LoadEncryptionKey returns the urlsafe-base64 Fernet key, resolved in priority
// order: the LAB_MANAGER_ENCRYPTION_KEY env var if valid, else the
// instance/.encryption_key file, else a freshly generated key persisted at 0600.
func LoadEncryptionKey(instanceDir string) ([]byte, error) {
	if env := os.Getenv("LAB_MANAGER_ENCRYPTION_KEY"); env != "" {
		if _, err := NewFernet([]byte(env)); err != nil {
			slog.Error("invalid LAB_MANAGER_ENCRYPTION_KEY format; falling back to key file")
		} else {
			return []byte(env), nil
		}
	}

	keyFile := filepath.Join(instanceDir, ".encryption_key")
	tightenMode(instanceDir, 0o700)
	b, err := os.ReadFile(keyFile)
	switch {
	case err == nil:
		tightenMode(keyFile, 0o600)
		return validateKeyFile(keyFile, b)
	case !errors.Is(err, fs.ErrNotExist):
		// Never generate over a key we merely failed to read: replacing it
		// would make every stored credential undecryptable.
		return nil, fmt.Errorf("read encryption key %s: %w", keyFile, err)
	}

	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, err
	}
	encoded := []byte(base64.URLEncoding.EncodeToString(raw))
	if err := os.MkdirAll(instanceDir, 0o700); err != nil {
		return nil, err
	}

	// Write a private temp file, then hard-link it into place: link fails with
	// ErrExist rather than clobbering a key another process created first.
	tmp, err := os.CreateTemp(instanceDir, ".encryption_key.tmp-*")
	if err != nil {
		return nil, err
	}
	// The temp name is always removed: after a successful Link the key lives on
	// under keyFile, and on any failure the temp is just garbage.
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, werr := tmp.Write(encoded)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return nil, werr
	}
	if err := os.Link(tmp.Name(), keyFile); err != nil {
		if errors.Is(err, fs.ErrExist) {
			existing, rerr := os.ReadFile(keyFile)
			if rerr != nil {
				return nil, fmt.Errorf("read encryption key %s: %w", keyFile, rerr)
			}
			return validateKeyFile(keyFile, existing)
		}
		return nil, err
	}
	slog.Warn("generated new encryption key", "path", keyFile)
	return encoded, nil
}

// tightenMode chmods an existing path to mode when it grants any group/other
// access (MkdirAll and WriteFile only apply a mode on creation). Failure warns
// and carries on: a readable key must still load, e.g. on a read-only mount.
func tightenMode(path string, mode os.FileMode) {
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm()&0o077 == 0 {
		return
	}
	slog.Warn("permissions too open on secret material; tightening", "path", path, "mode", fi.Mode().Perm().String(), "want", mode.String())
	if err := os.Chmod(path, mode); err != nil {
		slog.Warn("could not tighten permissions", "path", path, "err", err)
	}
}

// validateKeyFile checks the contents of an existing key file. An invalid file
// is an error, never a cue to regenerate: the file exists, so replacing it
// would destroy the only copy of whatever key encrypted the stored data.
func validateKeyFile(path string, b []byte) ([]byte, error) {
	key := bytes.TrimSpace(b)
	if _, err := NewFernet(key); err != nil {
		return nil, fmt.Errorf("encryption key file %s is invalid (refusing to overwrite): %w", path, err)
	}
	return key, nil
}
