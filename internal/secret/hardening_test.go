package secret

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func keyDir(t *testing.T) (dir, keyFile string) {
	t.Helper()
	t.Setenv("LAB_MANAGER_ENCRYPTION_KEY", "")
	dir = t.TempDir()
	return dir, filepath.Join(dir, ".encryption_key")
}

func TestLoadEncryptionKeyExistingValid(t *testing.T) {
	dir, keyFile := keyDir(t)
	if err := os.WriteFile(keyFile, []byte(refFernetKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadEncryptionKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != refFernetKey {
		t.Fatalf("key = %q, want %q", got, refFernetKey)
	}
}

func TestLoadEncryptionKeyGeneratesOnce(t *testing.T) {
	dir, keyFile := keyDir(t)
	first, err := LoadEncryptionKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFernet(first); err != nil {
		t.Fatalf("generated key invalid: %v", err)
	}
	fi, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 600", perm)
	}
	second, err := LoadEncryptionKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("second call returned a different key")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftover files in instance dir: %v", entries)
	}
}

func TestLoadEncryptionKeyRefusesInvalidExisting(t *testing.T) {
	for name, content := range map[string]string{"empty": "", "malformed": "not-a-key"} {
		t.Run(name, func(t *testing.T) {
			dir, keyFile := keyDir(t)
			if err := os.WriteFile(keyFile, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadEncryptionKey(dir); err == nil {
				t.Fatal("expected error for invalid existing key file")
			}
			after, err := os.ReadFile(keyFile)
			if err != nil || string(after) != content {
				t.Fatalf("key file modified: %q, %v", after, err)
			}
		})
	}
}

func TestLoadEncryptionKeyReadErrorDoesNotOverwrite(t *testing.T) {
	dir, keyFile := keyDir(t)
	if err := os.Mkdir(keyFile, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEncryptionKey(dir); err == nil {
		t.Fatal("expected error when key path is unreadable")
	}
	fi, err := os.Stat(keyFile)
	if err != nil || !fi.IsDir() {
		t.Fatalf("key path was replaced: %v, %v", fi, err)
	}
}

func TestCheckPasswordHashRejectsBadDigestsAndParams(t *testing.T) {
	cases := map[string]string{
		"scrypt-empty-digest":  "scrypt:32768:8:1$salt$",
		"pbkdf2-empty-digest":  "pbkdf2:sha256:1000$salt$",
		"odd-length-digest":    "scrypt:32768:8:1$salt$abc",
		"non-hex-digest":       "pbkdf2:sha256:1000$salt$zzzz",
		"scrypt-huge-N":        "scrypt:1073741824:8:1$salt$aabb",
		"scrypt-huge-r":        "scrypt:32768:1000:1$salt$aabb",
		"scrypt-huge-p":        "scrypt:32768:8:1000$salt$aabb",
		"scrypt-N-not-pow2":    "scrypt:30000:8:1$salt$aabb",
		"scrypt-zero-r":        "scrypt:32768:0:1$salt$aabb",
		"pbkdf2-huge-iter":     "pbkdf2:sha256:1000000000$salt$aabb",
		"pbkdf2-zero-iter":     "pbkdf2:sha256:0$salt$aabb",
		"pbkdf2-negative-iter": "pbkdf2:sha256:-5$salt$aabb",
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			if CheckPasswordHash(h, "x") {
				t.Fatal("expected false")
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("took %v; params not bounded", d)
			}
		})
	}
}
