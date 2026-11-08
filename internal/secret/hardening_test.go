package secret

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/scrypt"
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

func TestLoadEncryptionKeyTightensLooseModes(t *testing.T) {
	dir, keyFile := keyDir(t)
	if err := os.WriteFile(keyFile, []byte(refFernetKey+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEncryptionKey(dir); err != nil {
		t.Fatalf("LoadEncryptionKey: %v", err)
	}
	for path, want := range map[string]os.FileMode{keyFile: 0o600, dir: 0o700} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Fatalf("%s mode = %o, want %o", path, got, want)
		}
	}
}

func TestPasswordCostBounds(t *testing.T) {
	for _, c := range []struct {
		n, r, p int
		ok      bool
	}{
		{32768, 8, 1, true}, // what this app and Werkzeug emit
		{1 << 17, 16, 4, true},
		{1 << 18, 8, 1, false},
		{1024, 17, 1, false},
		{1024, 8, 5, false},
		{1000, 8, 1, false}, // not a power of two
		{1, 8, 1, false},
		{1024, 0, 1, false},
		{1024, 8, 0, false},
	} {
		if got := scryptCostOK(c.n, c.r, c.p); got != c.ok {
			t.Errorf("scryptCostOK(%d,%d,%d) = %v, want %v", c.n, c.r, c.p, got, c.ok)
		}
	}
	for _, c := range []struct {
		iter int
		ok   bool
	}{{600_000, true}, {2_000_000, true}, {2_000_001, false}, {0, false}} {
		if got := pbkdf2CostOK(c.iter); got != c.ok {
			t.Errorf("pbkdf2CostOK(%d) = %v, want %v", c.iter, got, c.ok)
		}
	}
}

func TestCheckPasswordHashCostCaps(t *testing.T) {
	// Real (cheap) digests, so only the cap, not a digest mismatch, can reject
	// them. The over-cap N case uses r=1 to keep the test's own allocation small.
	for _, c := range []struct{ n, r, p int }{{1 << 18, 1, 1}, {1024, 17, 1}, {1024, 8, 5}} {
		dk, err := scrypt.Key([]byte("x"), []byte("salt"), c.n, c.r, c.p, 64)
		if err != nil {
			t.Fatal(err)
		}
		h := fmt.Sprintf("scrypt:%d:%d:%d$salt$%s", c.n, c.r, c.p, hex.EncodeToString(dk))
		if CheckPasswordHash(h, "x") {
			t.Fatalf("scrypt %+v accepted", c)
		}
	}
}

func TestCheckPasswordHashRealWorldVectors(t *testing.T) {
	// scrypt:32768:8:1 is what this app and Werkzeug emit.
	h, err := GeneratePasswordHash("pw")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPasswordHash(h, "pw") {
		t.Fatal("generated scrypt hash does not verify")
	}
	// Werkzeug 3's pbkdf2 default; the largest count a real row carries.
	dk, err := pbkdf2.Key(sha256.New, "pw", []byte("salty"), 1_000_000, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPasswordHash("pbkdf2:sha256:1000000$salty$"+hex.EncodeToString(dk), "pw") {
		t.Fatal("pbkdf2 1000000 vector failed")
	}
}
