package secret

import (
	"strings"
	"testing"
)

// Reference vectors pinning the on-disk formats: a Fernet token and scrypt /
// pbkdf2 password hashes. They prove the implementations match the documented
// wire formats, not merely that they are self-consistent.
const (
	refFernetKey       = "VTfdkyi4hZ3WvGv84jig3XyW_OUl6ovpe1ZU7UUIgRM="
	refFernetPlaintext = "calvin-π-секрет"
	refFernetToken     = "gAAAAABqJd4UTLh2VW6yVK-IaN8xG5xV1h50q2iEZ3WeHG_COKLQtAGLTvAblJW51102k35NjHWDNJ8qExZH50SvtvNPJDQDVvbV-uOty79ccHZe6J328mE="

	refScryptHash = "scrypt:32768:8:1$tz9bE8FjnwObufMw$e13f31ef2c9c502aa284866cf0b4c407c54434f7f8d128a1e16d6fbbce01ef5445ee34ae6dfc441e06f778311850fad6aeaaa2cb1ee960f7b1af7605cd4a7a4f"
	refPBKDF2Hash = "pbkdf2:sha256:1000000$b5BsYAWTyUyzq5ac$b8ae0f1ca5391bd771107e50bfe2ad4f6adf5975762548d5d5d5aa67744bc2f4"

	// The real admin/admin hash from the shipped database has since had its
	// password changed (password_change_required=0), so "admin" must NOT verify
	// against it.
	realAdminHash = "scrypt:32768:8:1$INseyM3IxxibZLUF$5962cb3ce26c7048e4e16af67d7eefba6e82760750cb2ff6a9817009db8ee10ffc9767a8686dba6dea5916826dcdb2988cd088a374d2c306af2837384575a094"
)

func newFernet(t *testing.T) *Fernet {
	t.Helper()
	f, err := NewFernet([]byte(refFernetKey))
	if err != nil {
		t.Fatalf("NewFernet: %v", err)
	}
	return f
}

func TestFernetDecryptsReferenceToken(t *testing.T) {
	got, err := newFernet(t).Decrypt(refFernetToken)
	if err != nil {
		t.Fatalf("decrypt reference token: %v", err)
	}
	if string(got) != refFernetPlaintext {
		t.Fatalf("decrypt = %q, want %q", got, refFernetPlaintext)
	}
}

func TestFernetRoundTrip(t *testing.T) {
	f := newFernet(t)
	for _, pt := range []string{"", "calvin", "p@ss w/ spaces & symbols #1!", refFernetPlaintext} {
		tok, err := f.Encrypt([]byte(pt))
		if err != nil {
			t.Fatalf("encrypt %q: %v", pt, err)
		}
		got, err := f.Decrypt(tok)
		if err != nil {
			t.Fatalf("decrypt %q: %v", pt, err)
		}
		if string(got) != pt {
			t.Fatalf("round-trip = %q, want %q", got, pt)
		}
	}
}

func TestFernetRejectsTamperedToken(t *testing.T) {
	f := newFernet(t)
	if _, err := f.Decrypt("not-a-valid-token"); err == nil {
		t.Fatal("expected error decrypting garbage")
	}
	tok, _ := f.Encrypt([]byte("secret"))
	b := []byte(tok)
	b[len(b)/2] ^= 0x01
	if _, err := f.Decrypt(string(b)); err == nil {
		t.Fatal("expected error decrypting tampered token")
	}
}

func TestCheckPasswordHashFormats(t *testing.T) {
	cases := []struct {
		name, hash, password string
		want                 bool
	}{
		{"scrypt-correct", refScryptHash, "admin", true},
		{"scrypt-wrong", refScryptHash, "wrong", false},
		{"pbkdf2-correct", refPBKDF2Hash, "test1234", true},
		{"pbkdf2-wrong", refPBKDF2Hash, "nope", false},
		{"real-admin-rejects-default", realAdminHash, "admin", false},
		{"malformed", "not-a-hash", "x", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CheckPasswordHash(c.hash, c.password); got != c.want {
				t.Fatalf("CheckPasswordHash(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

func TestGeneratePasswordHashRoundTrip(t *testing.T) {
	hash, err := GeneratePasswordHash("hunter2-π")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.HasPrefix(hash, "scrypt:32768:8:1$") {
		t.Fatalf("unexpected hash format: %q", hash)
	}
	if !CheckPasswordHash(hash, "hunter2-π") {
		t.Fatal("generated hash failed to verify")
	}
	if CheckPasswordHash(hash, "hunter2") {
		t.Fatal("wrong password verified")
	}
}
