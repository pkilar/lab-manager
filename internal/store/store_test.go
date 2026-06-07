package store

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkilar/lab-manager/internal/model"
	"github.com/pkilar/lab-manager/internal/secret"
)

const testFernetKey = "VTfdkyi4hZ3WvGv84jig3XyW_OUl6ovpe1ZU7UUIgRM="

func testFernet(t *testing.T) *secret.Fernet {
	t.Helper()
	f, err := secret.NewFernet([]byte(testFernetKey))
	if err != nil {
		t.Fatalf("NewFernet: %v", err)
	}
	return f
}

func openTempStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "servers.db"), testFernet(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestDecryptCredentialLegacyPlaintextFallback(t *testing.T) {
	st := &Store{cipher: testFernet(t)}
	// The shipped DB stores plaintext credentials like "calvin"; they are not
	// valid Fernet tokens and must be returned verbatim.
	if got := st.decryptCredential("calvin"); got != "calvin" {
		t.Fatalf("legacy plaintext = %q, want calvin", got)
	}
	if got := st.decryptCredential(""); got != "" {
		t.Fatalf("empty = %q, want empty", got)
	}
	tok, _ := st.cipher.Encrypt([]byte("encrypted"))
	if got := st.decryptCredential(tok); got != "encrypted" {
		t.Fatalf("fernet round-trip via store = %q, want encrypted", got)
	}
}

func TestCreateServerEncryptsCredentialsAtRest(t *testing.T) {
	st := openTempStore(t)
	s := &model.Server{
		Name: "r630", IPAddress: "10.0.0.1", BMCType: "idrac",
		RedfishUser: "root", RedfishPassword: "calvin", Status: "Off",
	}
	if err := st.CreateServer(s); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	var raw string
	if err := st.db.QueryRow("SELECT redfish_password FROM server WHERE id = ?", s.ID).Scan(&raw); err != nil {
		t.Fatalf("read raw credential: %v", err)
	}
	if raw == "calvin" || !strings.HasPrefix(raw, "gAAAAA") {
		t.Fatalf("credential not encrypted at rest: %q", raw)
	}

	// And it must read back decrypted.
	got, err := st.GetServer(s.ID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if got.RedfishPassword != "calvin" {
		t.Fatalf("decrypted credential = %q, want calvin", got.RedfishPassword)
	}
}

func TestUpdateServerKeepsPasswordWhenNotSet(t *testing.T) {
	st := openTempStore(t)
	s := &model.Server{Name: "r630", IPAddress: "10.0.0.1", BMCType: "idrac", RedfishUser: "root", RedfishPassword: "calvin", Status: "Off"}
	if err := st.CreateServer(s); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	// Edit name only, do not set a new password.
	s.Name = "r630-renamed"
	if err := st.UpdateServer(s, false, false); err != nil {
		t.Fatalf("UpdateServer: %v", err)
	}
	got, err := st.GetServer(s.ID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if got.Name != "r630-renamed" || got.RedfishPassword != "calvin" {
		t.Fatalf("got name=%q pass=%q", got.Name, got.RedfishPassword)
	}
}

func TestInitDefaultUser(t *testing.T) {
	st := openTempStore(t)
	if err := st.InitDefaultUser(); err != nil {
		t.Fatalf("InitDefaultUser: %v", err)
	}
	u, err := st.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if !u.PasswordChangeRequired || !secret.CheckPasswordHash(u.PasswordHash, "admin") {
		t.Fatalf("admin not seeded correctly: pcr=%v", u.PasswordChangeRequired)
	}
	// Idempotent: a second call must not error or duplicate.
	if err := st.InitDefaultUser(); err != nil {
		t.Fatalf("second InitDefaultUser: %v", err)
	}
}

func TestGetServerNotFound(t *testing.T) {
	st := openTempStore(t)
	if _, err := st.GetServer(999); err != ErrNotFound {
		t.Fatalf("GetServer(missing) err = %v, want ErrNotFound", err)
	}
}
