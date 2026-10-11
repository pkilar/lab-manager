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
	if got := st.decryptCredential(1, "c", "calvin"); got != "calvin" {
		t.Fatalf("legacy plaintext = %q, want calvin", got)
	}
	if got := st.decryptCredential(1, "c", ""); got != "" {
		t.Fatalf("empty = %q, want empty", got)
	}
	tok, _ := st.cipher.Encrypt([]byte("encrypted"))
	if got := st.decryptCredential(1, "c", tok); got != "encrypted" {
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

func TestSOLInstanceRoundTrips(t *testing.T) {
	st := openTempStore(t)
	s := &model.Server{Name: "twin-node-b", IPAddress: "10.0.0.9", SOLInstance: 2}
	if err := st.CreateServer(s); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	got, err := st.GetServer(s.ID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if got.SOLInstance != 2 {
		t.Fatalf("SOLInstance after create = %d, want 2", got.SOLInstance)
	}

	got.SOLInstance = 15
	if err := st.UpdateServer(got, false, false); err != nil {
		t.Fatalf("UpdateServer: %v", err)
	}
	got, err = st.GetServer(s.ID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if got.SOLInstance != 15 {
		t.Fatalf("SOLInstance after update = %d, want 15", got.SOLInstance)
	}
}

// A server created without an explicit instance must persist the default rather
// than 0, which would emit `instance=0` and be rejected by ipmitool.
func TestCreateServerDefaultsSOLInstance(t *testing.T) {
	st := openTempStore(t)
	s := &model.Server{Name: "r630", IPAddress: "10.0.0.10"} // SOLInstance left zero
	if err := st.CreateServer(s); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	got, err := st.GetServer(s.ID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if got.SOLInstance != model.DefaultSOLInstance {
		t.Fatalf("SOLInstance = %d, want %d", got.SOLInstance, model.DefaultSOLInstance)
	}
}

// The live instance/servers.db predates sol_instance. Opening such a database
// must add the column and leave the existing row readable — SQLite backfills
// ALTER TABLE ... ADD COLUMN with NULL, not with the DEFAULT, so the scan has to
// tolerate NULL and fall back to instance 1.
func TestMigrationAddsSOLInstanceToExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	pre := openStoreAtPath(t, path)
	if _, err := pre.db.Exec("ALTER TABLE server DROP COLUMN sol_instance"); err != nil {
		t.Fatalf("simulate pre-migration schema: %v", err)
	}
	if _, err := pre.db.Exec(
		"INSERT INTO server (name, ip_address, bmc_type, status) VALUES ('legacy', '10.0.0.11', 'idrac', 'Off')",
	); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if err := pre.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	st := openStoreAtPath(t, path) // migrate() runs here
	servers, err := st.AllServers()
	if err != nil {
		t.Fatalf("AllServers after migration: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("got %d servers, want 1", len(servers))
	}
	if got := servers[0].SOLInstanceOrDefault(); got != model.DefaultSOLInstance {
		t.Fatalf("migrated row SOLInstanceOrDefault = %d, want %d", got, model.DefaultSOLInstance)
	}
}

func openStoreAtPath(t *testing.T, path string) *Store {
	t.Helper()
	st, err := Open(path, testFernet(t))
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	return st
}

func TestUndecryptableFernetTokenWarnsOncePerColumn(t *testing.T) {
	var warns []string
	old := warnUndecryptable
	warnUndecryptable = func(id int64, col string) { warns = append(warns, col) }
	t.Cleanup(func() { warnUndecryptable = old })

	otherKey := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	other, err := secret.NewFernet([]byte(otherKey))
	if err != nil {
		t.Fatalf("NewFernet: %v", err)
	}
	tok, err := other.Encrypt([]byte("calvin"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	st := &Store{cipher: testFernet(t)}

	for range 3 {
		if got := st.decryptCredential(7, "redfish_password", tok); got != tok {
			t.Fatalf("fallback must return the raw value, got %q", got)
		}
	}
	if len(warns) != 1 {
		t.Fatalf("warnings after repeats = %v, want exactly 1", warns)
	}
	st.decryptCredential(7, "ipmi_password", tok)
	st.decryptCredential(8, "redfish_password", tok)
	if len(warns) != 3 {
		t.Fatalf("distinct (server,column) pairs should each warn once, got %v", warns)
	}
}

func TestLegacyPlaintextDoesNotWarn(t *testing.T) {
	var n int
	old := warnUndecryptable
	warnUndecryptable = func(int64, string) { n++ }
	t.Cleanup(func() { warnUndecryptable = old })

	st := &Store{cipher: testFernet(t)}
	for _, v := range []string{"calvin", "p@ss word", strings.Repeat("A", 120)} {
		if got := st.decryptCredential(1, "redfish_password", v); got != v {
			t.Fatalf("plaintext %q altered to %q", v, got)
		}
	}
	if n != 0 {
		t.Fatalf("plaintext triggered %d warnings", n)
	}
}
