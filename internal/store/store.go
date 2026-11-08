// Package store is the SQLite persistence layer. It transparently encrypts and
// decrypts the credential columns and runs the additive schema migrations.
package store

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkilar/lab-manager/internal/model"
	"github.com/pkilar/lab-manager/internal/secret"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps the SQLite database and the credential cipher.
type Store struct {
	db     *sql.DB
	cipher *secret.Fernet

	warnMu sync.Mutex
	warned map[string]struct{} // "serverID/column" already warned about
}

const serverColumns = `id, name, ip_address, bmc_type, redfish_user, redfish_password, ipmi_user, ipmi_password, mac_address, status, last_updated, notes, sol_instance`

// Open connects to the SQLite database at dbPath, applies migrations, and
// returns a ready Store.
func Open(dbPath string, cipher *secret.Fernet) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	// SQLite is single-writer; serialize all access through one connection so
	// concurrent requests can't trip "database is locked".
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}

	st := &Store{db: db, cipher: cipher}
	if err := st.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := st.encryptLegacyCredentials(); err != nil {
		_ = db.Close()
		return nil, err
	}
	restrictDBFile(dbPath)
	return st, nil
}

// restrictDBFile chmods a real database file to 0600 (the driver creates it
// 0644 under a normal umask). The journal inherits the main file's mode. A
// failure only warns: a read-only mount must not stop startup.
func restrictDBFile(dbPath string) {
	if dbPath == "" || dbPath == ":memory:" || strings.HasPrefix(dbPath, "file::memory:") || strings.Contains(dbPath, "mode=memory") {
		return
	}
	path := strings.TrimPrefix(dbPath, "file:")
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if err := os.Chmod(path, 0o600); err != nil {
		slog.Warn("could not restrict database file permissions", "path", path, "err", err)
	}
}

// encryptLegacyCredentials encrypts, in one transaction, any credential still
// stored as plaintext. Values that decrypt are already encrypted, and
// token-shaped values that don't are a wrong-key token: both are left alone so
// nothing is ever double-encrypted. Idempotent; logs ids only, never values.
func (st *Store) encryptLegacyCredentials() error {
	tx, err := st.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	type fix struct {
		id         int64
		column, tk string
	}
	var fixes []fix
	wrongKey := false
	rows, err := tx.Query("SELECT id, redfish_password, ipmi_password FROM server")
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var rf, ipmi sql.NullString
		if err := rows.Scan(&id, &rf, &ipmi); err != nil {
			_ = rows.Close()
			return err
		}
		for _, c := range []struct {
			col string
			v   sql.NullString
		}{{"redfish_password", rf}, {"ipmi_password", ipmi}} {
			if c.v.String == "" {
				continue
			}
			if _, err := st.cipher.Decrypt(c.v.String); err == nil {
				continue
			}
			if looksLikeFernet(c.v.String) {
				wrongKey = true
				continue
			}
			tok, err := st.cipher.Encrypt([]byte(c.v.String))
			if err != nil {
				_ = rows.Close()
				return err
			}
			fixes = append(fixes, fix{id, c.col, tok})
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()
	if len(fixes) == 0 {
		return nil
	}
	if wrongKey {
		// Some tokens don't decrypt, so this is probably not the key they were
		// written with (e.g. a lost key file was regenerated). Encrypting the
		// plaintext now would bind it to that key, and restoring the right key
		// would then lose it too. Leave everything as it is until the key is
		// sorted out.
		slog.Warn("legacy plaintext credentials left unencrypted: other stored credentials don't decrypt with the current key",
			"count", len(fixes))
		return nil
	}

	ids := make([]int64, 0, len(fixes))
	for _, f := range fixes {
		// f.column is one of two package-internal constants.
		if _, err := tx.Exec("UPDATE server SET "+f.column+" = ? WHERE id = ?", f.tk, f.id); err != nil { //nolint:gosec // G202: column is a constant, values are bound
			return err
		}
		ids = append(ids, f.id)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	slog.Warn("encrypted legacy plaintext credentials", "count", len(fixes), "server_ids", ids)
	return nil
}

// Close releases the underlying database handle.
func (st *Store) Close() error { return st.db.Close() }

// migrate creates the tables for a fresh database and additively backfills
// columns that older databases may be missing — the columns
// (user.password_change_required, server.bmc_type, server.sol_instance) added
// after the initial schema.
func (st *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS server (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	ip_address TEXT NOT NULL,
	bmc_type TEXT DEFAULT 'generic',
	redfish_user TEXT,
	redfish_password TEXT,
	ipmi_user TEXT,
	ipmi_password TEXT,
	mac_address TEXT,
	status TEXT DEFAULT 'Off',
	last_updated DATETIME,
	notes TEXT,
	sol_instance INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS user (
	id INTEGER PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	password_change_required INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS revoked_session (
	sid TEXT PRIMARY KEY,
	expires DATETIME NOT NULL
);`
	if _, err := st.db.Exec(schema); err != nil {
		return fmt.Errorf("create tables: %w", err)
	}
	if err := st.addColumnIfMissing("user", "password_change_required", "INTEGER DEFAULT 1"); err != nil {
		return err
	}
	if err := st.addColumnIfMissing("server", "bmc_type", "TEXT DEFAULT 'generic'"); err != nil {
		return err
	}
	// Existing rows get NULL rather than the DEFAULT (SQLite only applies it to
	// new inserts), so scanServer must tolerate NULL here.
	if err := st.addColumnIfMissing("server", "sol_instance", "INTEGER DEFAULT 1"); err != nil {
		return err
	}
	return nil
}

func (st *Store) addColumnIfMissing(table, column, definition string) error {
	// table/column/definition are package-internal constants, never user input.
	rows, err := st.db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	found := false
	for rows.Next() {
		var (
			cid         int
			name, ctype string
			notnull, pk int
			dflt        sql.NullString
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = st.db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition))
	return err
}

// ---- credential helpers --------------------------------------------------

// warnUndecryptable is the logging seam for looksLikeFernet misses; tests swap it.
var warnUndecryptable = func(serverID int64, column string) {
	slog.Warn("stored credential looks encrypted but does not decrypt; wrong or regenerated encryption key?",
		"server_id", serverID, "column", column)
}

// looksLikeFernet reports whether v is shaped like a Fernet token: urlsafe
// base64 of at least version+timestamp+IV+one block+HMAC (73 bytes) starting
// with the 0x80 version byte.
func looksLikeFernet(v string) bool {
	raw, err := base64.URLEncoding.DecodeString(v)
	return err == nil && len(raw) >= 73 && raw[0] == 0x80
}

// warnOnce logs at most one warning per (server, column) per process.
func (st *Store) warnOnce(serverID int64, column string) {
	key := fmt.Sprintf("%d/%s", serverID, column)
	st.warnMu.Lock()
	_, seen := st.warned[key]
	if !seen {
		if st.warned == nil {
			st.warned = make(map[string]struct{})
		}
		st.warned[key] = struct{}{}
	}
	st.warnMu.Unlock()
	if !seen {
		warnUndecryptable(serverID, column)
	}
}

// decryptCredential returns a stored credential's plaintext, and unreadable =
// true when the value is shaped like a Fernet token but does not decrypt.
func (st *Store) decryptCredential(serverID int64, column, ciphertext string) (plaintext string, unreadable bool) {
	if ciphertext == "" {
		return "", false
	}
	pt, err := st.cipher.Decrypt(ciphertext)
	if err != nil {
		if looksLikeFernet(ciphertext) {
			// The key was lost or swapped. Flag it (never the value) and return
			// nothing: handing the token to a BMC as a password would only rack
			// up failed logins and can lock the account.
			st.warnOnce(serverID, column)
			return "", true
		}
		// Not token-shaped: a legacy plaintext credential stored before
		// encryption was introduced.
		return ciphertext, false
	}
	return string(pt), false
}

func (st *Store) encryptCredential(plaintext string) (any, error) {
	if plaintext == "" {
		return nil, nil
	}
	tok, err := st.cipher.Encrypt([]byte(plaintext))
	if err != nil {
		return nil, err
	}
	return tok, nil
}

// ---- server CRUD ---------------------------------------------------------

type scanner interface {
	Scan(dest ...any) error
}

func (st *Store) scanServer(sc scanner) (*model.Server, error) {
	var s model.Server
	var (
		bmc, rfUser, rfPass, ipmiUser, ipmiPass, mac, status, lastUpdated, notes sql.NullString
		solInstance                                                              sql.NullInt64
	)
	err := sc.Scan(&s.ID, &s.Name, &s.IPAddress, &bmc, &rfUser, &rfPass, &ipmiUser, &ipmiPass, &mac, &status, &lastUpdated, &notes, &solInstance)
	if err != nil {
		return nil, err
	}
	s.BMCType = bmc.String
	if s.BMCType == "" {
		s.BMCType = model.BMCGeneric
	}
	s.RedfishUser = rfUser.String
	var rfBad, ipmiBad bool
	s.RedfishPassword, rfBad = st.decryptCredential(s.ID, "redfish_password", rfPass.String)
	s.IPMIUser = ipmiUser.String
	s.IPMIPassword, ipmiBad = st.decryptCredential(s.ID, "ipmi_password", ipmiPass.String)
	s.CredentialsUnreadable = rfBad || ipmiBad
	s.MACAddress = mac.String
	s.Status = status.String
	s.Notes = notes.String
	s.SOLInstance = int(solInstance.Int64) // NULL on pre-migration rows → 0 → SOLInstanceOrDefault
	if lastUpdated.Valid {
		s.LastUpdated = parseDBTime(lastUpdated.String)
	}
	return &s, nil
}

func (st *Store) AllServers() ([]*model.Server, error) {
	rows, err := st.db.Query("SELECT " + serverColumns + " FROM server ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var servers []*model.Server
	for rows.Next() {
		s, err := st.scanServer(rows)
		if err != nil {
			return nil, err
		}
		servers = append(servers, s)
	}
	return servers, rows.Err()
}

func (st *Store) GetServer(id int64) (*model.Server, error) {
	row := st.db.QueryRow("SELECT "+serverColumns+" FROM server WHERE id = ?", id)
	s, err := st.scanServer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return s, err
}

func (st *Store) CreateServer(s *model.Server) error {
	rfPass, err := st.encryptCredential(s.RedfishPassword)
	if err != nil {
		return err
	}
	ipmiPass, err := st.encryptCredential(s.IPMIPassword)
	if err != nil {
		return err
	}
	res, err := st.db.Exec(
		`INSERT INTO server (name, ip_address, bmc_type, redfish_user, redfish_password, ipmi_user, ipmi_password, mac_address, status, last_updated, notes, sol_instance)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.Name, s.IPAddress, s.BMCType, nullStr(s.RedfishUser), rfPass, nullStr(s.IPMIUser), ipmiPass,
		nullStr(s.MACAddress), s.Status, formatDBTime(s.LastUpdated), nullStr(s.Notes), s.SOLInstanceOrDefault(),
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	s.ID = id
	return nil
}

// UpdateServer writes all non-password columns. Password columns are only
// touched when the corresponding setPassword flag is true, implementing the
// edit form's "leave blank to keep current" behaviour.
func (st *Store) UpdateServer(s *model.Server, setRedfishPw, setIPMIPw bool) error {
	set := []string{
		"name = ?", "ip_address = ?", "bmc_type = ?", "redfish_user = ?",
		"ipmi_user = ?", "mac_address = ?", "status = ?", "last_updated = ?", "notes = ?",
		"sol_instance = ?",
	}
	args := []any{
		s.Name, s.IPAddress, s.BMCType, nullStr(s.RedfishUser),
		nullStr(s.IPMIUser), nullStr(s.MACAddress), s.Status, formatDBTime(s.LastUpdated), nullStr(s.Notes),
		s.SOLInstanceOrDefault(),
	}
	if setRedfishPw {
		enc, err := st.encryptCredential(s.RedfishPassword)
		if err != nil {
			return err
		}
		set = append(set, "redfish_password = ?")
		args = append(args, enc)
	}
	if setIPMIPw {
		enc, err := st.encryptCredential(s.IPMIPassword)
		if err != nil {
			return err
		}
		set = append(set, "ipmi_password = ?")
		args = append(args, enc)
	}
	args = append(args, s.ID)
	_, err := st.db.Exec("UPDATE server SET "+strings.Join(set, ", ")+" WHERE id = ?", args...) //nolint:gosec // G202: set holds constant fragments, values are bound
	return err
}

// TouchStatus updates only the live status and timestamp of a server.
func (st *Store) TouchStatus(id int64, status string, t time.Time) error {
	_, err := st.db.Exec("UPDATE server SET status = ?, last_updated = ? WHERE id = ?", status, formatDBTime(t), id)
	return err
}

func (st *Store) DeleteServer(id int64) error {
	_, err := st.db.Exec("DELETE FROM server WHERE id = ?", id)
	return err
}

// ---- user access ---------------------------------------------------------

func scanUser(row *sql.Row) (*model.User, error) {
	var u model.User
	var pcr sql.NullInt64
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &pcr)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.PasswordChangeRequired = pcr.Int64 != 0
	return &u, nil
}

func (st *Store) GetUserByUsername(username string) (*model.User, error) {
	return scanUser(st.db.QueryRow("SELECT id, username, password_hash, password_change_required FROM user WHERE username = ?", username))
}

func (st *Store) GetUserByID(id int64) (*model.User, error) {
	return scanUser(st.db.QueryRow("SELECT id, username, password_hash, password_change_required FROM user WHERE id = ?", id))
}

func (st *Store) CreateUser(u *model.User) error {
	res, err := st.db.Exec(
		"INSERT INTO user (username, password_hash, password_change_required) VALUES (?, ?, ?)",
		u.Username, u.PasswordHash, boolToInt(u.PasswordChangeRequired),
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	u.ID = id
	return nil
}

func (st *Store) SetUserPassword(id int64, hash string, changeRequired bool) error {
	_, err := st.db.Exec(
		"UPDATE user SET password_hash = ?, password_change_required = ? WHERE id = ?",
		hash, boolToInt(changeRequired), id,
	)
	return err
}

// ---- session revocation --------------------------------------------------

// RevokeSession records that the login session sid was ended (logout), so a
// copy of its cookie is refused until expires, the session's own expiry. Rows
// past their expiry are dropped on the way, which keeps the table bounded by
// the number of logouts in one session lifetime.
func (st *Store) RevokeSession(sid string, expires time.Time) error {
	if _, err := st.db.Exec("DELETE FROM revoked_session WHERE expires < ?", formatDBTime(time.Now())); err != nil {
		return err
	}
	_, err := st.db.Exec("INSERT OR REPLACE INTO revoked_session (sid, expires) VALUES (?, ?)", sid, formatDBTime(expires))
	return err
}

// SessionRevoked reports whether sid was revoked by RevokeSession.
func (st *Store) SessionRevoked(sid string) (bool, error) {
	var n int
	err := st.db.QueryRow("SELECT count(*) FROM revoked_session WHERE sid = ?", sid).Scan(&n)
	return n > 0, err
}

// InitDefaultUser creates the default admin/admin account on first startup,
// flagged so the password-change gate forces an immediate change.
func (st *Store) InitDefaultUser() error {
	if _, err := st.GetUserByUsername("admin"); err == nil {
		return nil
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	hash, err := secret.GeneratePasswordHash("admin")
	if err != nil {
		return err
	}
	if err := st.CreateUser(&model.User{Username: "admin", PasswordHash: hash, PasswordChangeRequired: true}); err != nil {
		return err
	}
	slog.Warn("default admin user created; change the password immediately")
	return nil
}

// ---- small helpers -------------------------------------------------------

// nullStr maps an empty string to a SQL NULL, so blank optional columns are
// stored as NULL rather than an empty string.
func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

const dbTimeLayout = "2006-01-02 15:04:05.000000"

// formatDBTime renders a timestamp as naive UTC with microsecond precision,
// the column's stored text format.
func formatDBTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(dbTimeLayout)
}

func parseDBTime(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999",
		"2006-01-02 15:04:05",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
