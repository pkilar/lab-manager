// Package store is the SQLite persistence layer. It transparently encrypts and
// decrypts the credential columns and runs the additive schema migrations.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
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
}

const serverColumns = `id, name, ip_address, bmc_type, redfish_user, redfish_password, ipmi_user, ipmi_password, mac_address, status, last_updated, notes`

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
	return st, nil
}

// Close releases the underlying database handle.
func (st *Store) Close() error { return st.db.Close() }

// migrate creates the tables for a fresh database and additively backfills
// columns that older databases may be missing — the two columns
// (user.password_change_required and server.bmc_type) added after the initial
// schema.
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
	notes TEXT
);
CREATE TABLE IF NOT EXISTS user (
	id INTEGER PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	password_change_required INTEGER DEFAULT 1
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

func (st *Store) decryptCredential(ciphertext string) string {
	if ciphertext == "" {
		return ""
	}
	pt, err := st.cipher.Decrypt(ciphertext)
	if err != nil {
		// Not a valid Fernet token — treat as a legacy plaintext credential
		// stored before encryption was introduced (return it unchanged).
		return ciphertext
	}
	return string(pt)
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
	)
	err := sc.Scan(&s.ID, &s.Name, &s.IPAddress, &bmc, &rfUser, &rfPass, &ipmiUser, &ipmiPass, &mac, &status, &lastUpdated, &notes)
	if err != nil {
		return nil, err
	}
	s.BMCType = bmc.String
	if s.BMCType == "" {
		s.BMCType = model.BMCGeneric
	}
	s.RedfishUser = rfUser.String
	s.RedfishPassword = st.decryptCredential(rfPass.String)
	s.IPMIUser = ipmiUser.String
	s.IPMIPassword = st.decryptCredential(ipmiPass.String)
	s.MACAddress = mac.String
	s.Status = status.String
	s.Notes = notes.String
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
		`INSERT INTO server (name, ip_address, bmc_type, redfish_user, redfish_password, ipmi_user, ipmi_password, mac_address, status, last_updated, notes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.Name, s.IPAddress, s.BMCType, nullStr(s.RedfishUser), rfPass, nullStr(s.IPMIUser), ipmiPass,
		nullStr(s.MACAddress), s.Status, formatDBTime(s.LastUpdated), nullStr(s.Notes),
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
	}
	args := []any{
		s.Name, s.IPAddress, s.BMCType, nullStr(s.RedfishUser),
		nullStr(s.IPMIUser), nullStr(s.MACAddress), s.Status, formatDBTime(s.LastUpdated), nullStr(s.Notes),
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
	_, err := st.db.Exec("UPDATE server SET "+strings.Join(set, ", ")+" WHERE id = ?", args...)
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
