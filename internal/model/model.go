// Package model holds the core domain types shared across the application: the
// Server and User records and the BMC vendor taxonomy.
package model

import "time"

// BMC vendor types. These exact string values are persisted in the database.
const (
	BMCIDRAC      = "idrac"
	BMCSupermicro = "supermicro"
	BMCILO        = "ilo"
	BMCGeneric    = "generic"
)

// BMCTypes is the ordered list of (value, label) pairs offered in the UI.
var BMCTypes = []struct {
	Value string
	Label string
}{
	{BMCIDRAC, "Dell iDRAC"},
	{BMCSupermicro, "Supermicro IPMI"},
	{BMCILO, "HPE iLO"},
	{BMCGeneric, "Generic/Other"},
}

// ValidBMCType reports whether t is a recognized BMC vendor value.
func ValidBMCType(t string) bool {
	for _, b := range BMCTypes {
		if b.Value == t {
			return true
		}
	}
	return false
}

// Server represents a row of the `server` table. The password fields hold DECRYPTED
// plaintext in memory; the store encrypts them on write and decrypts on read, so
// only ciphertext is ever persisted.
type Server struct {
	ID              int64
	Name            string
	IPAddress       string
	BMCType         string
	RedfishUser     string
	RedfishPassword string
	IPMIUser        string
	IPMIPassword    string
	MACAddress      string
	Status          string
	LastUpdated     time.Time // UTC; the zero value means "never updated"
	Notes           string
}

// User mirrors a row of the `user` table.
type User struct {
	ID                     int64
	Username               string
	PasswordHash           string
	PasswordChangeRequired bool
}
