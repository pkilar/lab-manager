// Package model holds the core domain types shared across the application: the
// Server and User records and the BMC vendor taxonomy.
package model

import (
	"net"
	"time"
)

// BMC vendor types. These exact string values are persisted in the database.
const (
	BMCIDRAC      = "idrac"
	BMCSupermicro = "supermicro"
	BMCILO        = "ilo"
	BMCPiKVM      = "pikvm"
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
	{BMCPiKVM, "PiKVM"},
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

// IPMI SOL payload instance bounds. The instance selects which serial port the
// BMC redirects over Serial-over-LAN — instance 1 is the first port (COM1),
// which is why it is the default. ipmitool enforces the same range and rejects
// anything outside it with "Instance must range from 1 to 15".
const (
	DefaultSOLInstance = 1
	MaxSOLInstance     = 15
)

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
	// SOLInstance is the IPMI SOL payload instance for the serial console; 0
	// means "not set" (rows written before the column existed). Read it through
	// SOLInstanceOrDefault rather than directly.
	SOLInstance int
	// CredentialsUnreadable is set by the store when a stored password is
	// shaped like an encrypted token but does not decrypt (lost or swapped
	// encryption key). That password field is then empty, and callers must not
	// contact the BMC: a ciphertext sent as a password only racks up failed
	// logins and can lock the BMC account.
	CredentialsUnreadable bool
}

// BMCHost returns the server's address formatted for the host part of a URL:
// the canonical IP, with an IPv6 literal bracketed. ok is false when the stored
// value is not an IP address, so a row that bypassed form validation is never
// used to build a URL.
func (s *Server) BMCHost() (host string, ok bool) {
	ip := net.ParseIP(s.IPAddress)
	if ip == nil {
		return "", false
	}
	if ip.To4() == nil {
		return "[" + ip.String() + "]", true
	}
	return ip.String(), true
}

// ValidIP reports whether the stored address is an IP literal. Callers that
// hand the address to ipmitool (which takes IPv6 unbracketed) check it here
// rather than trusting that every row came through the web form.
func (s *Server) ValidIP() bool {
	return net.ParseIP(s.IPAddress) != nil
}

// SOLInstanceOrDefault returns the serial console's payload instance, falling
// back to instance 1 for unset or out-of-range values so a bad stored number
// can never produce an ipmitool argument that fails the session outright.
func (s *Server) SOLInstanceOrDefault() int {
	if s.SOLInstance < DefaultSOLInstance || s.SOLInstance > MaxSOLInstance {
		return DefaultSOLInstance
	}
	return s.SOLInstance
}

// User mirrors a row of the `user` table.
type User struct {
	ID                     int64
	Username               string
	PasswordHash           string
	PasswordChangeRequired bool
}
