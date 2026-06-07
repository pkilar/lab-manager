package web

import (
	"net"
	"regexp"
	"strings"
)

var (
	macPattern  = regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)
	unsafeChars = regexp.MustCompile(`[<>"'&]`)
)

// validateIPAddress reports whether s is a valid IPv4 or IPv6 address.
func validateIPAddress(s string) bool {
	return net.ParseIP(strings.TrimSpace(s)) != nil
}

// validateMACAddress reports whether s is a valid MAC address. An empty string
// is valid because the MAC is optional.
func validateMACAddress(s string) bool {
	if s == "" {
		return true
	}
	return macPattern.MatchString(strings.TrimSpace(s))
}

// sanitizeServerName strips HTML-significant characters and limits the result to
// 100 runes.
func sanitizeServerName(name string) string {
	if name == "" {
		return ""
	}
	s := unsafeChars.ReplaceAllString(name, "")
	if r := []rune(s); len(r) > 100 {
		return string(r[:100])
	}
	return s
}
