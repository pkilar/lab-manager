package web

import (
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkilar/lab-manager/internal/model"
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

// parseSOLInstance reads the serial console's IPMI payload instance from form
// input. An empty field means "unspecified" and yields the default (instance 1,
// the first serial port), so the field can be left alone on every existing
// server. Out-of-range values are rejected rather than clamped: silently
// turning a typo into instance 1 would open a console on the wrong port and
// look like a BMC fault.
func parseSOLInstance(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return model.DefaultSOLInstance, true
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < model.DefaultSOLInstance || n > model.MaxSOLInstance {
		return 0, false
	}
	return n, true
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
