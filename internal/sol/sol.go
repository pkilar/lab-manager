// Package sol streams a server's IPMI Serial-over-LAN console. ipmitool runs
// server-side; the web layer bridges a Session's I/O to a browser terminal so
// credentials never reach the client.
package sol

import "github.com/pkilar/lab-manager/internal/model"

// Creds picks the credentials ipmitool should use: IPMI first, Redfish as a
// fallback (the same root/calvin works for iDRAC IPMI). ok is false when the
// server has neither.
func Creds(s *model.Server) (user, pass string, ok bool) {
	if s.IPMIUser != "" {
		return s.IPMIUser, s.IPMIPassword, true
	}
	if s.RedfishUser != "" {
		return s.RedfishUser, s.RedfishPassword, true
	}
	return "", "", false
}

// activateArgs / deactivateArgs build the ipmitool argv. The password is NOT an
// argv element — it is passed via the IPMI_PASSWORD env var and the -E flag, so
// it never appears in `ps`.
func activateArgs(ip, user string) []string   { return solArgs(ip, user, "activate") }
func deactivateArgs(ip, user string) []string { return solArgs(ip, user, "deactivate") }

func solArgs(ip, user, verb string) []string {
	return []string{"-I", "lanplus", "-H", ip, "-U", user, "-E", "sol", verb}
}
