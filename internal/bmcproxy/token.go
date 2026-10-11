// Package bmcproxy reverse-proxies a BMC's web UI under
// <prefix>-<id>.<domain> (idrac-<id> for Dell iDRACs, pikvm-<id> for PiKVMs;
// the per-vendor differences live in vendor.go), performing a server-side
// auto-login so the browser lands in the BMC logged in without the BMC session
// token ever reaching the client.
package bmcproxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// tokenValiditySeconds bounds how long a handshake token is usable.
const tokenValiditySeconds = 30

// mintToken signs a short-lived token authorizing a proxy handshake for one
// iDRAC. It is created by the login-gated initiator on the main host and
// verified by the proxy host (which cannot otherwise see the lab-manager
// session, being a different origin).
func mintToken(secret []byte, serverID int64) string {
	ts := time.Now().Unix()
	sig := hmacHex(secret, fmt.Sprintf("%d:%d", serverID, ts))
	return base64.URLEncoding.EncodeToString(fmt.Appendf(nil, "%d:%s", ts, sig))
}

func verifyToken(secret []byte, token string, serverID int64) bool {
	raw, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	tsStr, sig, ok := strings.Cut(string(raw), ":")
	if !ok {
		return false
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	if time.Now().Unix()-ts > tokenValiditySeconds {
		return false
	}
	expected := hmacHex(secret, fmt.Sprintf("%d:%d", serverID, ts))
	return subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) == 1
}

func hmacHex(key []byte, message string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}
