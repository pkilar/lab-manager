// Package bmcproxy reverse-proxies a BMC's web UI under
// <prefix>-<id>.<domain> (idrac-<id> for Dell iDRACs, pikvm-<id> for PiKVMs;
// the per-vendor differences live in vendor.go), performing a server-side
// auto-login so the browser lands in the BMC logged in without the BMC session
// token ever reaching the client.
package bmcproxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// tokenValiditySeconds bounds how long a handshake token is usable.
const tokenValiditySeconds = 30

// tokenPurpose domain-separates handshake signatures: the same secret also signs
// console launch tokens and session cookies.
const tokenPurpose = "bmcproxy-handshake-v1|" //nolint:gosec // G101: an HMAC domain-separation label, not a secret

// usedTokens remembers consumed handshake tokens until they would have expired
// anyway, so a token leaked via logs or Referer can't be replayed.
type usedTokens struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// consume records token and reports whether this is its first use.
func (u *usedTokens) consume(token string) bool {
	now := time.Now()
	u.mu.Lock()
	defer u.mu.Unlock()
	for t, exp := range u.seen {
		if now.After(exp) {
			delete(u.seen, t)
		}
	}
	if _, dup := u.seen[token]; dup {
		return false
	}
	if u.seen == nil {
		u.seen = make(map[string]time.Time)
	}
	u.seen[token] = now.Add((tokenValiditySeconds + 5) * time.Second)
	return true
}

// mintToken signs a short-lived token authorizing a proxy handshake for one
// iDRAC. It is created by the login-gated initiator on the main host and
// verified by the proxy host (which cannot otherwise see the lab-manager
// session, being a different origin).
func mintToken(secret []byte, serverID int64) string {
	ts := time.Now().Unix()
	// The nonce keeps two launches in the same second distinct, which matters now
	// that each token is single-use.
	var nb [8]byte
	_, _ = rand.Read(nb[:])
	nonce := hex.EncodeToString(nb[:])
	sig := hmacHex(secret, fmt.Sprintf("%s%d:%d:%s", tokenPurpose, serverID, ts, nonce))
	return base64.URLEncoding.EncodeToString(fmt.Appendf(nil, "%d:%s:%s", ts, nonce, sig))
}

func verifyToken(secret []byte, token string, serverID int64) bool {
	raw, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	tsStr, rest, ok := strings.Cut(string(raw), ":")
	if !ok {
		return false
	}
	nonce, sig, ok := strings.Cut(rest, ":")
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
	expected := hmacHex(secret, fmt.Sprintf("%s%d:%d:%s", tokenPurpose, serverID, ts, nonce))
	return subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) == 1
}

func hmacHex(key []byte, message string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}
