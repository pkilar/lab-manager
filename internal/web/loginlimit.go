package web

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/pkilar/lab-manager/internal/secret"
)

const (
	loginFreeFailures = 5
	loginMaxCooldown  = 5 * time.Minute
	loginIdleReset    = 15 * time.Minute
	loginMaxEntries   = 10_000
)

// dummyPasswordHash is verified for unknown usernames so they cost the same
// scrypt work as known ones. It is generated lazily (scrypt is slow and tests
// build many Apps). On a generation error it returns "", which
// CheckPasswordHash simply rejects: the timing equalisation degrades but
// authentication stays correct.
var dummyPasswordHash = sync.OnceValue(func() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	h, err := secret.GeneratePasswordHash(hex.EncodeToString(b))
	if err != nil {
		return ""
	}
	return h
})

// loginKey normalizes a username for throttling.
func loginKey(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

type loginEntry struct {
	fails       int
	nextAllowed time.Time
	lastFail    time.Time
}

// loginLimiter throttles password guessing per username. It is keyed by
// username rather than client IP because behind Traefik every request carries
// Traefik's RemoteAddr. Unknown usernames are tracked identically so the
// throttle does not reveal which accounts exist.
type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginEntry
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{entries: make(map[string]*loginEntry)}
}

// loginCooldown is the wait imposed after the given number of consecutive
// failures: 1s, doubling per extra failure, capped at loginMaxCooldown.
func loginCooldown(fails int) time.Duration {
	n := fails - loginFreeFailures
	if n < 0 {
		return 0
	}
	if n >= 9 { // 1s<<9 = 512s > cap; also avoids shift overflow
		return loginMaxCooldown
	}
	return min(time.Second<<n, loginMaxCooldown)
}

// get returns the live entry for key, discarding one idle past loginIdleReset.
// Callers hold l.mu.
func (l *loginLimiter) get(key string, now time.Time) *loginEntry {
	e := l.entries[key]
	if e != nil && now.Sub(e.lastFail) > loginIdleReset {
		delete(l.entries, key)
		return nil
	}
	return e
}

// allow reports whether an attempt may proceed. Past the free failures it
// reserves the next slot before returning true, so concurrent attempts cannot
// all slip through the same window.
func (l *loginLimiter) allow(key string, now time.Time) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.get(key, now)
	if e == nil || e.fails < loginFreeFailures {
		return true, 0
	}
	if now.Before(e.nextAllowed) {
		return false, e.nextAllowed.Sub(now)
	}
	e.nextAllowed = now.Add(loginCooldown(e.fails))
	return true, 0
}

// fail records a failed attempt.
func (l *loginLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.get(key, now)
	if e == nil {
		if len(l.entries) >= loginMaxEntries {
			l.prune(now)
		}
		e = &loginEntry{}
		l.entries[key] = e
	}
	e.fails++
	e.lastFail = now
	if e.fails >= loginFreeFailures {
		e.nextAllowed = now.Add(loginCooldown(e.fails))
	}
}

// succeed clears the failure history for key.
func (l *loginLimiter) succeed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// prune bounds memory: drop idle entries, and if the map is still full (an
// attacker spraying unique usernames), clear it. Forgetting throttle state only
// resets the free-failure allowance, which is an acceptable trade for a hard
// memory cap. Callers hold l.mu.
func (l *loginLimiter) prune(now time.Time) {
	for k, e := range l.entries {
		if now.Sub(e.lastFail) > loginIdleReset {
			delete(l.entries, k)
		}
	}
	if len(l.entries) >= loginMaxEntries {
		clear(l.entries)
	}
}
