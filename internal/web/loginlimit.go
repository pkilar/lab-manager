package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkilar/lab-manager/internal/secret"
)

const (
	loginFreeFailures = 5
	loginMaxCooldown  = 5 * time.Minute
	loginIdleReset    = 15 * time.Minute
	loginMaxEntries   = 10_000

	// Input caps, checked before any lookup or scrypt so oversized fields cost
	// nothing and cannot become limiter keys.
	maxUsernameBytes = 128
	maxPasswordBytes = 1024

	// scrypt (N=32768, r=8) costs ~32 MiB per call and the container is small, so
	// only a couple may run at once; the rest wait briefly, then get a 503.
	scryptConcurrency = 2
	scryptWait        = 5 * time.Second
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

// scryptGate bounds concurrent scrypt work. Capacity and wait are fields so
// tests can shrink them.
type scryptGate struct {
	sem        chan struct{}
	wait       time.Duration
	maxWaiters int32
	waiters    atomic.Int32
}

// scryptMaxWaiters bounds the queue behind the gate. Each waiter holds a
// connection and its buffers for up to the wait, so an unbounded queue only
// moves a login flood's memory growth from scrypt to the waiting requests.
const scryptMaxWaiters = 16

func newScryptGate(capacity int, wait time.Duration) *scryptGate {
	return &scryptGate{sem: make(chan struct{}, capacity), wait: wait, maxWaiters: scryptMaxWaiters}
}

// acquire waits up to g.wait (or until ctx is done) for a slot, and fails at
// once when the queue is already full. On success the caller must call the
// returned release.
func (g *scryptGate) acquire(ctx context.Context) (release func(), ok bool) {
	select {
	case g.sem <- struct{}{}:
		return func() { <-g.sem }, true
	default:
	}
	if g.waiters.Add(1) > g.maxWaiters {
		g.waiters.Add(-1)
		return nil, false
	}
	defer g.waiters.Add(-1)
	t := time.NewTimer(g.wait)
	defer t.Stop()
	select {
	case g.sem <- struct{}{}:
		return func() { <-g.sem }, true
	case <-t.C:
		return nil, false
	case <-ctx.Done():
		return nil, false
	}
}

type loginEntry struct {
	fails       int
	inflight    int // admitted attempts whose result has not come back yet
	nextAllowed time.Time
	lastFail    time.Time
}

// loginLimiter throttles password guessing per username. It is keyed by
// username rather than client IP because behind Traefik every request carries
// Traefik's RemoteAddr. Unknown usernames are tracked identically so the
// throttle does not reveal which accounts exist.
//
// It also carries the scrypt gate and the change-password limiter (keyed by
// user id, a separate map so a crafted username cannot collide with it), so all
// of the password-guessing state lives in one injectable place.
type loginLimiter struct {
	mu         sync.Mutex
	entries    map[string]*loginEntry
	maxEntries int

	gate *scryptGate
	pw   *loginLimiter // change-password current-password check, keyed by user id
}

func newBareLimiter() *loginLimiter {
	return &loginLimiter{entries: make(map[string]*loginEntry), maxEntries: loginMaxEntries}
}

func newLoginLimiter() *loginLimiter {
	l := newBareLimiter()
	l.gate = newScryptGate(scryptConcurrency, scryptWait)
	l.pw = newBareLimiter()
	return l
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

// get returns the live entry for key, discarding one idle past loginIdleReset
// (never one with attempts in flight). Callers hold l.mu.
func (l *loginLimiter) get(key string, now time.Time) *loginEntry {
	e := l.entries[key]
	if e != nil && e.inflight == 0 && now.Sub(e.lastFail) > loginIdleReset {
		delete(l.entries, key)
		return nil
	}
	return e
}

// add inserts a fresh entry, making room first when the map is full. Callers
// hold l.mu.
func (l *loginLimiter) add(key string, now time.Time) *loginEntry {
	if len(l.entries) >= l.maxEntries {
		l.prune(now)
	}
	e := &loginEntry{lastFail: now}
	l.entries[key] = e
	return e
}

// allow reports whether an attempt may proceed. Every true must be followed by
// exactly one of fail, succeed or abort, which releases its in-flight slot.
// While under the free failures, fails+inflight is capped at the allowance so a
// burst of concurrent guesses cannot all slip through before any result lands.
// Past them it reserves the next slot before returning true.
func (l *loginLimiter) allow(key string, now time.Time) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.get(key, now)
	if e == nil {
		e = l.add(key, now)
	}
	if e.fails < loginFreeFailures {
		if e.fails+e.inflight >= loginFreeFailures {
			return false, time.Second
		}
		e.inflight++
		return true, 0
	}
	if now.Before(e.nextAllowed) {
		return false, e.nextAllowed.Sub(now)
	}
	e.nextAllowed = now.Add(loginCooldown(e.fails))
	e.inflight++
	return true, 0
}

// release gives back an in-flight slot. Callers hold l.mu.
func (e *loginEntry) release() {
	if e.inflight > 0 {
		e.inflight--
	}
}

// fail records a failed attempt.
func (l *loginLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.get(key, now)
	if e == nil {
		e = l.add(key, now)
	}
	e.release()
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

// abort ends an admitted attempt that produced no verdict (e.g. the server was
// too busy to check it), so it counts as neither a failure nor a success.
func (l *loginLimiter) abort(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		return
	}
	e.release()
	if e.fails == 0 && e.inflight == 0 {
		delete(l.entries, key)
	}
}

// prune bounds memory: drop idle entries, and if the map is still full (an
// attacker spraying unique usernames) evict the least recently failed tenth,
// sparing entries in cooldown and with attempts in flight where possible. A
// spray therefore pushes out its own harmless one-off entries instead of
// wiping the lockout on a real account. Callers hold l.mu.
func (l *loginLimiter) prune(now time.Time) {
	for k, e := range l.entries {
		if e.inflight == 0 && now.Sub(e.lastFail) > loginIdleReset {
			delete(l.entries, k)
		}
	}
	if len(l.entries) < l.maxEntries {
		return
	}
	keys := make([]string, 0, len(l.entries))
	for k := range l.entries {
		keys = append(keys, k)
	}
	rank := func(e *loginEntry) int {
		switch {
		case e.inflight > 0:
			return 2
		case now.Before(e.nextAllowed):
			return 1
		}
		return 0
	}
	slices.SortFunc(keys, func(a, b string) int {
		ea, eb := l.entries[a], l.entries[b]
		if ra, rb := rank(ea), rank(eb); ra != rb {
			return ra - rb
		}
		return ea.lastFail.Compare(eb.lastFail)
	})
	for _, k := range keys[:max(1, l.maxEntries/10)] {
		delete(l.entries, k)
	}
}
