# iDRAC KVM Reverse-Proxy Implementation Plan (Phase 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a feature-flagged reverse proxy that gives one-click auto-login into an iDRAC's web UI / HTML5 KVM by serving each iDRAC at `idrac-<id>.<proxy-domain>` through lab-manager.

**Architecture:** A new `internal/bmcproxy` package: parses the `idrac-<id>` Host, performs a signed-token → server-side `/data/login` handshake (holding the iDRAC `-http-session-` token server-side and injecting it upstream), and relays all other traffic via a single `httputil.ReverseProxy` (which also tunnels the KVM WebSocket — verified). `internal/web` dispatches proxy Hosts to it and adds a login-gated initiator + a "KVM" button. Feature-flagged by `LAB_MANAGER_BMC_PROXY_DOMAIN`; Swarm/Traefik-only.

**Tech Stack:** Go 1.26 stdlib (`net/http/httputil`, `crypto/tls`, `crypto/hmac`, `crypto/rand`, `html`); no new dependencies. Tests use stdlib `testing` + the already-present `github.com/gorilla/websocket` (test-only, for the fake iDRAC's WS echo + the WS client).

**Spec:** `docs/superpowers/specs/2026-06-10-idrac-kvm-proxy-design.md`

**Pre-verified:** `httputil.ReverseProxy` tunnels a WebSocket to an HTTPS self-signed backend with a skip-verify `Transport`, including injected `Cookie` and rewritten `Origin` (scratch experiment, since removed). The plan relies on this.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `internal/bmcproxy/token.go` (new) | HMAC mint/verify of the 30 s handshake token (server-id bound). |
| `internal/bmcproxy/session.go` (new) | In-memory proxy-session store: random ids → `{serverID, iDRAC cookie, expiry}`, TTL + GC. |
| `internal/bmcproxy/idrac_login.go` (new) | Server-side `/data/login`; returns the `-http-session-` cookie + `forwardUrl`. |
| `internal/bmcproxy/proxy.go` (new) | `Manager`, Host parsing, handshake, relay (`ReverseProxy` + Director/ModifyResponse), `Handler`. |
| `internal/bmcproxy/fakeidrac_test.go` (new) | Shared test fake iDRAC (httptest TLS) + `fakeLookup`. |
| `internal/bmcproxy/*_test.go` (new) | Per-file tests. |
| `internal/web/app.go` (modify) | `New` gains a proxy-domain arg; construct `*bmcproxy.Manager`; Host dispatch in `Handler`. |
| `internal/web/kvm.go` (new) | `/server/{id}/kvm` initiator (login-gated). |
| `internal/web/routes.go` (modify) | Register the initiator. |
| `internal/web/render.go` (modify) | `serverRow.KVMEnabled`. |
| `internal/web/templates/index.html` (modify) | "KVM" button. |
| `internal/web/handlers.go` (modify) | Set `KVMEnabled` when building index rows. |
| `internal/web/integration_test.go` (modify) | Update `testServer` for the new `New` signature. |
| `cmd/lab-manager/main.go` (modify) | Read `LAB_MANAGER_BMC_PROXY_DOMAIN`, pass to `web.New`. |
| `docker-stack.yml` (modify) | Traefik `idrac-*` router + the env var. |
| `CLAUDE.md`, `README.md` (modify) | Document the proxy, flag, and Traefik rule. |

Dependency graph: `model ← bmcproxy ← web` (bmcproxy depends only on `model`; it takes a `ServerLookup` interface that `*store.Store` satisfies).

---

## Task 1: `internal/bmcproxy` — handshake token

**Files:** Create `internal/bmcproxy/token.go`, `internal/bmcproxy/token_test.go`

- [ ] **Step 1: Write the failing test** — `internal/bmcproxy/token_test.go`

```go
package bmcproxy

import "testing"

func TestTokenRoundTrip(t *testing.T) {
	secret := []byte("test-secret")
	tok := mintToken(secret, 7)
	if !verifyToken(secret, tok, 7) {
		t.Fatal("valid token rejected")
	}
	if verifyToken(secret, tok, 8) {
		t.Fatal("token accepted for wrong server id")
	}
	if verifyToken([]byte("other"), tok, 7) {
		t.Fatal("token accepted under wrong secret")
	}
	if verifyToken(secret, "garbage", 7) {
		t.Fatal("garbage token accepted")
	}
}
```

- [ ] **Step 2: Run — expect FAIL** (undefined `mintToken`/`verifyToken`):
`go test ./internal/bmcproxy/ -run TestTokenRoundTrip`

- [ ] **Step 3: Implement** — `internal/bmcproxy/token.go`

```go
// Package bmcproxy reverse-proxies an iDRAC's web UI under
// idrac-<id>.<domain>, performing a server-side auto-login so the browser
// lands in the iDRAC logged in without the iDRAC session token ever reaching
// the client.
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
```

- [ ] **Step 4: Run — expect PASS**, plus `go vet ./internal/bmcproxy/` and `gofmt -l internal/bmcproxy/` clean.

- [ ] **Step 5: Commit**
```bash
git add internal/bmcproxy/token.go internal/bmcproxy/token_test.go
git commit -m "feat(bmcproxy): signed handshake token"
```

---

## Task 2: `internal/bmcproxy` — proxy-session store

**Files:** Create `internal/bmcproxy/session.go`, `internal/bmcproxy/session_test.go`

- [ ] **Step 1: Write the failing test** — `internal/bmcproxy/session_test.go`

```go
package bmcproxy

import (
	"testing"
	"time"
)

func TestSessionStoreCreateGetExpire(t *testing.T) {
	s := newSessionStore()
	base := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return base }

	id, err := s.create(42, "-http-session-=ABC")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, ok := s.get(id)
	if !ok || got.serverID != 42 || got.idracCookie != "-http-session-=ABC" {
		t.Fatalf("get = %+v ok=%v, want serverID 42", got, ok)
	}
	if _, ok := s.get("nope"); ok {
		t.Fatal("unknown id should not resolve")
	}

	s.updateCookie(id, "-http-session-=ROTATED")
	if g, _ := s.get(id); g.idracCookie != "-http-session-=ROTATED" {
		t.Fatalf("updateCookie not applied: %q", g.idracCookie)
	}

	// Advance past TTL: get must miss and the entry must be swept.
	s.now = func() time.Time { return base.Add(sessionTTL + time.Second) }
	if _, ok := s.get(id); ok {
		t.Fatal("expired session should not resolve")
	}
}
```

- [ ] **Step 2: Run — expect FAIL** (undefined symbols): `go test ./internal/bmcproxy/ -run TestSessionStore`

- [ ] **Step 3: Implement** — `internal/bmcproxy/session.go`

```go
package bmcproxy

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// sessionTTL bounds a proxy session's lifetime. After it lapses the user
// re-clicks KVM (the initiator re-runs the handshake).
const sessionTTL = 8 * time.Hour

// proxySession is the server-side state behind one opaque bmcproxy cookie. It
// holds the iDRAC session token to inject upstream — that token is never sent
// to the browser.
type proxySession struct {
	serverID    int64
	idracCookie string // "-http-session-=..." Cookie header value
	expiry      time.Time
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]*proxySession
	now      func() time.Time // injectable for tests
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]*proxySession{}, now: time.Now}
}

func (s *sessionStore) create(serverID int64, idracCookie string) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.sessions[id] = &proxySession{serverID: serverID, idracCookie: idracCookie, expiry: s.now().Add(sessionTTL)}
	s.mu.Unlock()
	return id, nil
}

func (s *sessionStore) get(id string) (*proxySession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, false
	}
	if s.now().After(sess.expiry) {
		delete(s.sessions, id)
		return nil, false
	}
	return sess, true
}

// updateCookie refreshes the injected iDRAC cookie when the controller rotates
// it mid-session (captured from an upstream Set-Cookie).
func (s *sessionStore) updateCookie(id, idracCookie string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[id]; ok {
		sess.idracCookie = idracCookie
	}
}

func (s *sessionStore) gc() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, sess := range s.sessions {
		if now.After(sess.expiry) {
			delete(s.sessions, id)
		}
	}
}

func randomID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
```

- [ ] **Step 4: Run — expect PASS**; `go vet` + `gofmt -l` clean. (`gc` is unused until Task 4 wires a GC ticker; Go does not flag unused unexported funcs, but if `go vet` ever complains, it is consumed in Task 4 — leave it.)

- [ ] **Step 5: Commit**
```bash
git add internal/bmcproxy/session.go internal/bmcproxy/session_test.go
git commit -m "feat(bmcproxy): in-memory proxy-session store"
```

---

## Task 3: `internal/bmcproxy` — iDRAC server-side login + shared test fake

**Files:** Create `internal/bmcproxy/idrac_login.go`, `internal/bmcproxy/fakeidrac_test.go`, `internal/bmcproxy/idrac_login_test.go`

- [ ] **Step 1: Create the shared test fake** — `internal/bmcproxy/fakeidrac_test.go`

```go
package bmcproxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/pkilar/lab-manager/internal/model"
)

// idracSessionValue is the -http-session- value the fake iDRAC issues on login.
const idracSessionValue = "SESSIONXYZ"

// newFakeIDRAC returns an httptest TLS server emulating the iDRAC endpoints the
// proxy touches: /data/login, a cookie-protected resource, a self-referential
// redirect, a cookie-rotating endpoint, and a WebSocket echo.
func newFakeIDRAC(t *testing.T) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{}
	mux := http.NewServeMux()

	mux.HandleFunc("/data/login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("user") != "root" || r.FormValue("password") != "calvin" {
			io.WriteString(w, `<root><status>ok</status><authResult>5</authResult></root>`)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "-http-session-", Value: idracSessionValue, Path: "/"})
		io.WriteString(w, `<root><status>ok</status><authResult>0</authResult>`+
			`<forwardUrl>index.html?ST1=aaa,ST2=bbb</forwardUrl></root>`)
	})

	requireSession := func(r *http.Request) bool {
		c, err := r.Cookie("-http-session-")
		return err == nil && c.Value == idracSessionValue
	}

	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		if !requireSession(r) {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, "unauthorized")
			return
		}
		io.WriteString(w, "secret-content")
	})

	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+"/protected", http.StatusFound)
	})

	mux.HandleFunc("/rotate", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "-http-session-", Value: "ROTATED", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "pref", Value: "1", Path: "/", Domain: strings.Split(r.Host, ":")[0]})
		io.WriteString(w, "rotated")
	})

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		if !requireSession(r) || r.Header.Get("Origin") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			_ = c.WriteMessage(mt, append([]byte("echo:"), msg...))
		}
	})

	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func hostport(srv *httptest.Server) string { return strings.TrimPrefix(srv.URL, "https://") }

// fakeLookup satisfies ServerLookup for tests.
type fakeLookup map[int64]*model.Server

func (f fakeLookup) GetServer(id int64) (*model.Server, error) {
	s, ok := f[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return s, nil
}
```

- [ ] **Step 2: Write the failing test** — `internal/bmcproxy/idrac_login_test.go`

```go
package bmcproxy

import (
	"context"
	"testing"
)

func TestIDRACLoginCapturesCookieAndForwardURL(t *testing.T) {
	idrac := newFakeIDRAC(t)
	cookie, forward, err := idracLogin(context.Background(), hostport(idrac), "root", "calvin")
	if err != nil {
		t.Fatalf("idracLogin: %v", err)
	}
	if cookie != "-http-session-="+idracSessionValue {
		t.Fatalf("cookie = %q, want -http-session-=%s", cookie, idracSessionValue)
	}
	if forward != "index.html?ST1=aaa,ST2=bbb" {
		t.Fatalf("forward = %q", forward)
	}
}

func TestIDRACLoginRejectsBadCreds(t *testing.T) {
	idrac := newFakeIDRAC(t)
	if _, _, err := idracLogin(context.Background(), hostport(idrac), "root", "wrong"); err == nil {
		t.Fatal("expected error on bad credentials")
	}
}
```

- [ ] **Step 3: Run — expect FAIL** (undefined `idracLogin`): `go test ./internal/bmcproxy/ -run TestIDRACLogin`

- [ ] **Step 4: Implement** — `internal/bmcproxy/idrac_login.go`

```go
package bmcproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const idracSessionCookie = "-http-session-"

// proxyTransport reaches BMCs which present self-signed certs. Shared so its
// connection pool is reused across the login and the relay.
var proxyTransport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // BMCs use self-signed certs
}

// loginClient never follows redirects: /data/login returns 200 + XML, and we
// must read the Set-Cookie/forwardUrl off that exact response.
var loginClient = &http.Client{
	Transport:     proxyTransport,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

var (
	authResultPattern = regexp.MustCompile(`<authResult>(\d+)</authResult>`)
	forwardURLPattern = regexp.MustCompile(`<forwardUrl>([^<]*)</forwardUrl>`)
)

// idracLogin performs the iDRAC web login server-side and returns the
// "-http-session-=..." cookie to inject upstream plus the SPA forward URL
// ("index.html?ST1=...,ST2=...").
func idracLogin(ctx context.Context, ip, user, pass string) (cookie, forwardURL string, err error) {
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	form := strings.NewReader(url.Values{"user": {user}, "password": {pass}}.Encode())
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, "https://"+ip+"/data/login", form)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := loginClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	m := authResultPattern.FindSubmatch(body)
	if m == nil {
		return "", "", errors.New("iDRAC login response unparseable")
	}
	if string(m[1]) != "0" {
		return "", "", fmt.Errorf("iDRAC login failed (authResult %s)", m[1])
	}
	for _, c := range resp.Cookies() {
		if c.Name == idracSessionCookie {
			cookie = c.Name + "=" + c.Value
			break
		}
	}
	if cookie == "" {
		return "", "", errors.New("iDRAC login set no session cookie")
	}
	fm := forwardURLPattern.FindSubmatch(body)
	if fm == nil {
		return "", "", errors.New("iDRAC login response had no forwardUrl")
	}
	return cookie, string(fm[1]), nil
}
```

- [ ] **Step 5: Run — expect PASS**; vet + gofmt clean.

- [ ] **Step 6: Commit**
```bash
git add internal/bmcproxy/idrac_login.go internal/bmcproxy/fakeidrac_test.go internal/bmcproxy/idrac_login_test.go
git commit -m "feat(bmcproxy): server-side iDRAC login + shared test fake"
```

---

## Task 4: `internal/bmcproxy` — Manager, Host parsing, initiator helpers

**Files:** Create `internal/bmcproxy/proxy.go`; create `internal/bmcproxy/proxy_test.go`

- [ ] **Step 1: Write the failing test** — `internal/bmcproxy/proxy_test.go`

```go
package bmcproxy

import "testing"

func newTestManager() *Manager {
	return NewManager(fakeLookup{}, []byte("secret"), "pi.home.kilar.net")
}

func TestHostServerID(t *testing.T) {
	m := newTestManager()
	cases := []struct {
		host   string
		wantID int64
		wantOK bool
	}{
		{"idrac-1.pi.home.kilar.net", 1, true},
		{"idrac-42.pi.home.kilar.net:443", 42, true},
		{"lab.pi.home.kilar.net", 0, false},
		{"idrac-1.evil.com", 0, false},
		{"idrac-x.pi.home.kilar.net", 0, false},
		{"pi.home.kilar.net", 0, false},
	}
	for _, c := range cases {
		id, ok := m.HostServerID(c.host)
		if id != c.wantID || ok != c.wantOK {
			t.Errorf("HostServerID(%q) = (%d,%v), want (%d,%v)", c.host, id, ok, c.wantID, c.wantOK)
		}
	}
}

func TestEnabledAndURLs(t *testing.T) {
	if NewManager(fakeLookup{}, nil, "").Enabled() {
		t.Fatal("empty domain should be disabled")
	}
	m := newTestManager()
	if !m.Enabled() {
		t.Fatal("configured domain should be enabled")
	}
	tok := m.MintToken(3)
	if got := m.AuthURL(3, tok); got != "https://idrac-3.pi.home.kilar.net/__labmgr/auth?token="+tok {
		t.Fatalf("AuthURL = %q", got)
	}
	if got := m.appBaseURL(); got != "https://lab.pi.home.kilar.net" {
		t.Fatalf("appBaseURL = %q", got)
	}
}
```
> Note: `MintToken` produces URL-safe base64 (no characters needing query-escaping), so the expected `AuthURL` compares against the raw token.

- [ ] **Step 2: Run — expect FAIL** (undefined `Manager`, etc.): `go test ./internal/bmcproxy/ -run 'TestHostServerID|TestEnabledAndURLs'`

- [ ] **Step 3: Implement** — `internal/bmcproxy/proxy.go`

```go
package bmcproxy

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/pkilar/lab-manager/internal/model"
)

// proxyCookieName is the opaque session cookie the browser holds on the proxy
// subdomain. It maps to server-side state (the injected iDRAC cookie).
const proxyCookieName = "bmcproxy"

// ServerLookup fetches a server by id; *store.Store satisfies it.
type ServerLookup interface {
	GetServer(id int64) (*model.Server, error)
}

// Manager serves the iDRAC reverse proxy for idrac-<id>.<domain> hosts.
type Manager struct {
	lookup   ServerLookup
	secret   []byte
	domain   string // e.g. "pi.home.kilar.net"; empty disables the feature
	sessions *sessionStore
}

// NewManager builds a proxy Manager and starts its session GC. A blank domain
// yields a disabled manager (Enabled() == false).
func NewManager(lookup ServerLookup, secret []byte, domain string) *Manager {
	m := &Manager{lookup: lookup, secret: secret, domain: domain, sessions: newSessionStore()}
	if m.Enabled() {
		go m.sessionGC()
	}
	return m
}

func (m *Manager) sessionGC() {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		m.sessions.gc()
	}
}

// Enabled reports whether the proxy feature is configured.
func (m *Manager) Enabled() bool { return m != nil && m.domain != "" }

var hostIDPattern = regexp.MustCompile(`^idrac-(\d+)\.(.+)$`)

// HostServerID returns the iDRAC server id when host is a proxy host for this
// manager's domain.
func (m *Manager) HostServerID(host string) (int64, bool) {
	if !m.Enabled() {
		return 0, false
	}
	host = stripPort(host)
	mt := hostIDPattern.FindStringSubmatch(host)
	if mt == nil || mt[2] != m.domain {
		return 0, false
	}
	id, err := strconv.ParseInt(mt[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// MintToken signs a handshake token for the initiator on the main host.
func (m *Manager) MintToken(serverID int64) string { return mintToken(m.secret, serverID) }

// AuthURL is where the initiator redirects the browser to start the handshake.
func (m *Manager) AuthURL(serverID int64, token string) string {
	return fmt.Sprintf("https://idrac-%d.%s/__labmgr/auth?token=%s", serverID, m.domain, url.QueryEscape(token))
}

// appBaseURL is the main app's external URL (used to bounce expired sessions
// back through the login-gated initiator). The app is deployed at lab.<domain>.
func (m *Manager) appBaseURL() string { return "https://lab." + m.domain }
```

- [ ] **Step 4: Run — expect PASS**; vet + gofmt clean.

- [ ] **Step 5: Commit**
```bash
git add internal/bmcproxy/proxy.go internal/bmcproxy/proxy_test.go
git commit -m "feat(bmcproxy): Manager, host parsing, initiator helpers"
```

---

## Task 5: `internal/bmcproxy` — the relay (HTTP + WebSocket)

**Files:** Modify `internal/bmcproxy/proxy.go`; create `internal/bmcproxy/relay_test.go`

- [ ] **Step 1: Write the failing tests** — `internal/bmcproxy/relay_test.go`

```go
package bmcproxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pkilar/lab-manager/internal/model"
)

// relayServer fronts m.relay for server id 1, backed by a fake iDRAC, with one
// pre-created proxy session. Returns the front server and the session id.
func relayServer(t *testing.T) (*httptest.Server, *Manager, string) {
	t.Helper()
	idrac := newFakeIDRAC(t)
	m := NewManager(fakeLookup{1: {ID: 1, BMCType: model.BMCIDRAC, IPAddress: hostport(idrac)}}, []byte("s"), "pi.home.kilar.net")
	sid, err := m.sessions.create(1, "-http-session-="+idracSessionValue)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.relay(w, r, 1)
	}))
	t.Cleanup(front.Close)
	return front, m, sid
}

func TestRelayInjectsSessionCookie(t *testing.T) {
	front, _, sid := relayServer(t)
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/protected", nil)
	req.AddCookie(&http.Cookie{Name: proxyCookieName, Value: sid})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := readAll(t, resp)
	if resp.StatusCode != 200 || body != "secret-content" {
		t.Fatalf("status=%d body=%q (upstream cookie not injected?)", resp.StatusCode, body)
	}
}

func TestRelayWithoutCookieBounces(t *testing.T) {
	front, _, _ := relayServer(t)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(front.URL + "/protected")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://lab.pi.home.kilar.net/server/1/kvm" {
		t.Fatalf("bounce Location = %q", loc)
	}
}

func TestRelayRewritesLocationAndCookies(t *testing.T) {
	front, m, sid := relayServer(t)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Location pointing at the iDRAC host is rewritten to the proxy host.
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/redirect", nil)
	req.AddCookie(&http.Cookie{Name: proxyCookieName, Value: sid})
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc := resp.Header.Get("Location")
	frontHost := strings.TrimPrefix(front.URL, "http://")
	if !strings.HasPrefix(loc, "http://"+frontHost+"/protected") {
		t.Fatalf("Location not rewritten to proxy host: %q", loc)
	}

	// Upstream -http-session- Set-Cookie is captured server-side and stripped;
	// other cookies pass through with Domain dropped.
	req2, _ := http.NewRequest(http.MethodGet, front.URL+"/rotate", nil)
	req2.AddCookie(&http.Cookie{Name: proxyCookieName, Value: sid})
	resp2, err := c.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	for _, sc := range resp2.Header.Values("Set-Cookie") {
		if strings.HasPrefix(sc, "-http-session-=") {
			t.Fatalf("iDRAC session cookie leaked to browser: %q", sc)
		}
		if strings.Contains(strings.ToLower(sc), "domain=") {
			t.Fatalf("passthrough cookie kept its Domain: %q", sc)
		}
	}
	if g, _ := m.sessions.get(sid); g.idracCookie != "-http-session-=ROTATED" {
		t.Fatalf("rotation not captured: %q", g.idracCookie)
	}
}

func TestRelayTunnelsWebSocket(t *testing.T) {
	front, _, sid := relayServer(t)
	u, _ := url.Parse(front.URL)
	u.Scheme = "ws"
	h := http.Header{"Cookie": {proxyCookieName + "=" + sid}}
	conn, resp, err := websocket.DefaultDialer.Dial(u.String()+"/ws", h)
	if err != nil {
		t.Fatalf("ws dial through proxy: %v (resp %v)", err, resp)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err := conn.WriteMessage(websocket.TextMessage, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != "echo:hi" {
		t.Fatalf("ws round-trip = %q, want echo:hi", msg)
	}
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}
```

- [ ] **Step 2: Run — expect FAIL** (undefined `m.relay`): `go test ./internal/bmcproxy/ -run TestRelay`

- [ ] **Step 3: Implement** — append to `internal/bmcproxy/proxy.go`

Add these imports to the existing import block: `"log"`, `"net/http"`, `"net/http/httputil"`, `"strings"`. (Final block: `fmt`, `log`, `net`, `net/http`, `net/http/httputil`, `net/url`, `regexp`, `strconv`, `strings`, `time`, and the `model` import.)

Then append:
```go
// relay proxies an authenticated request to the iDRAC, injecting the
// server-side session cookie. A single ReverseProxy handles both plain HTTP and
// the KVM WebSocket (it natively tunnels Upgrade requests).
func (m *Manager) relay(w http.ResponseWriter, r *http.Request, id int64) {
	sess, sid := m.sessionFor(r)
	if sess == nil || sess.serverID != id {
		http.Redirect(w, r, m.appBaseURL()+"/server/"+strconv.FormatInt(id, 10)+"/kvm", http.StatusFound)
		return
	}
	s, err := m.lookup.GetServer(id)
	if err != nil {
		http.Error(w, "server not found", http.StatusNotFound)
		return
	}
	m.serveHTTP(w, r, sid, s.IPAddress, sess.idracCookie)
}

func (m *Manager) sessionFor(r *http.Request) (*proxySession, string) {
	c, err := r.Cookie(proxyCookieName)
	if err != nil {
		return nil, ""
	}
	sess, ok := m.sessions.get(c.Value)
	if !ok {
		return nil, ""
	}
	return sess, c.Value
}

func (m *Manager) serveHTTP(w http.ResponseWriter, r *http.Request, sid, ip, idracCookie string) {
	rp := &httputil.ReverseProxy{
		Transport: proxyTransport,
		Director: func(req *http.Request) {
			req.URL.Scheme = "https"
			req.URL.Host = ip
			req.Host = ip
			req.Header.Set("Origin", "https://"+ip)
			req.Header.Set("Referer", "https://"+ip+"/")
			// Rebuild Cookie: drop our proxy cookie and any client-supplied
			// session, then inject the server-held iDRAC session.
			var keep []string
			for _, c := range req.Cookies() {
				if c.Name == proxyCookieName || c.Name == idracSessionCookie {
					continue
				}
				keep = append(keep, c.Name+"="+c.Value)
			}
			keep = append(keep, idracCookie)
			req.Header.Set("Cookie", strings.Join(keep, "; "))
		},
		ModifyResponse: func(resp *http.Response) error {
			rewriteLocation(resp, ip, r.Host)
			m.rewriteSetCookies(resp, sid)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Printf("ERROR: bmcproxy upstream %s: %v", ip, err)
			http.Error(w, "iDRAC unreachable", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

// rewriteLocation rewrites a redirect that points at the iDRAC host so it points
// at the proxy host instead; relative and other-host Locations are left alone.
func rewriteLocation(resp *http.Response, ip, proxyHost string) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	u, err := url.Parse(loc)
	if err != nil {
		return
	}
	if u.Host == ip {
		u.Scheme = "https"
		u.Host = proxyHost
		resp.Header.Set("Location", u.String())
	}
}

// rewriteSetCookies captures the iDRAC session cookie into server-side state
// (and strips it from the browser-facing response); other cookies are
// host-scoped to the subdomain by dropping their Domain attribute.
func (m *Manager) rewriteSetCookies(resp *http.Response, sid string) {
	lines := resp.Header.Values("Set-Cookie")
	if len(lines) == 0 {
		return
	}
	var out []string
	for _, line := range lines {
		c, err := http.ParseSetCookie(line)
		if err != nil {
			out = append(out, line)
			continue
		}
		if c.Name == idracSessionCookie {
			m.sessions.updateCookie(sid, c.Name+"="+c.Value)
			continue
		}
		c.Domain = ""
		out = append(out, c.String())
	}
	resp.Header.Del("Set-Cookie")
	for _, line := range out {
		resp.Header.Add("Set-Cookie", line)
	}
}
```
> `http.ParseSetCookie` is stdlib (Go 1.23+). The `r.Host` captured in `ModifyResponse` is the inbound proxy host, which is what `Location` must point back to.

- [ ] **Step 4: Run — expect PASS** (run with the race detector, since the relay is concurrent): `go test -race ./internal/bmcproxy/ -run TestRelay -v`. Then vet + gofmt clean.

- [ ] **Step 5: Commit**
```bash
git add internal/bmcproxy/proxy.go internal/bmcproxy/relay_test.go
git commit -m "feat(bmcproxy): HTTP + WebSocket relay with cookie injection and rewriting"
```

---

## Task 6: `internal/bmcproxy` — handshake + top-level Handler

**Files:** Modify `internal/bmcproxy/proxy.go`; create `internal/bmcproxy/handler_test.go`

- [ ] **Step 1: Write the failing tests** — `internal/bmcproxy/handler_test.go`

```go
package bmcproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pkilar/lab-manager/internal/model"
)

// proxyFront fronts m.Handler, letting the test set the proxy Host header.
func proxyFront(t *testing.T, m *Manager) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(m.Handler))
	t.Cleanup(s.Close)
	return s
}

func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestHandshakeLogsInAndSetsSession(t *testing.T) {
	idrac := newFakeIDRAC(t)
	m := NewManager(fakeLookup{1: {ID: 1, BMCType: model.BMCIDRAC, IPAddress: hostport(idrac)}}, []byte("s"), "pi.home.kilar.net")
	front := proxyFront(t, m)

	tok := m.MintToken(1)
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/__labmgr/auth?token="+tok, nil)
	req.Host = "idrac-1.pi.home.kilar.net"
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/index.html?ST1=aaa,ST2=bbb" {
		t.Fatalf("Location = %q", loc)
	}
	var sid string
	for _, c := range resp.Cookies() {
		if c.Name == proxyCookieName {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("no bmcproxy cookie set")
	}
	sess, ok := m.sessions.get(sid)
	if !ok || sess.serverID != 1 || sess.idracCookie != "-http-session-="+idracSessionValue {
		t.Fatalf("session not stored correctly: %+v ok=%v", sess, ok)
	}
}

func TestHandshakeBadTokenBounces(t *testing.T) {
	idrac := newFakeIDRAC(t)
	m := NewManager(fakeLookup{1: {ID: 1, BMCType: model.BMCIDRAC, IPAddress: hostport(idrac)}}, []byte("s"), "pi.home.kilar.net")
	front := proxyFront(t, m)

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/__labmgr/auth?token=bad", nil)
	req.Host = "idrac-1.pi.home.kilar.net"
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound ||
		resp.Header.Get("Location") != "https://lab.pi.home.kilar.net/server/1/kvm" {
		t.Fatalf("bad token: status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestHandlerRejectsUnknownHost(t *testing.T) {
	m := NewManager(fakeLookup{}, []byte("s"), "pi.home.kilar.net")
	front := proxyFront(t, m)
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
	req.Host = "lab.pi.home.kilar.net" // not a proxy host
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("non-proxy host status=%d, want 404", resp.StatusCode)
	}
}

func TestHandshakeLoginFailureShowsError(t *testing.T) {
	idrac := newFakeIDRAC(t)
	// Server with WRONG creds so the fake's /data/login returns authResult 5.
	m := NewManager(fakeLookup{1: {ID: 1, BMCType: model.BMCIDRAC, IPAddress: hostport(idrac), RedfishUser: "root", RedfishPassword: "wrong"}}, []byte("s"), "pi.home.kilar.net")
	front := proxyFront(t, m)
	tok := m.MintToken(1)
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/__labmgr/auth?token="+tok, nil)
	req.Host = "idrac-1.pi.home.kilar.net"
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("login failure status=%d, want 502", resp.StatusCode)
	}
	if !strings.Contains(readAll(t, resp), "iDRAC login failed") {
		t.Fatal("error page missing reason")
	}
}
```
> Note: `TestHandshakeLogsInAndSetsSession` uses a server with no explicit creds; `handleAuth` must default to the iDRAC account. The fake accepts `root`/`calvin`, so the no-cred lookup entry must resolve to those — see the implementation: when neither Redfish nor IPMI creds are set the handshake errors. **Set the happy-path lookup server's creds to `root`/`calvin`.** Update that test's lookup to `{ID:1, BMCType: model.BMCIDRAC, IPAddress: hostport(idrac), RedfishUser:"root", RedfishPassword:"calvin"}`.

- [ ] **Step 2: Fix the happy-path test's creds** (per the note): in `TestHandshakeLogsInAndSetsSession`, set `RedfishUser: "root", RedfishPassword: "calvin"` on the lookup entry.

- [ ] **Step 3: Run — expect FAIL** (undefined `m.Handler`, `m.handleAuth`): `go test ./internal/bmcproxy/ -run 'TestHandshake|TestHandler'`

- [ ] **Step 4: Implement** — append to `internal/bmcproxy/proxy.go`

Add imports `"context"` and `"html"` to the import block (final additions beyond Task 5's set).

```go
// Handler serves one request on a proxy host: the auth handshake, or a relay.
func (m *Manager) Handler(w http.ResponseWriter, r *http.Request) {
	id, ok := m.HostServerID(r.Host)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/__labmgr/auth" {
		m.handleAuth(w, r, id)
		return
	}
	m.relay(w, r, id)
}

// handleAuth verifies the handshake token, logs into the iDRAC server-side,
// stores the session, sets the opaque proxy cookie, and redirects the browser
// to the SPA forward URL.
func (m *Manager) handleAuth(w http.ResponseWriter, r *http.Request, id int64) {
	if !verifyToken(m.secret, r.URL.Query().Get("token"), id) {
		// Bounce through the login-gated initiator to re-mint.
		http.Redirect(w, r, m.appBaseURL()+"/server/"+strconv.FormatInt(id, 10)+"/kvm", http.StatusFound)
		return
	}
	s, err := m.lookup.GetServer(id)
	if err != nil || s.BMCType != model.BMCIDRAC {
		http.NotFound(w, r)
		return
	}
	user, pass := s.RedfishUser, s.RedfishPassword
	if user == "" {
		user, pass = s.IPMIUser, s.IPMIPassword
	}
	if user == "" {
		m.errorPage(w, "No credentials configured for this server")
		return
	}
	cookie, forwardURL, err := idracLogin(r.Context(), s.IPAddress, user, pass)
	if err != nil {
		log.Printf("ERROR: bmcproxy iDRAC login (server %d): %v", id, err)
		m.errorPage(w, err.Error())
		return
	}
	sid, err := m.sessions.create(id, cookie)
	if err != nil {
		m.errorPage(w, "internal error")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     proxyCookieName,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/"+strings.TrimPrefix(forwardURL, "/"), http.StatusFound)
}

func (m *Manager) errorPage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	fmt.Fprintf(w,
		`<!doctype html><meta charset="utf-8"><title>iDRAC proxy</title>`+
			`<body style="font-family:sans-serif;background:#1a1a2e;color:#fff;padding:40px">`+
			`<h2 style="color:#ef4444">Could not open iDRAC</h2><p>%s</p>`+
			`<p><a style="color:#60a5fa" href="%s/">&larr; Back to lab-manager</a></p>`,
		html.EscapeString(msg), html.EscapeString(m.appBaseURL()))
}
```
> `context` is used transitively via `r.Context()` (no direct `context.` reference needed) — if `goimports`/the compiler reports `context` unused, drop it from the import list. The compile is the source of truth; keep only the imports actually referenced (`fmt`, `html`, `log`, `net`, `net/http`, `net/http/httputil`, `net/url`, `regexp`, `strconv`, `strings`, `time`, `model`).

- [ ] **Step 5: Run — expect PASS** (whole package, race): `go test -race ./internal/bmcproxy/ -v`. Then vet + gofmt clean.

- [ ] **Step 6: Commit**
```bash
git add internal/bmcproxy/proxy.go internal/bmcproxy/handler_test.go
git commit -m "feat(bmcproxy): auth handshake and top-level Handler"
```

---

## Task 7: Web wiring — dispatch, initiator, button, config

**Files:** Modify `internal/web/app.go`, `internal/web/routes.go`, `internal/web/render.go`, `internal/web/handlers.go`, `internal/web/templates/index.html`, `internal/web/integration_test.go`, `cmd/lab-manager/main.go`; create `internal/web/kvm.go`, `internal/web/kvm_test.go`

- [ ] **Step 1: Extend `App` + `New` + Host dispatch** — `internal/web/app.go`

Add the import `"github.com/pkilar/lab-manager/internal/bmcproxy"`. Add the field `proxy *bmcproxy.Manager` to `App` (after `sol`). Change `New`'s signature and body:
```go
func New(st *store.Store, secretKey []byte, wolEnabled bool, bmcProxyDomain string) (*App, error) {
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	return &App{
		store:      st,
		power:      power.NewController(st, wolEnabled),
		console:    console.NewManager(secretKey),
		sol:        sol.NewManager(),
		proxy:      bmcproxy.NewManager(st, secretKey, bmcProxyDomain),
		tmpl:       tmpl,
		secretKey:  secretKey,
		wolEnabled: wolEnabled,
	}, nil
}
```
Replace `Handler`:
```go
// Handler builds the full middleware chain, with a Host-based split: requests to
// an idrac-<id>.<proxy-domain> host go to the BMC reverse proxy (its own auth,
// no app middleware — the iDRAC SPA needs large bodies and self-framing); all
// other hosts go through the normal app chain.
func (a *App) Handler() http.Handler {
	app := securityHeaders(limitRequestBody(a.withSession(a.withCSRF(a.routes()))))
	if !a.proxy.Enabled() {
		return app
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := a.proxy.HostServerID(r.Host); ok {
			a.proxy.Handler(w, r)
			return
		}
		app.ServeHTTP(w, r)
	})
}
```

- [ ] **Step 2: Create the initiator** — `internal/web/kvm.go`

```go
package web

import (
	"log"
	"net/http"

	"github.com/pkilar/lab-manager/internal/model"
)

// handleKVM (main host) starts the iDRAC KVM proxy handshake: it mints a
// short-lived token and redirects the browser to the iDRAC's proxy subdomain.
func (a *App) handleKVM(w http.ResponseWriter, r *http.Request) {
	if !a.proxy.Enabled() {
		http.NotFound(w, r)
		return
	}
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s, err := a.store.GetServer(id)
	if err != nil {
		a.notFoundOrError(w, r, err)
		return
	}
	if s.BMCType != model.BMCIDRAC {
		requestSession(r).flash("error", "KVM auto-login is only available for iDRAC servers")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if s.RedfishUser == "" && s.IPMIUser == "" {
		requestSession(r).flash("error", "No credentials configured for this server")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	log.Printf("KVM proxy launch: user=%d server=%d", currentUser(r).ID, id)
	token := a.proxy.MintToken(id)
	http.Redirect(w, r, a.proxy.AuthURL(id, token), http.StatusFound)
}
```

- [ ] **Step 3: Register the route** — `internal/web/routes.go`, after the SOL block:
```go
	// iDRAC KVM proxy initiator (no-op when the proxy is disabled).
	mux.HandleFunc("GET /server/{id}/kvm", a.requireLogin(true, a.handleKVM))
```

- [ ] **Step 4: View model + index button**

In `internal/web/render.go`, add to `serverRow` (after `HasCreds`):
```go
	KVMEnabled       bool
```
In `internal/web/handlers.go`, the index rows are built in `handleIndex` at the
`row := serverRow{` literal (around line 155, inside `for _, s := range servers`).
Add the `KVMEnabled` field to that literal, right after the `HasCreds:` line:
```go
		row := serverRow{
			ID:        s.ID,
			Name:      s.Name,
			IPAddress: s.IPAddress,
			BMCType:   s.BMCType,
			HasCreds:  s.RedfishUser != "" || s.IPMIUser != "",
			KVMEnabled: a.proxy.Enabled() && s.BMCType == model.BMCIDRAC,
			HasMAC:    s.MACAddress != "",
			Status:    s.Status,
			StatusOn:  s.Status == "On",
		}
```
(`model` is already imported in handlers.go; `gofmt` will realign the field
colons.)

In `internal/web/templates/index.html`, after the SOL "📟 Serial" `{{end}}`, add:
```html
                        {{if .KVMEnabled}}
                        <a href="/server/{{.ID}}/kvm" target="_blank" rel="noopener"
                            class="btn btn-info btn-sm" title="iDRAC KVM auto-login">KVM</a>
                        {{end}}
```

- [ ] **Step 5: Config** — `cmd/lab-manager/main.go`

Find the `web.New(st, secretKey, wolEnabled)` call (around the `wolEnabled :=` line) and change to:
```go
	wolEnabled := envBool("WOL_ENABLED", false)
	bmcProxyDomain := os.Getenv("LAB_MANAGER_BMC_PROXY_DOMAIN")
	app, err := web.New(st, secretKey, wolEnabled, bmcProxyDomain)
```
And add `"bmc_proxy_domain", bmcProxyDomain` to the existing `slog.Info("lab-manager listening", ...)` call's key/value args.

- [ ] **Step 6: Fix the test harness** — `internal/web/integration_test.go`

The `testServer` helper calls `New(st, []byte("integration-secret"), false)`. Update it to pass an empty proxy domain:
```go
	app, err := New(st, []byte("integration-secret"), false, "")
```

- [ ] **Step 7: Write the initiator test** — `internal/web/kvm_test.go`

```go
package web

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkilar/lab-manager/internal/secret"
	"github.com/pkilar/lab-manager/internal/store"
)

// proxyTestServer is testServer with the BMC proxy enabled for a fixed domain.
func proxyTestServer(t *testing.T) (*httptest.Server, *http.Client) {
	t.Helper()
	dir := t.TempDir()
	keyB64, err := secret.LoadEncryptionKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := secret.NewFernet(keyB64)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "servers.db"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.InitDefaultUser(); err != nil {
		t.Fatal(err)
	}
	app, err := New(st, []byte("integration-secret"), false, "pi.home.kilar.net")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return srv, c
}

func TestKVMInitiatorRedirectsToProxySubdomain(t *testing.T) {
	srv, c := proxyTestServer(t)
	authenticateAndSeed(t, srv.URL, c) // logs in, clears gate, adds iDRAC server id 1 (root/calvin)

	resp := func() *http.Response {
		r, err := c.Get(srv.URL + "/server/1/kvm")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}()
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://idrac-1.pi.home.kilar.net/__labmgr/auth?token=") {
		t.Fatalf("KVM initiator Location = %q", loc)
	}
}
```
> `authenticateAndSeed` (added in the SOL phase, in `sol_ws_test.go`) logs in, clears the password gate, and adds an iDRAC server with `root`/`calvin` — exactly what this test needs. Reuse it.

- [ ] **Step 8: Run — expect PASS** and the whole suite green:
```bash
go test ./internal/web/ -run 'TestKVMInitiator|TestTemplates|TestSOL|TestFullAuthFlow' -v
go build ./... && go vet ./... && gofmt -l internal cmd
```

- [ ] **Step 9: Commit**
```bash
git add internal/web/app.go internal/web/kvm.go internal/web/routes.go internal/web/render.go internal/web/handlers.go internal/web/templates/index.html internal/web/integration_test.go internal/web/kvm_test.go cmd/lab-manager/main.go
git commit -m "feat(web): host-dispatch the iDRAC KVM proxy + KVM initiator/button"
```

---

## Task 8: Traefik routing, docs, and final verification

**Files:** Modify `docker-stack.yml`, `CLAUDE.md`, `README.md`

- [ ] **Step 1: Add the Traefik router + env** — `docker-stack.yml`

Under `services.lab-manager.environment`, add:
```yaml
      # iDRAC KVM reverse proxy. Set to the base domain so the app answers
      # idrac-<id>.<domain> and shows the KVM button. Empty disables the feature.
      - LAB_MANAGER_BMC_PROXY_DOMAIN=${LAB_MANAGER_BMC_PROXY_DOMAIN:-}
```
Under `deploy.labels`, add a second router on the same service (Traefik v3.6 `HostRegexp` = Go regexp; reuses the default `*.pi` cert via `tls=true`):
```yaml
        - "traefik.http.routers.lab-manager-bmc.rule=HostRegexp(`^idrac-[0-9]+\\.pi\\.home\\.kilar\\.net$`)"
        - "traefik.http.routers.lab-manager-bmc.entrypoints=websecure"
        - "traefik.http.routers.lab-manager-bmc.tls=true"
        - "traefik.http.routers.lab-manager-bmc.service=lab-manager"
```
Add a comment noting it requires `LAB_MANAGER_BMC_PROXY_DOMAIN=pi.home.kilar.net` to be set, and that `*.pi.home.kilar.net` wildcard DNS already resolves to the cluster.

- [ ] **Step 2: Document** — `CLAUDE.md`

- Add to the packages list: `**internal/bmcproxy** — reverse-proxies an iDRAC at idrac-<id>.<domain> for one-click KVM auto-login: signed-token handshake, server-side /data/login, server-held iDRAC session injected upstream, single httputil.ReverseProxy for HTTP + the KVM WebSocket. Feature-flagged by LAB_MANAGER_BMC_PROXY_DOMAIN; Swarm/Traefik-only.`
- Add to the dependency-graph line: `…/console/sol/bmcproxy ← web`.
- Add to the Environment Variables section a `LAB_MANAGER_BMC_PROXY_DOMAIN` entry (base domain; unset disables; Swarm/Traefik-only; needs the `idrac-*` Traefik router + wildcard DNS + the `*.pi` cert).
- Add to Routes: `**iDRAC KVM proxy**: /server/<id>/kvm (initiator, main host) → idrac-<id>.<domain> (proxied iDRAC; /__labmgr/auth handshake + transparent relay)`.

- [ ] **Step 3: Document** — `README.md`

Add a short "iDRAC KVM auto-login (opt-in)" section: what it does, the `LAB_MANAGER_BMC_PROXY_DOMAIN` flag, the Traefik `idrac-*` router requirement, the wildcard-DNS/cert note, that it's Swarm-only (like WoL is compose-only), and that SOL is the fallback. (Match the README's existing "Wake-on-LAN (opt-in)" section style.)

- [ ] **Step 4: Final verification**
```bash
go mod tidy
gofmt -l internal cmd
go vet ./...
go build ./...
go test -race ./...
```
Expected: gofmt prints nothing; vet clean; build OK; all tests pass (including the new `internal/bmcproxy` package and the web suite).

- [ ] **Step 5: Commit**
```bash
git add docker-stack.yml CLAUDE.md README.md
git commit -m "docs+deploy: Traefik idrac-* router and iDRAC KVM proxy docs"
```

---

## Post-implementation: deploy-time verification (out of band, by the operator)

These cannot run from the dev host — they need the deployed cluster + a real iDRAC:

1. Set `LAB_MANAGER_BMC_PROXY_DOMAIN=pi.home.kilar.net`, deploy, confirm the `idrac-*` Traefik router is live.
2. Click **KVM** on the iDRAC row → confirm the browser lands logged into the iDRAC UI at `idrac-<id>.pi.home.kilar.net`.
3. Launch **Virtual Console** → confirm the HTML5 KVM connects (the WebSocket tunnels).
4. If the KVM fails to connect, capture the browser devtools Network/WS tab: the likely culprit is the vConsole JS building its WS URL from the iDRAC IP rather than `window.location`, or an `Origin`/`Referer` the proxy must match — report back for a targeted fix. SOL remains the working fallback throughout.

---

## Self-Review notes (addressed)

- **Spec coverage:** subdomain dispatch (T7), signed-token handshake (T1, T6), server-side `/data/login` + session injection (T3, T5, T6), session never in browser (T5 strips/captures `-http-session-`), single ReverseProxy for HTTP+WS (T5, pre-verified), `Location`/`Set-Cookie` rewriting (T5), KVM button gated on proxy+iDRAC (T7), feature flag (T4 `Enabled`, T7 dispatch, T8 env), iDRAC-only (T6 `handleAuth`, T7 initiator), Traefik v3.6 router (T8), docs (T8), deploy-time verification milestone (post-impl). Fake-iDRAC automated tests cover handshake/relay/WS/rewrite/expiry.
- **Type consistency:** `Manager` / `NewManager(ServerLookup, []byte, string)` / `Enabled` / `HostServerID` / `MintToken` / `AuthURL` / `appBaseURL` / `Handler` / `handleAuth` / `relay` / `serveHTTP` / `sessionFor` / `rewriteLocation` / `rewriteSetCookies` / `proxyCookieName` / `idracSessionCookie` / `proxyTransport` / `sessionStore`(`create`/`get`/`updateCookie`/`gc`/`now`) / `idracLogin` / `mintToken`/`verifyToken` are used identically across tasks. `web.New` gains one `string` arg, updated at both call sites (main.go, testServer).
- **No placeholders:** every code step is complete; the one harness-reuse (`authenticateAndSeed`) is a real existing helper from the SOL phase, named explicitly.
```
