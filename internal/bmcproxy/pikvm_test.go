package bmcproxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkilar/lab-manager/internal/model"
)

const pikvmTokenValue = "PIKVMTOKEN"

// fakePiKVM emulates the kvmd endpoints the proxy touches and records calls.
type fakePiKVM struct {
	*httptest.Server
	mu            sync.Mutex
	logins        int
	logoutCookies []string
	lastBody      string
	lastCT        string
	status        int  // login status override (0 = normal)
	noCookie      bool // auth-disabled mode: 200, no Set-Cookie
	revoked       bool // tokens dropped (a reboot or in-UI logout) until the next login
}

func (f *fakePiKVM) loginCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logins
}

func (f *fakePiKVM) logouts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.logoutCookies...)
}

func newFakePiKVM(t *testing.T) *fakePiKVM {
	t.Helper()
	f := &fakePiKVM{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		f.mu.Lock()
		f.logins++
		f.lastBody, f.lastCT = string(raw), r.Header.Get("Content-Type")
		status, noCookie := f.status, f.noCookie
		f.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		form, _ := url.ParseQuery(string(raw))
		if form.Get("user") != "admin" || form.Get("passwd") != "secret" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if !noCookie {
			http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: pikvmTokenValue, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		}
		f.mu.Lock()
		f.revoked = false
		f.mu.Unlock()
		io.WriteString(w, `{"ok": true, "result": {}}`)
	})
	mux.HandleFunc("/api/auth/check", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		noCookie, revoked := f.noCookie, f.revoked
		f.mu.Unlock()
		c, err := r.Cookie("auth_token")
		if noCookie || (!revoked && err == nil && (c.Value == pikvmTokenValue || c.Value == "ROTATED")) {
			io.WriteString(w, `{"ok": true, "result": {}}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		f.mu.Lock()
		f.logoutCookies = append(f.logoutCookies, r.Header.Get("Cookie"))
		f.mu.Unlock()
	})
	mux.HandleFunc("/echo-cookie", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "cookie=%s", r.Header.Get("Cookie"))
	})
	mux.HandleFunc("/rotate", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: "ROTATED", Path: "/"})
		io.WriteString(w, "rotated")
	})
	mux.HandleFunc("/kvm/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<html><head></head><body>pikvm</body></html>")
	})
	f.Server = httptest.NewTLSServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakePiKVM) ip() string { return strings.TrimPrefix(f.URL, "https://") }

func pikvmServer(f *fakePiKVM) *model.Server {
	return &model.Server{ID: 7, BMCType: model.BMCPiKVM, IPAddress: f.ip(), RedfishUser: "admin", RedfishPassword: "secret"}
}

func TestPikvmLogin(t *testing.T) {
	t.Run("cookie", func(t *testing.T) {
		f := newFakePiKVM(t)
		c, fwd, err := pikvmLogin(t.Context(), f.ip(), "admin", "secret")
		if err != nil || c != "auth_token="+pikvmTokenValue || fwd != "" {
			t.Fatalf("got (%q,%q,%v)", c, fwd, err)
		}
	})
	t.Run("form body", func(t *testing.T) {
		f := newFakePiKVM(t)
		_, _, _ = pikvmLogin(t.Context(), f.ip(), "admin", "se cret&x=1")
		form, _ := url.ParseQuery(f.lastBody)
		if form.Get("user") != "admin" || form.Get("passwd") != "se cret&x=1" {
			t.Fatalf("body = %q", f.lastBody)
		}
		if f.lastCT != "application/x-www-form-urlencoded" {
			t.Fatalf("content-type = %q", f.lastCT)
		}
	})
	t.Run("bad credentials", func(t *testing.T) {
		f := newFakePiKVM(t)
		_, _, err := pikvmLogin(t.Context(), f.ip(), "admin", "wrong")
		if err == nil || !strings.Contains(err.Error(), "invalid credentials") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("auth disabled", func(t *testing.T) {
		f := newFakePiKVM(t)
		f.noCookie = true
		c, _, err := pikvmLogin(t.Context(), f.ip(), "admin", "secret")
		if err != nil || c != "" {
			t.Fatalf("got (%q,%v), want empty cookie and no error", c, err)
		}
	})
	t.Run("server error", func(t *testing.T) {
		f := newFakePiKVM(t)
		f.status = http.StatusInternalServerError
		_, _, err := pikvmLogin(t.Context(), f.ip(), "admin", "secret")
		if err == nil || !strings.Contains(err.Error(), "500") {
			t.Fatalf("err = %v", err)
		}
	})
}

func pikvmHandshake(t *testing.T, m *Manager, front *httptest.Server, host, query string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/__labmgr/auth?token="+m.MintToken(7)+query, nil)
	req.Host = host
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

func proxyCookieOf(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == proxyCookieName {
			return c
		}
	}
	return nil
}

func TestPikvmHandshakeTargets(t *testing.T) {
	f := newFakePiKVM(t)
	m := NewManager(fakeLookup{7: pikvmServer(f)}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	front := proxyFront(t, m)
	const host = "pikvm-7.pi.home.kilar.net"

	cases := []struct{ query, want string }{
		{"", "/kvm/"},
		{"&to=terminal", "/extras/webterm/ttyd/"},
		{"&to=" + url.QueryEscape("//evil.com"), "/kvm/"},
		{"&to=garbage", "/kvm/"},
	}
	for _, c := range cases {
		resp := pikvmHandshake(t, m, front, host, c.query, nil)
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != c.want {
			t.Errorf("query %q: status=%d loc=%q, want %q", c.query, resp.StatusCode, resp.Header.Get("Location"), c.want)
		}
		pc := proxyCookieOf(resp)
		if pc == nil || !pc.HttpOnly || !pc.Secure {
			t.Fatalf("query %q: bad proxy cookie %+v", c.query, pc)
		}
		sess, ok := m.sessions.get(pc.Value)
		if !ok || sess.bmcCookie != "auth_token="+pikvmTokenValue || sess.vendor != pikvmVendor {
			t.Fatalf("session = %+v ok=%v", sess, ok)
		}
		if m.sessions.pendingAutoLaunch(pc.Value) {
			t.Error("PiKVM sessions must not be flagged for iDRAC auto-launch")
		}
	}
}

func TestHandshakeVendorMismatch404(t *testing.T) {
	f := newFakePiKVM(t)
	idrac := newFakeIDRAC(t)
	m := NewManager(fakeLookup{
		7: pikvmServer(f),
		1: {ID: 1, BMCType: model.BMCIDRAC, IPAddress: hostport(idrac), RedfishUser: "root", RedfishPassword: "calvin"},
	}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	front := proxyFront(t, m)

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/__labmgr/auth?token="+m.MintToken(1), nil)
	req.Host = "pikvm-1.pi.home.kilar.net" // iDRAC server on the pikvm host
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("pikvm host for iDRAC server: %d, want 404", resp.StatusCode)
	}
	if resp := pikvmHandshake(t, m, front, "idrac-7.pi.home.kilar.net", "", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("idrac host for PiKVM server: %d, want 404", resp.StatusCode)
	}
	if f.loginCount() != 0 {
		t.Error("mismatched handshake must not log in")
	}
}

func pikvmRelayFront(t *testing.T, m *Manager) *httptest.Server {
	t.Helper()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.relay(w, r, 7, pikvmVendor)
	}))
	t.Cleanup(front.Close)
	return front
}

func TestPikvmRelayCookies(t *testing.T) {
	f := newFakePiKVM(t)
	m := NewManager(fakeLookup{7: pikvmServer(f)}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	sid, _, _ := m.sessions.create(pikvmVendor, 7, f.ip(), "auth_token="+pikvmTokenValue)
	front := pikvmRelayFront(t, m)

	get := func(path string) (*http.Response, string) {
		req, _ := http.NewRequest(http.MethodGet, front.URL+path, nil)
		req.AddCookie(&http.Cookie{Name: proxyCookieName, Value: sid})
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: "FORGED"})
		req.AddCookie(&http.Cookie{Name: "keep", Value: "1"})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp, readAll(t, resp)
	}

	_, body := get("/echo-cookie")
	if body != "cookie=keep=1; auth_token="+pikvmTokenValue {
		t.Fatalf("upstream saw %q", body)
	}

	resp, _ := get("/rotate")
	if len(resp.Header.Values("Set-Cookie")) != 0 {
		t.Errorf("auth_token leaked to browser: %q", resp.Header.Values("Set-Cookie"))
	}
	if s, _ := m.sessions.get(sid); s.bmcCookie != "auth_token=ROTATED" {
		t.Errorf("rotation not captured: %q", s.bmcCookie)
	}

	// HTML is passed through untouched even if a (stray) flag were set.
	m.sessions.setAutoLaunch(sid)
	_, page := get("/kvm/")
	if strings.Contains(page, "QuickLaunch") || strings.Contains(page, "<script") {
		t.Errorf("iDRAC auto-launch script injected into PiKVM page: %q", page)
	}
}

func TestPikvmRelayNoCookieWhenAuthDisabled(t *testing.T) {
	f := newFakePiKVM(t)
	m := NewManager(fakeLookup{7: pikvmServer(f)}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	sid, _, _ := m.sessions.create(pikvmVendor, 7, f.ip(), "")
	front := pikvmRelayFront(t, m)
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/echo-cookie", nil)
	req.AddCookie(&http.Cookie{Name: proxyCookieName, Value: sid})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if body := readAll(t, resp); body != "cookie=" {
		t.Fatalf("upstream saw %q, want no cookie injected", body)
	}
}

func TestPikvmRelayBouncesPreserveTerminal(t *testing.T) {
	f := newFakePiKVM(t)
	m := NewManager(fakeLookup{7: pikvmServer(f)}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	front := pikvmRelayFront(t, m)
	for path, want := range map[string]string{
		"/extras/webterm/ttyd/ws": "/server/7/kvm?to=terminal",
		"/kvm/":                   "/server/7/kvm",
	} {
		req, _ := http.NewRequest(http.MethodGet, front.URL+path, nil) // no session
		resp, err := noRedirect().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || !strings.HasSuffix(loc, want) {
			t.Errorf("%s: status=%d loc=%q, want suffix %q", path, resp.StatusCode, loc, want)
		}
	}
}

func TestRelayVendorChangeBounces(t *testing.T) {
	f := newFakePiKVM(t)
	srv := pikvmServer(f)
	m := NewManager(fakeLookup{7: srv}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	sid, _, _ := m.sessions.create(pikvmVendor, 7, f.ip(), "auth_token="+pikvmTokenValue)
	front := pikvmRelayFront(t, m)

	srv.BMCType = model.BMCGeneric // operator retyped the server
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/kvm/", nil)
	req.AddCookie(&http.Cookie{Name: proxyCookieName, Value: sid})
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d, want 302", resp.StatusCode)
	}
	if _, ok := m.sessions.get(sid); ok {
		t.Error("session should be dropped")
	}
	waitFor(t, func() bool { return len(f.logouts()) == 1 })
	if got := f.logouts()[0]; got != "auth_token="+pikvmTokenValue {
		t.Errorf("logout cookie = %q", got)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not met in time")
	}
}

func TestPikvmSessionReuse(t *testing.T) {
	f := newFakePiKVM(t)
	m := NewManager(fakeLookup{7: pikvmServer(f)}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	front := proxyFront(t, m)
	const host = "pikvm-7.pi.home.kilar.net"

	first := pikvmHandshake(t, m, front, host, "", nil)
	pc := proxyCookieOf(first)
	if pc == nil || f.loginCount() != 1 {
		t.Fatalf("first handshake: cookie=%v logins=%d", pc, f.loginCount())
	}
	second := pikvmHandshake(t, m, front, host, "&to=terminal", &http.Cookie{Name: proxyCookieName, Value: pc.Value})
	if second.StatusCode != http.StatusFound || second.Header.Get("Location") != "/extras/webterm/ttyd/" {
		t.Fatalf("second: status=%d loc=%q", second.StatusCode, second.Header.Get("Location"))
	}
	if f.loginCount() != 1 {
		t.Errorf("logins = %d, want 1 (session reused)", f.loginCount())
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(f.logouts()); n != 0 {
		t.Errorf("logouts = %d, want 0", n)
	}
	if proxyCookieOf(second) != nil {
		t.Error("reuse must not issue a new proxy cookie")
	}
	// A stale/foreign cookie still performs a real login.
	pikvmHandshake(t, m, front, host, "", &http.Cookie{Name: proxyCookieName, Value: "bogus"})
	if f.loginCount() != 2 {
		t.Errorf("logins = %d, want 2 after an unrecognised cookie", f.loginCount())
	}
}

// The proxy's session record outlives the PiKVM's: a reboot drops every token.
// Reusing the dead cookie would land every later launch on the PiKVM login page
// until the proxy session expired, so a handshake must re-check it upstream and
// log in afresh when kvmd no longer honours it.
func TestPikvmSessionReuseRevalidates(t *testing.T) {
	f := newFakePiKVM(t)
	m := NewManager(fakeLookup{7: pikvmServer(f)}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	front := proxyFront(t, m)
	const host = "pikvm-7.pi.home.kilar.net"

	pc := proxyCookieOf(pikvmHandshake(t, m, front, host, "", nil))
	if pc == nil {
		t.Fatal("first handshake set no proxy cookie")
	}
	f.mu.Lock()
	f.revoked = true // the PiKVM rebooted
	f.mu.Unlock()

	again := pikvmHandshake(t, m, front, host, "", &http.Cookie{Name: proxyCookieName, Value: pc.Value})
	if f.loginCount() != 2 {
		t.Fatalf("logins = %d, want 2 (dead session must not be reused)", f.loginCount())
	}
	if again.StatusCode != http.StatusFound || again.Header.Get("Location") != "/kvm/" {
		t.Fatalf("re-login: status=%d loc=%q", again.StatusCode, again.Header.Get("Location"))
	}
	if np := proxyCookieOf(again); np == nil || np.Value == pc.Value {
		t.Error("a fresh login must issue a new proxy cookie")
	}
	// The dead session was displaced, and released on the BMC best-effort.
	waitFor(t, func() bool { return len(f.logouts()) == 1 })
}

func TestPikvmDisplaceLogsOutViaVendor(t *testing.T) {
	f := newFakePiKVM(t)
	m := NewManager(fakeLookup{7: pikvmServer(f)}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	front := proxyFront(t, m)
	// No cookie on the second handshake => fresh login displaces the first.
	pikvmHandshake(t, m, front, "pikvm-7.pi.home.kilar.net", "", nil)
	pikvmHandshake(t, m, front, "pikvm-7.pi.home.kilar.net", "", nil)
	waitFor(t, func() bool { return len(f.logouts()) == 1 })
	if got := f.logouts()[0]; got != "auth_token="+pikvmTokenValue {
		t.Errorf("logout cookie = %q", got)
	}
}

func TestPikvmGCAndCloseLogOut(t *testing.T) {
	f := newFakePiKVM(t)
	m := NewManager(fakeLookup{7: pikvmServer(f)}, []byte("s"), "pi.home.kilar.net")

	base := time.Unix(5_000_000, 0)
	m.sessions.now = func() time.Time { return base }
	_, _, _ = m.sessions.create(pikvmVendor, 7, f.ip(), "auth_token=GC")
	m.sessions.now = func() time.Time { return base.Add(sessionTTL + time.Second) }
	for _, s := range m.sessions.gc() {
		s.vendor.logout(s.ip, s.bmcCookie)
	}
	if got := f.logouts(); len(got) != 1 || got[0] != "auth_token=GC" {
		t.Fatalf("gc logouts = %q", got)
	}

	_, _, _ = m.sessions.create(pikvmVendor, 8, f.ip(), "auth_token=CLOSE")
	m.Close()
	if got := f.logouts(); len(got) != 2 || got[1] != "auth_token=CLOSE" {
		t.Fatalf("close logouts = %q", got)
	}
}

func TestPikvmLogoutNoopOnEmpty(t *testing.T) {
	f := newFakePiKVM(t)
	pikvmLogout(f.ip(), "")
	pikvmLogout("", "auth_token=x")
	if len(f.logouts()) != 0 {
		t.Fatal("empty ip/cookie must be a no-op")
	}
}

func TestAuthURLAndSupports(t *testing.T) {
	m := newTestManager(t)
	if got := m.AuthURL("https", "lab.pi.home.kilar.net", model.BMCIDRAC, 3, "T", ""); got != "https://idrac-3.pi.home.kilar.net/__labmgr/auth?token=T" {
		t.Errorf("idrac = %q", got)
	}
	if got := m.AuthURL("https", "lab.pi.home.kilar.net", model.BMCPiKVM, 7, "T", TargetTerminal); got != "https://pikvm-7.pi.home.kilar.net/__labmgr/auth?token=T&to=terminal" {
		t.Errorf("pikvm terminal = %q", got)
	}
	if got := m.AuthURL("http", "127.0.0.1:5000", model.BMCPiKVM, 7, "T", ""); got != "http://pikvm-7.pi.home.kilar.net:5000/__labmgr/auth?token=T" {
		t.Errorf("pikvm dev = %q", got)
	}

	for typ, want := range map[string]bool{
		model.BMCIDRAC: true, model.BMCPiKVM: true,
		model.BMCSupermicro: false, model.BMCILO: false, model.BMCGeneric: false, "": false,
	} {
		if got := m.Supports(typ); got != want {
			t.Errorf("Supports(%q) = %v, want %v", typ, got, want)
		}
	}
	off := NewManager(fakeLookup{}, nil, "")
	if off.Supports(model.BMCIDRAC) || off.Supports(model.BMCPiKVM) {
		t.Error("disabled manager must support nothing")
	}
}

func TestHostServerIDPiKVM(t *testing.T) {
	m := newTestManager(t)
	for host, want := range map[string]bool{
		"pikvm-7.pi.home.kilar.net":     true,
		"pikvm-7.pi.home.kilar.net:443": true,
		"pikvm-x.pi.home.kilar.net":     false,
		"pikvm-7.evil.com":              false,
	} {
		if _, ok := m.HostServerID(host); ok != want {
			t.Errorf("HostServerID(%q) ok=%v, want %v", host, ok, want)
		}
	}
	if got := upstreamHost(pikvmVendor, "10.0.0.9", "pikvm-7.pi.home.kilar.net:5900"); got != "10.0.0.9" {
		t.Errorf("pikvm must never forward the inbound port, got %q", got)
	}
}
