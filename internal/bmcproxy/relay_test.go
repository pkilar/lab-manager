package bmcproxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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
	t.Cleanup(m.Close)
	sid, _, err := m.sessions.create(1, hostport(idrac), "-http-session-="+idracSessionValue)
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

// The KVM applet emits query strings net/url cannot parse (bare escapes,
// semicolon separators), which ReverseProxy.Rewrite drops unless the raw string
// is copied across. The browser's own forwarding headers must never reach the
// BMC either: Rewrite strips X-Forwarded-*/Forwarded, and the relay drops the
// X-Real-Ip that Traefik adds on top.
func TestRelayPreservesRawQueryAndStripsForwardingHeaders(t *testing.T) {
	front, _, sid := relayServer(t)
	const rawQuery = "ST1=aaa,ST2=bbb&kvmport=5900;foo=%ZZ"
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/echo?"+rawQuery, nil)
	req.AddCookie(&http.Cookie{Name: proxyCookieName, Value: sid})
	for h, v := range map[string]string{
		"X-Forwarded-For":   "203.0.113.9",
		"X-Forwarded-Host":  "evil.example",
		"X-Forwarded-Proto": "http",
		"Forwarded":         "for=203.0.113.9",
		"X-Real-Ip":         "203.0.113.9",
	} {
		req.Header.Set(h, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	want := "rawquery=" + rawQuery + "|xff=|xfh=|xfp=|fwd=|xrip="
	if got := readAll(t, resp); got != want {
		t.Fatalf("upstream saw\n %q\nwant\n %q", got, want)
	}
}

// sessionStore.get() used to hand out the *proxySession itself after releasing
// the mutex, so relay read sess.idracCookie unlocked while a concurrent
// /rotate response rewrote that same field under the lock via updateCookie.
// The raced field is the credential injected upstream. Overlapping relays trip
// the race detector; this passes only once get() returns a copy.
func TestRelayConcurrentRotateIsRaceFree(t *testing.T) {
	front, _, sid := relayServer(t)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for _, path := range []string{"/rotate", "/protected", "/rotate"} {
				req, _ := http.NewRequest(http.MethodGet, front.URL+path, nil)
				req.AddCookie(&http.Cookie{Name: proxyCookieName, Value: sid})
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		})
	}
	wg.Wait()
}

func TestRelayWithoutCookieBounces(t *testing.T) {
	front, _, _ := relayServer(t)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/protected", nil)
	// Production shape: canonical proxy host, TLS terminated at Traefik. The
	// bounce back to the initiator must then be absolute HTTPS with no port.
	req.Host = "idrac-1.pi.home.kilar.net"
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := c.Do(req)
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

func TestRewriteLocationHandlesPortAndScope(t *testing.T) {
	cases := []struct {
		loc, ip, want string
	}{
		{"https://10.0.0.5/login", "10.0.0.5", "https://idrac-1.example/login"},
		{"https://10.0.0.5:443/login", "10.0.0.5", "https://idrac-1.example/login"},     // iDRAC :443 redirect
		{"https://10.0.0.5:443/login", "10.0.0.5:443", "https://idrac-1.example/login"}, // ip carries port (test-like)
		{"/relative/path", "10.0.0.5", "/relative/path"},                                // relative: untouched
		{"https://other.example/x", "10.0.0.5", "https://other.example/x"},              // foreign host: untouched
	}
	for _, c := range cases {
		resp := &http.Response{Header: http.Header{}}
		resp.Header.Set("Location", c.loc)
		rewriteLocation(resp, c.ip, "idrac-1.example", "https")
		if got := resp.Header.Get("Location"); got != c.want {
			t.Errorf("rewriteLocation(%q, ip=%q) = %q, want %q", c.loc, c.ip, got, c.want)
		}
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

// After login the proxy injects a one-shot auto-launch script into the first
// dashboard document, so the operator's console opens itself instead of making
// them find a launch button. The flag is set at handshake; here we set it
// directly on the pre-created session to exercise the relay path.
func TestRelayInjectsAutoLaunchIntoDashboard(t *testing.T) {
	front, m, sid := relayServer(t)
	m.sessions.setAutoLaunch(sid)

	body := getDashboard(t, front, sid)
	// The upstream gzips (the browser asked for it); the proxy must strip
	// Accept-Encoding so the Transport hands ModifyResponse a decompressed body.
	// If that failed, the injected script would have landed in gzip bytes and
	// "dashboard" would be unreadable here.
	if !strings.Contains(body, "dashboard") {
		t.Errorf("dashboard body not delivered decompressed; got %q", body)
	}
	if !strings.Contains(body, "QuickLaunch('viewer')") {
		t.Error("dashboard HTML should carry the auto-launch script")
	}
	// The script must run, so it goes in the <head> (a frameset ignores scripts
	// placed after </frameset>): assert it lands before the body content.
	if strings.Index(body, "__labmgrKVM") > strings.Index(body, "dashboard") {
		t.Error("auto-launch script must be injected into <head>, before the body")
	}

	// One-shot: a second load of the same session must NOT be injected again.
	if again := getDashboard(t, front, sid); strings.Contains(again, "QuickLaunch('viewer')") {
		t.Error("auto-launch must be injected only once per handshake")
	}
}

// Non-HTML responses (assets, XHR) must never be rewritten, even while the flag
// is pending — injecting into JSON or an image would corrupt it.
func TestRelayDoesNotInjectIntoNonHTML(t *testing.T) {
	front, m, sid := relayServer(t)
	m.sessions.setAutoLaunch(sid)

	// /protected returns text/plain; the flag must survive for the real dashboard.
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/protected", nil)
	req.AddCookie(&http.Cookie{Name: proxyCookieName, Value: sid})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	_ = resp.Body.Close()
	if strings.Contains(body, "QuickLaunch") {
		t.Fatalf("non-HTML response was injected: %q", body)
	}
	if !m.sessions.takeAutoLaunch(sid) {
		t.Error("a non-HTML response must not consume the one-shot flag")
	}
}

func getDashboard(t *testing.T, front *httptest.Server, sid string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: proxyCookieName, Value: sid})
	req.Header.Set("Accept-Encoding", "gzip") // the browser asks for gzip; proxy must strip it
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return readAll(t, resp)
}

func TestInjectScript(t *testing.T) {
	cases := []struct{ in, want string }{
		// Head-first: a frameset runs scripts only in the head.
		{"<html><head></head><frameset></frameset></html>", "<html><head>SCRIPT</head><frameset></frameset></html>"},
		{"<html><HEAD></HEAD><body>x</body></html>", "<html><HEAD>SCRIPT</HEAD><body>x</body></html>"}, // case-insensitive
		{"<html><body>x</body></html>", "<html><body>xSCRIPT</body></html>"},                           // no head: before </body>
		{"<html>no body</html>", "<html>no bodySCRIPT</html>"},                                         // only </html>
		{"raw fragment", "raw fragmentSCRIPT"},                                                         // neither: append
	}
	for _, c := range cases {
		if got := string(injectScript([]byte(c.in), "SCRIPT")); got != c.want {
			t.Errorf("injectScript(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// maybeInjectAutoLaunch, unit-tested directly so the guards don't depend on
// Transport compression quirks: identity HTML with the flag set is injected; a
// compressed body is left alone AND keeps the flag for a later identity load.
func TestMaybeInjectAutoLaunchGuards(t *testing.T) {
	newResp := func(ct, ce, body string) *http.Response {
		h := http.Header{}
		if ct != "" {
			h.Set("Content-Type", ct)
		}
		if ce != "" {
			h.Set("Content-Encoding", ce)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Request:    &http.Request{Method: http.MethodGet},
			Header:     h,
			Body:       io.NopCloser(strings.NewReader(body)),
		}
	}
	bodyOf := func(r *http.Response) string {
		b, _ := io.ReadAll(r.Body)
		return string(b)
	}

	t.Run("identity html is injected", func(t *testing.T) {
		m := NewManager(fakeLookup{}, []byte("s"), "pi.home.kilar.net")
		t.Cleanup(m.Close)
		sid, _, _ := m.sessions.create(1, "", "c")
		m.sessions.setAutoLaunch(sid)
		resp := newResp("text/html", "", "<html><body>x</body></html>")
		if err := m.maybeInjectAutoLaunch(resp, sid); err != nil {
			t.Fatal(err)
		}
		if got := bodyOf(resp); !strings.Contains(got, "QuickLaunch('viewer')") {
			t.Errorf("identity HTML not injected: %q", got)
		}
		if resp.Header.Get("Content-Length") == "" {
			t.Error("Content-Length must be updated after injection")
		}
	})

	t.Run("gzip body is not injected and keeps the flag", func(t *testing.T) {
		m := NewManager(fakeLookup{}, []byte("s"), "pi.home.kilar.net")
		t.Cleanup(m.Close)
		sid, _, _ := m.sessions.create(1, "", "c")
		m.sessions.setAutoLaunch(sid)
		resp := newResp("text/html", "gzip", "\x1f\x8b compressed bytes")
		if err := m.maybeInjectAutoLaunch(resp, sid); err != nil {
			t.Fatal(err)
		}
		if got := bodyOf(resp); strings.Contains(got, "QuickLaunch") {
			t.Errorf("gzip body must not be injected: %q", got)
		}
		if !m.sessions.takeAutoLaunch(sid) {
			t.Error("a skipped (compressed) response must preserve the one-shot flag")
		}
	})
}

func TestRewriteSetCookiesFailsClosedOnMalformedSession(t *testing.T) {
	m := NewManager(nil, []byte("k"), "x.test")
	t.Cleanup(m.Close)
	// Empty ip: Close's logout skips it rather than dialing a real address.
	sid, _, _ := m.sessions.create(1, "", "-http-session-=OLD")
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", `-http-session-="abc; Path=/`) // unbalanced quote: unparseable
	resp.Header.Add("Set-Cookie", `  -http-session-=sp"ace; Path=/`)
	resp.Header.Add("Set-Cookie", `other="oops; Path=/`) // unparseable, not the session cookie
	m.rewriteSetCookies(resp, sid)

	got := resp.Header.Values("Set-Cookie")
	if len(got) != 1 || got[0] != `other="oops; Path=/` {
		t.Fatalf("want only the non-session cookie passed through, got %q", got)
	}
	if s, _ := m.sessions.get(sid); s.idracCookie != "-http-session-=OLD" {
		t.Fatalf("malformed line must not alter stored cookie: %q", s.idracCookie)
	}
}

func TestRewriteSetCookiesCapturesWellFormedSession(t *testing.T) {
	m := NewManager(nil, []byte("k"), "x.test")
	t.Cleanup(m.Close)
	// Empty ip: Close's logout skips it rather than dialing a real address.
	sid, _, _ := m.sessions.create(1, "", "-http-session-=OLD")
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "-http-session-=NEW; Path=/; Domain=idrac.test")
	m.rewriteSetCookies(resp, sid)
	if got := resp.Header.Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("session cookie leaked: %q", got)
	}
	if s, _ := m.sessions.get(sid); s.idracCookie != "-http-session-=NEW" {
		t.Fatalf("session cookie not captured: %q", s.idracCookie)
	}
}

// If the server's address changes after login, the session cookie belongs to the
// old BMC. It must not be replayed to the new address: the session is dropped,
// logged out where it was issued, and the browser bounced to the initiator.
func TestRelayIPChangeDropsSessionAndLogsOutOldBMC(t *testing.T) {
	idrac := newFakeIDRAC(t)
	srv := &model.Server{ID: 1, BMCType: model.BMCIDRAC, IPAddress: hostport(idrac)}
	m := NewManager(fakeLookup{1: srv}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	sid, _, err := m.sessions.create(1, hostport(idrac), "-http-session-="+idracSessionValue)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { m.relay(w, r, 1) }))
	t.Cleanup(front.Close)

	srv.IPAddress = "192.0.2.1:443" // operator re-addressed the server
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/protected", nil)
	req.AddCookie(&http.Cookie{Name: proxyCookieName, Value: sid})
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasSuffix(resp.Header.Get("Location"), "/server/1/kvm") {
		t.Fatalf("got %d Location=%q, want 302 to the initiator", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, ok := m.sessions.get(sid); ok {
		t.Error("session should be removed after an address change")
	}
	deadline := time.Now().Add(3 * time.Second)
	for idrac.logoutCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if idrac.logoutCount() != 1 {
		t.Errorf("old BMC logouts = %d, want 1", idrac.logoutCount())
	}
}

func TestMaybeInjectAutoLaunchOnlyOnRealDashboard(t *testing.T) {
	const doc = "<html><head></head><body>x</body></html>"
	newResp := func(method string, status int, ct string, body io.ReadCloser) *http.Response {
		return &http.Response{
			StatusCode: status,
			Request:    &http.Request{Method: method},
			Header:     http.Header{"Content-Type": {ct}},
			Body:       body,
		}
	}
	str := func(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }
	setup := func(t *testing.T) (*Manager, string) {
		m := NewManager(fakeLookup{}, []byte("s"), "pi.home.kilar.net")
		t.Cleanup(m.Close)
		sid, _, _ := m.sessions.create(1, "", "c")
		m.sessions.setAutoLaunch(sid)
		return m, sid
	}
	read := func(r *http.Response) string {
		b, _ := io.ReadAll(r.Body)
		return string(b)
	}

	t.Run("non-200 html keeps the flag for the real dashboard", func(t *testing.T) {
		m, sid := setup(t)
		for _, status := range []int{http.StatusFound, http.StatusNotFound, http.StatusNotModified} {
			r := newResp(http.MethodGet, status, "text/html", str(doc))
			if err := m.maybeInjectAutoLaunch(r, sid); err != nil {
				t.Fatal(err)
			}
			if got := read(r); got != doc {
				t.Errorf("status %d body altered: %q", status, got)
			}
		}
		r := newResp(http.MethodGet, http.StatusOK, "text/html; charset=utf-8", str(doc))
		if err := m.maybeInjectAutoLaunch(r, sid); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(read(r), "QuickLaunch('viewer')") {
			t.Error("a later 200 HTML must still receive the script")
		}
	})

	t.Run("HEAD keeps the flag and Content-Length", func(t *testing.T) {
		m, sid := setup(t)
		r := newResp(http.MethodHead, http.StatusOK, "text/html", str(""))
		r.Header.Set("Content-Length", "1234")
		if err := m.maybeInjectAutoLaunch(r, sid); err != nil {
			t.Fatal(err)
		}
		if r.Header.Get("Content-Length") != "1234" {
			t.Errorf("HEAD Content-Length rewritten to %q", r.Header.Get("Content-Length"))
		}
		if !m.sessions.takeAutoLaunch(sid) {
			t.Error("HEAD must not consume the one-shot flag")
		}
	})

	t.Run("media type must be exactly text/html", func(t *testing.T) {
		m, sid := setup(t)
		r := newResp(http.MethodGet, http.StatusOK, "text/htmlx", str(doc))
		if err := m.maybeInjectAutoLaunch(r, sid); err != nil {
			t.Fatal(err)
		}
		if read(r) != doc || !m.sessions.takeAutoLaunch(sid) {
			t.Error("text/htmlx must be left alone with the flag intact")
		}
	})

	t.Run("oversized body passes through byte-identical and keeps the flag", func(t *testing.T) {
		m, sid := setup(t)
		big := strings.Repeat("a", maxInjectBody+10)
		closed := false
		body := struct {
			io.Reader
			io.Closer
		}{strings.NewReader(big), closerFunc(func() error { closed = true; return nil })}
		r := newResp(http.MethodGet, http.StatusOK, "text/html", body)
		if err := m.maybeInjectAutoLaunch(r, sid); err != nil {
			t.Fatal(err)
		}
		if got := read(r); got != big {
			t.Errorf("oversized body altered (len %d, want %d)", len(got), len(big))
		}
		_ = r.Body.Close()
		if !closed {
			t.Error("original body Close must be preserved")
		}
		if !m.sessions.takeAutoLaunch(sid) {
			t.Error("oversized body must not consume the one-shot flag")
		}
	})
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

func TestRelayBlocksCrossSiteWrites(t *testing.T) {
	front, _, sid := relayServer(t)
	const host = "idrac-1.pi.home.kilar.net"
	do := func(method, origin string) int {
		req, _ := http.NewRequest(method, front.URL+"/protected", nil)
		req.Host = host
		req.AddCookie(&http.Cookie{Name: proxyCookieName, Value: sid})
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := noRedirect().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	cases := []struct {
		name, method, origin string
		want                 int
	}{
		{"same-host POST", http.MethodPost, "https://" + host, http.StatusOK},
		{"same-host POST other port", http.MethodPost, "https://" + host + ":5900", http.StatusOK},
		{"POST without Origin", http.MethodPost, "", http.StatusOK},
		{"sibling-host POST", http.MethodPost, "https://evil.pi.home.kilar.net", http.StatusForbidden},
		{"Origin null POST", http.MethodPost, "null", http.StatusForbidden},
		{"sibling-host DELETE", http.MethodDelete, "https://idrac-2.pi.home.kilar.net", http.StatusForbidden},
		{"GET with foreign Origin", http.MethodGet, "https://evil.pi.home.kilar.net", http.StatusOK},
	}
	for _, c := range cases {
		if got := do(c.method, c.origin); got != c.want {
			t.Errorf("%s: status %d, want %d", c.name, got, c.want)
		}
	}
}

func TestRelayBlocksCrossSiteWebSocket(t *testing.T) {
	front, _, sid := relayServer(t)
	u, _ := url.Parse(front.URL)
	u.Scheme = "ws"
	const host = "idrac-1.pi.home.kilar.net"
	dial := func(origin string) error {
		h := http.Header{"Cookie": {proxyCookieName + "=" + sid}, "Host": {host}, "Origin": {origin}}
		conn, _, err := websocket.DefaultDialer.Dial(u.String()+"/ws", h)
		if err == nil {
			_ = conn.Close()
		}
		return err
	}
	// The console page is on :443 and its socket on :5900 of the same host.
	if err := dial("https://" + host); err != nil {
		t.Errorf("same-host upgrade refused: %v", err)
	}
	if err := dial("https://evil.pi.home.kilar.net"); err == nil {
		t.Error("sibling-host upgrade must be refused")
	} else if !errors.Is(err, websocket.ErrBadHandshake) {
		t.Errorf("unexpected dial error: %v", err)
	}
}

func TestCloseLogsOutSessionsOnce(t *testing.T) {
	idrac := newFakeIDRAC(t)
	m := NewManager(fakeLookup{}, []byte("s"), "pi.home.kilar.net")
	if _, _, err := m.sessions.create(1, hostport(idrac), "-http-session-="+idracSessionValue); err != nil {
		t.Fatal(err)
	}
	m.Close()
	if idrac.logoutCount() != 1 {
		t.Fatalf("Close should log out the live session, got %d logouts", idrac.logoutCount())
	}
	m.Close() // idempotent
	if idrac.logoutCount() != 1 {
		t.Errorf("second Close must be a no-op, got %d logouts", idrac.logoutCount())
	}
	select {
	case <-m.done:
	default:
		t.Error("GC done channel should be closed")
	}
	var nilMgr *Manager
	nilMgr.Close() // nil-safe
}
