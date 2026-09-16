package bmcproxy

import (
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

func TestInjectBeforeBodyClose(t *testing.T) {
	cases := []struct{ in, want string }{
		{"<html><body>x</body></html>", "<html><body>xSCRIPT</body></html>"},
		{"<HTML><BODY>x</BODY></HTML>", "<HTML><BODY>xSCRIPT</BODY></HTML>"}, // case-insensitive
		{"<html>no body</html>", "<html>no bodySCRIPT</html>"},               // falls to </html>
		{"raw fragment", "raw fragmentSCRIPT"},                               // neither: append
	}
	for _, c := range cases {
		if got := string(injectBeforeBodyClose([]byte(c.in), "SCRIPT")); got != c.want {
			t.Errorf("injectBeforeBodyClose(%q) = %q, want %q", c.in, got, c.want)
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
		return &http.Response{Header: h, Body: io.NopCloser(strings.NewReader(body))}
	}
	bodyOf := func(r *http.Response) string {
		b, _ := io.ReadAll(r.Body)
		return string(b)
	}

	t.Run("identity html is injected", func(t *testing.T) {
		m := NewManager(fakeLookup{}, []byte("s"), "pi.home.kilar.net")
		sid, _, _ := m.sessions.create(1, "x", "c")
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
		sid, _, _ := m.sessions.create(1, "x", "c")
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
