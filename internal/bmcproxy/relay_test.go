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
