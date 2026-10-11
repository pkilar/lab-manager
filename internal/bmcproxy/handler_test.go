package bmcproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pkilar/lab-manager/internal/model"
)

// proxyFront fronts m.Handler, letting the test set the proxy Host header.
func proxyFront(t *testing.T, m *Manager) *httptest.Server {
	t.Helper()
	// Emulate the production edge: Traefik terminates TLS and forwards the
	// original scheme. Without this the handshake is (correctly) treated as
	// plain HTTP, which drops the Secure cookie flag.
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Forwarded-Proto", "https")
		m.Handler(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestHandshakeLogsInAndSetsSession(t *testing.T) {
	idrac := newFakeIDRAC(t)
	m := NewManager(fakeLookup{1: {ID: 1, BMCType: model.BMCIDRAC, IPAddress: hostport(idrac), RedfishUser: "root", RedfishPassword: "calvin"}}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
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
			if !c.HttpOnly {
				t.Error("bmcproxy cookie must be HttpOnly")
			}
			if !c.Secure {
				t.Error("bmcproxy cookie must be Secure")
			}
		}
	}
	if sid == "" {
		t.Fatal("no bmcproxy cookie set")
	}
	sess, ok := m.sessions.get(sid)
	if !ok || sess.serverID != 1 || sess.bmcCookie != "-http-session-="+idracSessionValue {
		t.Fatalf("session not stored correctly: %+v ok=%v", sess, ok)
	}
	// The handshake flags the session so the dashboard it redirects to gets the
	// console auto-launch script injected.
	if !m.sessions.takeAutoLaunch(sid) {
		t.Error("handshake should flag the session for console auto-launch")
	}
}

func TestSafeForwardPathBlocksOpenRedirect(t *testing.T) {
	cases := []struct{ in, want string }{
		{"index.html?ST1=aaa,ST2=bbb", "/index.html?ST1=aaa,ST2=bbb"},
		{"/index.html?x=1", "/index.html?x=1"},
		{"//evil.com/x", "/x"},               // protocol-relative → same-origin path only
		{"https://evil.com/p?q=1", "/p?q=1"}, // absolute → host dropped
		{"", "/"},                            // empty → root
	}
	for _, c := range cases {
		if got := safeForwardPath(c.in); got != c.want {
			t.Errorf("safeForwardPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLogoutIDRACReleasesSession(t *testing.T) {
	idrac := newFakeIDRAC(t)
	m := NewManager(fakeLookup{}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	idracLogout(hostport(idrac), "-http-session-="+idracSessionValue)
	if idrac.logoutCount() != 1 {
		t.Fatalf("logoutIDRAC should call /data/logout once, got %d", idrac.logoutCount())
	}
}

func TestHandshakeLogsOutPriorSession(t *testing.T) {
	idrac := newFakeIDRAC(t)
	m := NewManager(fakeLookup{1: {ID: 1, BMCType: model.BMCIDRAC, IPAddress: hostport(idrac), RedfishUser: "root", RedfishPassword: "calvin"}}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	front := proxyFront(t, m)

	// Two handshakes for the same server: the second must log the first iDRAC
	// web session out so launches don't pile up on the iDRAC session table.
	for i := range 2 {
		tok := m.MintToken(1)
		req, _ := http.NewRequest(http.MethodGet, front.URL+"/__labmgr/auth?token="+tok, nil)
		req.Host = "idrac-1.pi.home.kilar.net"
		resp, err := noRedirect().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("handshake %d status=%d, want 302", i, resp.StatusCode)
		}
	}

	// The displaced logout fires in a goroutine; poll briefly for it.
	for i := 0; i < 100 && idrac.logoutCount() == 0; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if idrac.logoutCount() != 1 {
		t.Fatalf("second handshake should log out the first session exactly once, got %d", idrac.logoutCount())
	}
}

func TestHandshakeBadTokenBounces(t *testing.T) {
	idrac := newFakeIDRAC(t)
	m := NewManager(fakeLookup{1: {ID: 1, BMCType: model.BMCIDRAC, IPAddress: hostport(idrac)}}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
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
	t.Cleanup(m.Close)
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
	// Wrong creds so the fake's /data/login returns authResult 5.
	m := NewManager(fakeLookup{1: {ID: 1, BMCType: model.BMCIDRAC, IPAddress: hostport(idrac), RedfishUser: "root", RedfishPassword: "wrong"}}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
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
