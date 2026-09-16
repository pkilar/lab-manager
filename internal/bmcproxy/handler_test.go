package bmcproxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pkilar/lab-manager/internal/model"
)

// assertConsoleLaunch checks that loc is the HTML5 virtual-console page carrying
// the two iDRAC session tokens in the shapes the viewer expects (ST2 as ST2=,
// ST1 as TokenName/TokenKey) and pointing its KVM WebSocket at the proxy host on
// 5900. Structural, so it does not depend on query-parameter ordering.
func assertConsoleLaunch(t *testing.T, loc, wantST1, wantST2, wantHost string) {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Location %q: %v", loc, err)
	}
	if u.Path != "/virtualconsolehtml5.html" {
		t.Fatalf("Location path = %q, want the console page", u.Path)
	}
	q := u.Query()
	checks := map[string]string{
		"ST2": wantST2, "TokenName": "ST1", "TokenKey": wantST1,
		"ipAddr": wantHost, "kvmPort": "5900",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Errorf("console URL %s = %q, want %q", k, got, want)
		}
	}
}

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
	// The proxy lands the browser on the virtual-console page (built from the
	// login's ST1/ST2), not the System Summary dashboard the forwardUrl names.
	assertConsoleLaunch(t, resp.Header.Get("Location"), "aaa", "bbb", "idrac-1.pi.home.kilar.net")
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
	if !ok || sess.serverID != 1 || sess.idracCookie != "-http-session-="+idracSessionValue {
		t.Fatalf("session not stored correctly: %+v ok=%v", sess, ok)
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

func TestConsoleLaunchPathBuildsViewerURL(t *testing.T) {
	// Normal case: comma-separated tokens from the login forwardUrl.
	got := consoleLaunchPath("index.html?ST1=aaa,ST2=bbb", "idrac-1.pi.home.kilar.net")
	assertConsoleLaunch(t, got, "aaa", "bbb", "idrac-1.pi.home.kilar.net")

	// A host that carries a port (dev) must have it stripped: the viewer appends
	// kvmPort itself, so "host:8443" + 5900 would be nonsense.
	got = consoleLaunchPath("index.html?ST1=aaa,ST2=bbb", "idrac-1.pi.home.kilar.net:8443")
	assertConsoleLaunch(t, got, "aaa", "bbb", "idrac-1.pi.home.kilar.net")
}

// Without both tokens the console page cannot authenticate, so the caller must
// fall back to the dashboard rather than build a viewer URL that would fail.
func TestConsoleLaunchPathFallsBackWithoutBothTokens(t *testing.T) {
	cases := []string{
		"index.html",              // iDRAC gave no tokens at all
		"index.html?ST1=aaa",      // missing ST2
		"index.html?ST2=bbb",      // missing ST1
		"",                        // empty
		"index.html?ST1=,ST2=bbb", // ST1 present but empty
	}
	for _, in := range cases {
		if got := consoleLaunchPath(in, "idrac-1.pi.home.kilar.net"); got != "" {
			t.Errorf("consoleLaunchPath(%q) = %q, want \"\" (fall back to dashboard)", in, got)
		}
	}
}

func TestLogoutIDRACReleasesSession(t *testing.T) {
	idrac := newFakeIDRAC(t)
	m := NewManager(fakeLookup{}, []byte("s"), "pi.home.kilar.net")
	m.logoutIDRAC(hostport(idrac), "-http-session-="+idracSessionValue)
	if idrac.logoutCount() != 1 {
		t.Fatalf("logoutIDRAC should call /data/logout once, got %d", idrac.logoutCount())
	}
}

func TestHandshakeLogsOutPriorSession(t *testing.T) {
	idrac := newFakeIDRAC(t)
	m := NewManager(fakeLookup{1: {ID: 1, BMCType: model.BMCIDRAC, IPAddress: hostport(idrac), RedfishUser: "root", RedfishPassword: "calvin"}}, []byte("s"), "pi.home.kilar.net")
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
	// Wrong creds so the fake's /data/login returns authResult 5.
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
