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

	// Behind Traefik the browser's scheme arrives as X-Forwarded-Proto, so the
	// handshake must be minted as HTTPS. (The exact production host form —
	// https, no port — is locked in bmcproxy.TestEnabledAndURLs; here the
	// httptest listener necessarily carries a port.)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/server/1/kvm", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://idrac-1.pi.home.kilar.net") ||
		!strings.Contains(loc, "/__labmgr/auth?token=") {
		t.Fatalf("KVM initiator Location = %q", loc)
	}
}

// Over plain HTTP on a non-default port the handshake must stay on that scheme
// and port. Hardcoding https here sent the browser to a host that does not
// resolve in development, which is why the KVM path could only ever be
// exercised in production.
func TestKVMInitiatorKeepsDevSchemeAndPort(t *testing.T) {
	srv, c := proxyTestServer(t)
	authenticateAndSeed(t, srv.URL, c)

	resp, err := c.Get(srv.URL + "/server/1/kvm") // plain-HTTP httptest host:port
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	want := "http://idrac-1.pi.home.kilar.net:" + port + "/__labmgr/auth?token="
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, want) {
		t.Fatalf("dev KVM initiator Location = %q, want prefix %q", loc, want)
	}
}

// TestHostDispatchRoutesProxyAndApp locks the Host-dispatch boundary: a proxy
// Host reaches the proxy (which bounces unauthenticated relays back to the
// initiator), while a normal Host never reaches the proxy's reserved path.
func TestHostDispatchRoutesProxyAndApp(t *testing.T) {
	srv, c := proxyTestServer(t)

	// Proxy Host, no proxy session → proxy.Handler relays → bounce to initiator.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/protected", nil)
	req.Host = "idrac-1.pi.home.kilar.net"
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound ||
		resp.Header.Get("Location") != "https://lab.pi.home.kilar.net/server/1/kvm" {
		t.Fatalf("proxy-host dispatch: status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Normal (non-proxy) Host hitting the proxy's reserved path → app mux 404;
	// the proxy is never reached.
	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/__labmgr/auth?token=x", nil)
	resp2, err := c.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("normal-host /__labmgr/auth: status=%d, want 404", resp2.StatusCode)
	}
}

// ---- Console button routing ----------------------------------------------

// With the proxy enabled, an iDRAC row's primary Console button must link
// straight to the auto-login proxy. It previously always rendered the
// browser-side token flow, which for iDRAC can only ever reach the copy/paste
// page — so "Console" behaved differently on Dell than on Supermicro.
func TestConsoleButtonUsesProxyForIDRAC(t *testing.T) {
	srv, c := proxyTestServer(t)
	authenticateAndSeed(t, srv.URL, c) // seeds iDRAC id 1 with root/calvin

	_, body := get(t, c, srv.URL+"/")
	if !strings.Contains(body, `href="/server/1/kvm"`) {
		t.Fatal("iDRAC row should link Console at /server/1/kvm")
	}
	if strings.Contains(body, `onclick="openConsole(`) {
		t.Fatal("iDRAC row should not fall back to the browser-side token flow")
	}
	// The credentials fallback must stay reachable: auto-login can fail.
	if !strings.Contains(body, `href="/server/1/console/manual"`) {
		t.Fatal("proxy rows need a manual-credentials fallback link")
	}
}

// The fallback must keep working wherever auto-login does not apply, or the
// docker-compose deploy and every non-iDRAC vendor lose their console button.
func TestConsoleButtonFallsBackWithoutProxy(t *testing.T) {
	srv, c, _ := testServer(t) // proxy disabled
	authenticateAndSeed(t, srv.URL, c)

	_, body := get(t, c, srv.URL+"/")
	if !strings.Contains(body, `onclick="openConsole(`) {
		t.Fatal("without the proxy the Console button must use the token flow")
	}
	if strings.Contains(body, `href="/server/1/kvm"`) {
		t.Fatal("no /kvm link should render when the proxy is disabled")
	}
}

// /console/manual is the only browser-navigable route to the credentials page
// (/server/{id}/console is JSON), so it must mint a token and land on HTML.
func TestConsoleManualRedirectsToLaunch(t *testing.T) {
	srv, c := proxyTestServer(t)
	authenticateAndSeed(t, srv.URL, c)

	resp, err := c.Get(srv.URL + "/server/1/console/manual")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "/server/1/console/launch?token=") {
		t.Fatalf("status=%d loc=%q", resp.StatusCode, loc)
	}
	launchResp, page := get(t, c, srv.URL+loc)
	if launchResp.StatusCode != http.StatusOK || !strings.Contains(page, "iDRAC") {
		t.Fatalf("launch page status=%d len=%d", launchResp.StatusCode, len(page))
	}
}

// A /kvm link that cannot auto-login must degrade to the credentials page.
// Returning 404 made the primary Console button look like it did nothing.
func TestKVMFallsBackToManualWhenUnavailable(t *testing.T) {
	srv, c, _ := testServer(t) // proxy disabled
	authenticateAndSeed(t, srv.URL, c)

	resp, err := c.Get(srv.URL + "/server/1/kvm")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound ||
		resp.Header.Get("Location") != "/server/1/console/manual" {
		t.Fatalf("status=%d loc=%q, want 302 to the credentials page",
			resp.StatusCode, resp.Header.Get("Location"))
	}
}
