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

	resp, err := c.Get(srv.URL + "/server/1/kvm")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://idrac-1.pi.home.kilar.net/__labmgr/auth?token=") {
		t.Fatalf("KVM initiator Location = %q", loc)
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
