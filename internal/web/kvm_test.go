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
