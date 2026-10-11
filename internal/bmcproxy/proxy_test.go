package bmcproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pkilar/lab-manager/internal/model"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m := NewManager(fakeLookup{}, []byte("secret"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	return m
}

func TestHostServerID(t *testing.T) {
	m := newTestManager(t)
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
	m := newTestManager(t)
	if !m.Enabled() {
		t.Fatal("configured domain should be enabled")
	}
	tok := m.MintToken(3)

	// Production: HTTPS, no port — must be byte-identical to the old behaviour.
	if got := m.AuthURL("https", "lab.pi.home.kilar.net", model.BMCIDRAC, 3, tok, ""); got != "https://idrac-3.pi.home.kilar.net/__labmgr/auth?token="+tok {
		t.Fatalf("AuthURL = %q", got)
	}
	httpsReq := httptest.NewRequest(http.MethodGet, "/", nil)
	httpsReq.Host = "idrac-3.pi.home.kilar.net"
	httpsReq.Header.Set("X-Forwarded-Proto", "https")
	if got := m.appBaseURL(httpsReq); got != "https://lab.pi.home.kilar.net" {
		t.Fatalf("appBaseURL = %q", got)
	}

	// Development: plain HTTP on a non-default port. The scheme and port must
	// carry through, or the handshake redirects off the dev server entirely.
	if got := m.AuthURL("http", "127.0.0.1:5000", model.BMCIDRAC, 3, tok, ""); got != "http://idrac-3.pi.home.kilar.net:5000/__labmgr/auth?token="+tok {
		t.Fatalf("dev AuthURL = %q", got)
	}
	devReq := httptest.NewRequest(http.MethodGet, "/", nil)
	devReq.Host = "idrac-3.pi.home.kilar.net:5000"
	if got := m.appBaseURL(devReq); got != "http://lab.pi.home.kilar.net:5000" {
		t.Fatalf("dev appBaseURL = %q", got)
	}
}

// The iDRAC's HTML5 virtual console lives on a separate TLS listener on 5900,
// and its SPA derives the URL from window.location.host — so the request
// reaches the proxy as idrac-<id>.<domain>:5900 and must be forwarded to the
// BMC's 5900. Every other inbound port belongs to the app's own listener
// (":5000" in development) and must NOT be forwarded to the BMC.
func TestUpstreamHostRoutesConsolePort(t *testing.T) {
	cases := []struct {
		name, ip, inbound, want string
	}{
		{"console port passes through", "10.22.40.136", "idrac-1.pi.home.kilar.net:5900", "10.22.40.136:5900"},
		{"https default stays bare", "10.22.40.136", "idrac-1.pi.home.kilar.net", "10.22.40.136"},
		{"dev app port is not forwarded", "10.22.40.136", "idrac-1.localhost:5000", "10.22.40.136"},
		{"ip carrying a port is replaced", "127.0.0.1:44321", "idrac-1.pi.home.kilar.net:5900", "127.0.0.1:5900"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := upstreamHost(idracVendor, tc.ip, tc.inbound); got != tc.want {
				t.Fatalf("upstreamHost(%q, %q) = %q, want %q", tc.ip, tc.inbound, got, tc.want)
			}
		})
	}
}
