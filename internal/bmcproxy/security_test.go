package bmcproxy

import (
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pkilar/lab-manager/internal/model"
)

const testProxyHost = "idrac-1.pi.home.kilar.net"

func TestSetCookieDomainStrippedAndReservedNamesDropped(t *testing.T) {
	m := NewManager(fakeLookup{}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	resp := &http.Response{Header: http.Header{}}
	for _, l := range []string{
		`plant=a"b; Domain=.pi.home.kilar.net; Path=/`,    // unparseable: Domain must go
		`plant2=a"b; path=/; DOMAIN = .kilar.net; Secure`, // case and spacing
		`session=a"b; Domain=.pi.home.kilar.net; Path=/`,  // the lead's example: app cookie name
		`session=ok; Path=/`,                              // parseable, reserved
		`__Host-session=x; Path=/`,
		`bmcproxy=x; Path=/`,
		`__Host-bmcproxy=x; Path=/`,
		`good=1; Domain=.kilar.net; Path=/`, // parseable: Domain already dropped
	} {
		resp.Header.Add("Set-Cookie", l)
	}
	m.rewriteSetCookies(resp, "sid", idracVendor)
	got := resp.Header.Values("Set-Cookie")
	if len(got) != 3 {
		t.Fatalf("got %q, want plant, plant2 and good only", got)
	}
	for _, l := range got {
		if strings.Contains(strings.ToLower(l), "domain") {
			t.Errorf("Domain survived: %q", l)
		}
	}
	if !strings.HasPrefix(got[0], "plant=") || !strings.HasPrefix(got[1], "plant2=") || !strings.Contains(got[1], "Secure") {
		t.Errorf("UI cookies mangled: %q", got)
	}
}

func TestRelayStripsCredentialHeadersAndAppCookies(t *testing.T) {
	front, _, sid := relayServer(t)
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/hdrs", nil)
	req.AddCookie(&http.Cookie{Name: proxyCookieName, Value: sid})
	req.AddCookie(&http.Cookie{Name: "session", Value: "APP"})
	req.AddCookie(&http.Cookie{Name: "__Host-session", Value: "APP"})
	req.AddCookie(&http.Cookie{Name: "__Host-bmcproxy", Value: "X"})
	req.AddCookie(&http.Cookie{Name: "ui", Value: "keep"})
	req.Header.Set("Authorization", "Basic abc")
	req.Header.Set("Proxy-Authorization", "Basic abc")
	req.Header.Set("X-Kvmd-User", "admin")
	req.Header.Set("X-KVMD-Passwd", "pw")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	got := readAll(t, resp)
	want := "auth=|pauth=|kvmd=|kvmd2=|cookie=ui=keep; -http-session-=" + idracSessionValue
	if got != want {
		t.Fatalf("upstream saw %q, want %q", got, want)
	}
}

func TestRewriteLocationOffHostAndRefresh(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Location", "https://evil.example/steal?x=1")
	resp.Header.Set("Content-Location", "//evil.example")
	resp.Header.Set("Refresh", "0; url=https://evil.example/r")
	rewriteLocation(resp, "10.0.0.5", testProxyHost, "https")
	for h, want := range map[string]string{
		"Location":         "https://" + testProxyHost + "/steal?x=1",
		"Content-Location": "https://" + testProxyHost + "/",
		"Refresh":          "0; url=https://" + testProxyHost + "/r",
	} {
		if got := resp.Header.Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
}

// Proxy hosts skip the app's securityHeaders, so every response, relayed or
// generated, carries frame-ancestors; a BMC's own CSP is kept alongside it.
func TestProxyHostResponsesCarryFrameAncestors(t *testing.T) {
	_, m, sid := relayServer(t)
	front := proxyFront(t, m)
	do := func(host, path string, cookie *http.Cookie) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, front.URL+path, nil)
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
	has := func(resp *http.Response) bool {
		return slices.Contains(resp.Header.Values("Content-Security-Policy"), "frame-ancestors 'self'")
	}
	relayed := do(testProxyHost, "/hostile", &http.Cookie{Name: hostProxyCookieName, Value: sid})
	if !has(relayed) {
		t.Errorf("relayed: CSP = %q", relayed.Header.Values("Content-Security-Policy"))
	}
	if csp := relayed.Header.Values("Content-Security-Policy"); len(csp) != 2 || !strings.Contains(strings.Join(csp, "|"), "default-src 'self'") {
		t.Errorf("BMC CSP must be kept alongside ours, got %q", csp)
	}
	if r := do(testProxyHost, "/protected", nil); r.StatusCode != http.StatusFound || !has(r) {
		t.Errorf("bounce: status=%d has=%v", r.StatusCode, has(r))
	}
	if r := do("unknown.example", "/", nil); r.StatusCode != http.StatusNotFound || !has(r) {
		t.Errorf("404: status=%d has=%v", r.StatusCode, has(r))
	}
}

func TestRelayFetchMetadataPolicy(t *testing.T) {
	front, _, sid := relayServer(t)
	cases := []struct {
		name                           string
		site, mode, dest, origin, host string
		refused                        bool
	}{
		{"no headers", "", "", "", "", testProxyHost, false},
		{"same-origin subresource", "same-origin", "no-cors", "image", "", testProxyHost, false},
		{"typed URL", "none", "navigate", "document", "", testProxyHost, false},
		{"cross-site navigation", "cross-site", "navigate", "document", "", testProxyHost, true},
		{"sibling img", "same-site", "no-cors", "image", "", testProxyHost, true},
		{"sibling fetch with its own origin", "same-site", "cors", "empty", "https://evil.pi.home.kilar.net", testProxyHost, true},
		{"app 302 chain navigation", "same-site", "navigate", "document", "", testProxyHost, false},
		{"sibling iframe", "same-site", "navigate", "iframe", "", testProxyHost, true},
		{"console websocket :443 to :5900", "same-site", "websocket", "empty", "https://" + testProxyHost, testProxyHost + ":5900", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, front.URL+"/protected", nil)
			req.Host = c.host
			req.AddCookie(&http.Cookie{Name: proxyCookieName, Value: sid})
			for k, v := range map[string]string{"Sec-Fetch-Site": c.site, "Sec-Fetch-Mode": c.mode, "Sec-Fetch-Dest": c.dest, "Origin": c.origin} {
				if v != "" {
					req.Header.Set(k, v)
				}
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if got := resp.StatusCode == http.StatusForbidden; got != c.refused {
				t.Errorf("status=%d, refused=%v want %v", resp.StatusCode, got, c.refused)
			}
		})
	}
}

// The handshake path keeps working for a same-site navigation (the app 302s the
// browser there) and is not subject to the Fetch Metadata policy.
func TestHandshakeIgnoresFetchMetadata(t *testing.T) {
	idrac := newFakeIDRAC(t)
	m := NewManager(fakeLookup{1: {ID: 1, BMCType: model.BMCIDRAC, IPAddress: hostport(idrac), RedfishUser: "root", RedfishPassword: "calvin"}}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	front := proxyFront(t, m)
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/__labmgr/auth?token="+m.MintToken(1), nil)
	req.Host = testProxyHost
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d, want 302", resp.StatusCode)
	}
}

func TestProxyCookieNameFollowsScheme(t *testing.T) {
	idrac := newFakeIDRAC(t)
	m := NewManager(fakeLookup{1: {ID: 1, BMCType: model.BMCIDRAC, IPAddress: hostport(idrac), RedfishUser: "root", RedfishPassword: "calvin"}}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	handshake := func(h http.Handler) *http.Cookie {
		srv := httptest.NewServer(h)
		defer srv.Close()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/__labmgr/auth?token="+m.MintToken(1), nil)
		req.Host = testProxyHost
		resp, err := noRedirect().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		cs := resp.Cookies()
		if len(cs) != 1 {
			t.Fatalf("cookies = %v", cs)
		}
		return cs[0]
	}
	if plain := handshake(http.HandlerFunc(m.Handler)); plain.Name != "bmcproxy" || plain.Secure {
		t.Errorf("http cookie = %+v", plain)
	}

	https := handshake(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-Forwarded-Proto", "https")
		m.Handler(w, r)
	}))
	if https.Name != "__Host-bmcproxy" || !https.Secure || https.Path != "/" || https.Domain != "" {
		t.Errorf("https cookie = %+v", https)
	}
	// Relay reads the matching name only: a plain "bmcproxy" planted by a
	// sibling is ignored over HTTPS.
	front := proxyFront(t, m)
	get := func(name string) int {
		req, _ := http.NewRequest(http.MethodGet, front.URL+"/protected", nil)
		req.Host = testProxyHost
		req.AddCookie(&http.Cookie{Name: name, Value: https.Value})
		resp, err := noRedirect().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if got := get("__Host-bmcproxy"); got != http.StatusOK {
		t.Errorf("__Host- cookie over https: %d", got)
	}
	if got := get("bmcproxy"); got != http.StatusFound {
		t.Errorf("plain cookie over https: %d, want bounce", got)
	}
}

func TestHandshakeTokenIsSingleUse(t *testing.T) {
	idrac := newFakeIDRAC(t)
	m := NewManager(fakeLookup{1: {ID: 1, BMCType: model.BMCIDRAC, IPAddress: hostport(idrac), RedfishUser: "root", RedfishPassword: "calvin"}}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	front := proxyFront(t, m)
	tok := m.MintToken(1)
	loc := func() string {
		req, _ := http.NewRequest(http.MethodGet, front.URL+"/__labmgr/auth?token="+tok, nil)
		req.Host = testProxyHost
		resp, err := noRedirect().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.Header.Get("Location")
	}
	if first := loc(); strings.Contains(first, "/server/1/kvm") {
		t.Fatalf("first use bounced: %q", first)
	}
	if second := loc(); !strings.Contains(second, "/server/1/kvm") {
		t.Fatalf("replayed token accepted, Location = %q", second)
	}
	if a, b := m.MintToken(1), m.MintToken(1); a == b {
		t.Error("two tokens minted in one second must differ")
	}
}

func TestUsedTokensArePruned(t *testing.T) {
	var u usedTokens
	u.seen = map[string]time.Time{"old": time.Now().Add(-time.Second)}
	if !u.consume("new") {
		t.Fatal("fresh token refused")
	}
	if _, ok := u.seen["old"]; ok {
		t.Error("expired entry not pruned")
	}
}

func TestTokenIsPurposeBound(t *testing.T) {
	secret := []byte("k")
	// What the signature would be without the purpose prefix (i.e. a console
	// token or any other HMAC under the same key).
	ts := time.Now().Unix()
	legacy := base64URL(t, ts, "n", hmacHex(secret, "7:"+itoa(ts)+":n"))
	if verifyToken(secret, legacy, 7) {
		t.Fatal("token without the purpose prefix accepted")
	}
}

func TestTransportHasDialAndHandshakeTimeouts(t *testing.T) {
	if proxyTransport.DialContext == nil || proxyTransport.TLSHandshakeTimeout != 10*time.Second {
		t.Fatalf("dial=%v tlsHandshake=%v", proxyTransport.DialContext != nil, proxyTransport.TLSHandshakeTimeout)
	}
	_ = tls.VersionTLS12
}

func TestUpstreamHostIPv6ConsolePort(t *testing.T) {
	if got := upstreamHost(idracVendor, "[2001:db8::1]", testProxyHost+":5900"); got != "[2001:db8::1]:5900" {
		t.Errorf("got %q", got)
	}
	if got := upstreamHost(idracVendor, "10.0.0.5", testProxyHost+":5900"); got != "10.0.0.5:5900" {
		t.Errorf("got %q", got)
	}
	if got := upstreamHost(idracVendor, "[2001:db8::1]", testProxyHost); got != "[2001:db8::1]" {
		t.Errorf("got %q", got)
	}
}

func TestNonIPAddressRefused(t *testing.T) {
	useRealBMCHost(t)
	srv := &model.Server{ID: 1, BMCType: model.BMCIDRAC, IPAddress: "evil.example/x", RedfishUser: "root", RedfishPassword: "pw"}
	m := NewManager(fakeLookup{1: srv}, []byte("s"), "pi.home.kilar.net")
	t.Cleanup(m.Close)
	front := proxyFront(t, m)

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/__labmgr/auth?token="+m.MintToken(1), nil)
	req.Host = testProxyHost
	resp, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("handshake status=%d, want 404", resp.StatusCode)
	}

	sid, _, _ := m.sessions.create(idracVendor, 1, "evil.example/x", "-http-session-=x")
	req, _ = http.NewRequest(http.MethodGet, front.URL+"/protected", nil)
	req.Host = testProxyHost
	req.AddCookie(&http.Cookie{Name: hostProxyCookieName, Value: sid})
	resp, err = noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("relay status=%d, want 404", resp.StatusCode)
	}
}

func TestUnreadableCredentialsNeverReachBMC(t *testing.T) {
	var hits int
	bmc := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	t.Cleanup(bmc.Close)
	for _, tc := range []struct {
		bmcType, host string
		id            int64
	}{{model.BMCIDRAC, testProxyHost, 1}, {model.BMCPiKVM, "pikvm-1.pi.home.kilar.net", 1}} {
		srv := &model.Server{ID: 1, BMCType: tc.bmcType, IPAddress: strings.TrimPrefix(bmc.URL, "https://"), RedfishUser: "root", CredentialsUnreadable: true}
		m := NewManager(fakeLookup{1: srv}, []byte("s"), "pi.home.kilar.net")
		front := proxyFront(t, m)
		req, _ := http.NewRequest(http.MethodGet, front.URL+"/__labmgr/auth?token="+m.MintToken(1), nil)
		req.Host = tc.host
		resp, err := noRedirect().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body := readAll(t, resp)
		m.Close()
		if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "can&#39;t be decrypted") {
			t.Errorf("%s: status=%d body=%q", tc.bmcType, resp.StatusCode, body)
		}
	}
	if hits != 0 {
		t.Errorf("BMC was contacted %d times", hits)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func base64URL(t *testing.T, ts int64, nonce, sig string) string {
	t.Helper()
	return base64.URLEncoding.EncodeToString([]byte(itoa(ts) + ":" + nonce + ":" + sig))
}
