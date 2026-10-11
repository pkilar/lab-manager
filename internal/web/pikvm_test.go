package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// pikvmIP is a TEST-NET-1 address: rendering the index never dials it, and if
// anything ever did, it could not reach a real lab device.
const pikvmIP = "192.0.2.3"

// seedPiKVM adds a PiKVM (id 2) to a store already seeded by
// authenticateAndSeed, returning its id.
func seedPiKVM(t *testing.T, base string, c *http.Client) int64 {
	t.Helper()
	_, nb := get(t, c, base+"/server/new")
	mustRedirect(t, postForm(t, c, base+"/server/new", url.Values{
		"name": {"pikvm"}, "ip_address": {pikvmIP}, "bmc_type": {"pikvm"},
		"redfish_user": {"admin"}, "redfish_password": {"PIKVMSECRET"},
		"csrf_token": {csrfFrom(t, nb)},
	}), "/")
	return 2
}

// With the proxy on, both PiKVM buttons go through the auto-login initiator,
// and the IPMI serial button is replaced by the PiKVM's own web terminal: a
// PiKVM serves no IPMI SOL, so that button could only ever fail.
func TestPiKVMRowUsesProxyForConsoleAndTerminal(t *testing.T) {
	srv, c := proxyTestServer(t)
	authenticateAndSeed(t, srv.URL, c) // iDRAC id 1
	seedPiKVM(t, srv.URL, c)

	_, body := get(t, c, srv.URL+"/")
	for _, want := range []string{
		`href="/server/2/kvm"`,
		`href="/server/2/kvm?to=terminal"`,
		`Opens the PiKVM web terminal already logged in`,
		`href="/server/2/console/manual"`, // credentials fallback stays
		`PiKVM`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("index missing %q", want)
		}
	}
	if strings.Contains(body, `href="/server/2/sol/launch"`) {
		t.Error("a PiKVM row must not offer the IPMI serial console")
	}
	if !strings.Contains(body, `href="/server/1/sol/launch"`) {
		t.Error("the iDRAC row lost its serial console button")
	}
	if strings.Contains(body, "PIKVMSECRET") {
		t.Error("index leaked the PiKVM password")
	}
}

// Without the proxy (the docker-compose deploy) there is no way to log a
// browser into a PiKVM, so both buttons open the PiKVM's own pages directly.
func TestPiKVMRowLinksDirectlyWithoutProxy(t *testing.T) {
	srv, c, _ := testServer(t) // proxy disabled
	authenticateAndSeed(t, srv.URL, c)
	seedPiKVM(t, srv.URL, c)

	_, body := get(t, c, srv.URL+"/")
	for _, want := range []string{
		`href="https://` + pikvmIP + `/kvm/"`,
		`href="https://` + pikvmIP + `/extras/webterm/ttyd/"`,
		`Opens the PiKVM web terminal (use 🔑 for credentials)`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("index missing %q", want)
		}
	}
	if strings.Contains(body, `href="/server/2/kvm`) {
		t.Error("no /kvm link should render when the proxy is disabled")
	}
	if strings.Contains(body, `href="/server/2/sol/launch"`) {
		t.Error("a PiKVM row must not offer the IPMI serial console")
	}
}

// The initiator mints the handshake on the pikvm-<id> host, and passes only the
// known terminal target through: anything else lands on the KVM.
func TestKVMInitiatorTargetsPiKVM(t *testing.T) {
	srv, c := proxyTestServer(t)
	authenticateAndSeed(t, srv.URL, c)
	seedPiKVM(t, srv.URL, c)

	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	prefix := "http://pikvm-2.pi.home.kilar.net:" + port + "/__labmgr/auth?token="
	for _, tc := range []struct {
		query, wantSuffix string
		wantTarget        bool
	}{
		{"", "", false},
		{"?to=terminal", "&to=terminal", true},
		{"?to=%2F%2Fevil.example%2F", "", false},
	} {
		resp, err := c.Get(srv.URL + "/server/2/kvm" + tc.query)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		loc := resp.Header.Get("Location")
		if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, prefix) {
			t.Fatalf("query %q: status=%d loc=%q, want 302 to %s…", tc.query, resp.StatusCode, loc, prefix)
		}
		if got := strings.Contains(loc, "&to="); got != tc.wantTarget || !strings.HasSuffix(loc, tc.wantSuffix) {
			t.Errorf("query %q: loc=%q, want target=%v", tc.query, loc, tc.wantTarget)
		}
	}
}

// The edit form must round-trip the vendor, or saving a PiKVM row silently
// turned it back into Generic (the first <option>).
func TestPiKVMEditFormKeepsType(t *testing.T) {
	srv, c, _ := testServer(t)
	authenticateAndSeed(t, srv.URL, c)
	seedPiKVM(t, srv.URL, c)

	_, body := get(t, c, srv.URL+"/server/2/edit")
	if !strings.Contains(body, `<option value="pikvm" selected>PiKVM</option>`) {
		t.Error("edit form does not preselect PiKVM")
	}
}
