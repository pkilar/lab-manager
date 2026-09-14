package web

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
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
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d loc=%q", resp.StatusCode, loc)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Location %q: %v", loc, err)
	}
	if u.Path != "/server/1/console/launch" || u.Query().Get("token") == "" {
		t.Fatalf("loc=%q, want a tokenised launch URL", loc)
	}
	// manual=1 tells the launch page to show credentials instead of driving an
	// auto-login — the whole point of this route.
	if u.Query().Get("manual") != "1" {
		t.Errorf("loc=%q should carry manual=1", loc)
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

// seedSupermicro adds a Supermicro server (id 2) to a store already seeded by
// authenticateAndSeed, returning its id.
func seedSupermicro(t *testing.T, base string, c *http.Client) int64 {
	t.Helper()
	_, nb := get(t, c, base+"/server/new")
	mustRedirect(t, postForm(t, c, base+"/server/new", url.Values{
		"name": {"smc-1"}, "ip_address": {"10.22.40.60"}, "bmc_type": {"supermicro"},
		"ipmi_user": {"ADMIN"}, "ipmi_password": {"SUPERSECRET"},
		"csrf_token": {csrfFrom(t, nb)},
	}), "/")
	return 2
}

// The Supermicro launch page logs in by submitting a form from the browser, so
// the password is necessarily in the document — but it must not be DISPLAYED.
// Showing it turned every console launch into a credential popup.
func TestSupermicroLaunchDoesNotDisplayCredentials(t *testing.T) {
	srv, c := proxyTestServer(t)
	authenticateAndSeed(t, srv.URL, c)
	id := seedSupermicro(t, srv.URL, c)

	page := supermicroLaunchPage(t, srv.URL, c, id, false)

	// The auto-login form still needs the password, so assert on the visible
	// credential UI rather than on the string itself.
	for _, marker := range []string{"credentials-box", "credential-value", "copy-btn", "Login Credentials"} {
		if strings.Contains(page, marker) {
			t.Errorf("auto-login page still renders credential UI (%q)", marker)
		}
	}
	// It must still be the auto-login page, not silently downgraded.
	if !strings.Contains(page, "attemptDirectLogin") {
		t.Error("auto-login page should still drive the browser-side login")
	}
	// And it must offer the way to the credentials.
	if !strings.Contains(page, "/server/2/console/manual") {
		t.Error("auto-login page should link to the credentials page")
	}
}

// The 🔑 route must reach a page that actually shows the credentials — for
// Supermicro that means the generic helper, not the auto-submitting page.
func TestSupermicroManualShowsCredentials(t *testing.T) {
	srv, c := proxyTestServer(t)
	authenticateAndSeed(t, srv.URL, c)
	id := seedSupermicro(t, srv.URL, c)

	page := supermicroLaunchPage(t, srv.URL, c, id, true)

	if strings.Contains(page, "attemptDirectLogin") {
		t.Error("manual page must not auto-login; that is what it exists to bypass")
	}
	for _, marker := range []string{"credentials-box", "ADMIN", "copyToClipboard"} {
		if !strings.Contains(page, marker) {
			t.Errorf("manual page should show credentials, missing %q", marker)
		}
	}
}

// supermicroLaunchPage fetches the launch page for id, either via the 🔑 route
// (manual) or via the tokenised console API the Console button uses.
func supermicroLaunchPage(t *testing.T, base string, c *http.Client, id int64, manual bool) string {
	t.Helper()
	sid := strconv.FormatInt(id, 10)
	if manual {
		resp, err := c.Get(base + "/server/" + sid + "/console/manual")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		loc := resp.Header.Get("Location")
		if resp.StatusCode != http.StatusFound || loc == "" {
			t.Fatalf("console/manual: status=%d loc=%q", resp.StatusCode, loc)
		}
		_, page := get(t, c, base+loc)
		return page
	}
	// The Console button path: /console is JSON and returns the launch URL.
	_, body := get(t, c, base+"/server/"+sid+"/console")
	var api struct {
		Success      bool   `json:"success"`
		AutoLoginURL string `json:"auto_login_url"`
	}
	if err := json.Unmarshal([]byte(body), &api); err != nil {
		t.Fatalf("decode console API: %v (body=%s)", err, body)
	}
	if !api.Success || api.AutoLoginURL == "" {
		t.Fatalf("console API gave no auto-login URL: %s", body)
	}
	u, err := url.Parse(api.AutoLoginURL)
	if err != nil {
		t.Fatal(err)
	}
	_, page := get(t, c, base+u.Path+"?"+u.RawQuery)
	return page
}

// The 🔑 button used to render only on proxy (iDRAC) rows. Now that no launch
// page displays credentials, every vendor with credentials needs it.
func TestKeyButtonRendersForEveryVendorWithCreds(t *testing.T) {
	srv, c := proxyTestServer(t)
	authenticateAndSeed(t, srv.URL, c) // iDRAC id 1
	seedSupermicro(t, srv.URL, c)      // Supermicro id 2

	_, body := get(t, c, srv.URL+"/")
	for _, id := range []string{"1", "2"} {
		if !strings.Contains(body, `href="/server/`+id+`/console/manual"`) {
			t.Errorf("server %s row is missing the 🔑 credentials link", id)
		}
	}
}

// For a vendor with no auto-login, the Console launch page was byte-for-byte the
// 🔑 page — so "Console" popped up a credential list instead of opening a
// console. Console must now link to the BMC's own UI, leaving credentials to 🔑.
func TestConsoleButtonSkipsCredentialPageWithoutAutoLogin(t *testing.T) {
	srv, c := proxyTestServer(t)
	authenticateAndSeed(t, srv.URL, c) // iDRAC id 1

	_, nb := get(t, c, srv.URL+"/server/new")
	mustRedirect(t, postForm(t, c, srv.URL+"/server/new", url.Values{
		"name": {"generic-box"}, "ip_address": {"10.99.0.9"}, "bmc_type": {"generic"},
		"ipmi_user": {"ADMIN"}, "ipmi_password": {"SECRET123"},
		"csrf_token": {csrfFrom(t, nb)},
	}), "/")

	_, body := get(t, c, srv.URL+"/")
	if !strings.Contains(body, `href="https://10.99.0.9/"`) {
		t.Error("Console on a no-auto-login row should link straight to the BMC UI")
	}
	// It must not fall back to the token flow, which lands on the credentials page.
	if strings.Contains(body, `onclick="openConsole( 2`) {
		t.Error("a no-auto-login row should not use the token flow for Console")
	}
	// The 🔑 button stays: that is where credentials belong.
	if !strings.Contains(body, `href="/server/2/console/manual"`) {
		t.Error("the credentials button must still render")
	}
	// The tooltip must not claim an auto-login it cannot perform.
	if strings.Contains(body, `title="Opens the BMC already logged in">Console</a>`) &&
		!strings.Contains(body, `href="/server/1/kvm"`) {
		t.Error("tooltip claims auto-login on a row that has none")
	}
}

// Supermicro genuinely auto-logs-in from the browser, so it must keep the
// tokenised flow rather than being downgraded to a plain BMC link.
func TestConsoleButtonKeepsTokenFlowForSupermicro(t *testing.T) {
	srv, c := proxyTestServer(t)
	authenticateAndSeed(t, srv.URL, c)
	seedSupermicro(t, srv.URL, c) // id 2, 10.22.40.60

	_, body := get(t, c, srv.URL+"/")
	if !strings.Contains(body, `onclick="openConsole( 2`) {
		t.Error("Supermicro must keep the token flow so its auto-login page runs")
	}
	if strings.Contains(body, `href="https://10.22.40.60/`) {
		t.Error("Supermicro must not be downgraded to a plain BMC link")
	}
}

// kvm.go guards on kvmTarget, not consoleTarget: now that consoleTarget returns
// a BMC URL for non-iDRAC vendors, reusing it there would have sent a generic
// server into the iDRAC proxy handshake instead of degrading to credentials.
func TestKVMStillDegradesForNonIDRAC(t *testing.T) {
	srv, c := proxyTestServer(t)
	authenticateAndSeed(t, srv.URL, c)

	// Must be a vendor whose consoleTarget is NON-empty, or the test cannot tell
	// the two guards apart: Supermicro returns "" from both. A generic row now
	// yields the BMC URL, so guarding on consoleTarget would wrongly proceed.
	_, nb := get(t, c, srv.URL+"/server/new")
	mustRedirect(t, postForm(t, c, srv.URL+"/server/new", url.Values{
		"name": {"generic-box"}, "ip_address": {"10.99.0.9"}, "bmc_type": {"generic"},
		"ipmi_user": {"ADMIN"}, "ipmi_password": {"SECRET123"},
		"csrf_token": {csrfFrom(t, nb)},
	}), "/")

	resp, err := c.Get(srv.URL + "/server/2/kvm")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound ||
		resp.Header.Get("Location") != "/server/2/console/manual" {
		t.Fatalf("/kvm on a non-iDRAC row: status=%d loc=%q, want 302 to /console/manual",
			resp.StatusCode, resp.Header.Get("Location"))
	}
}

// The Supermicro launch page is a relay. It must end as the console itself,
// leaving no spare window: browsers refuse window.close() on a page that did not
// script-open itself, so the earlier shape (helper becomes console, relay closes
// itself) left the relay on screen. Closing a window you opened is always
// permitted, so the helper is the throwaway now.
func TestSupermicroRelayBecomesTheConsole(t *testing.T) {
	srv, c := proxyTestServer(t)
	authenticateAndSeed(t, srv.URL, c)
	id := seedSupermicro(t, srv.URL, c)

	page := supermicroLaunchPage(t, srv.URL, c, id, false)

	if !strings.Contains(page, "helper.close()") {
		t.Error("the helper window must be closed once the cookie is set")
	}
	if !strings.Contains(page, "window.location.href = CONSOLE_URL") {
		t.Error("the relay must navigate itself to the console")
	}
	// Self-close is the primitive browsers refuse; it must not come back.
	if strings.Contains(page, "window.close()") {
		t.Error("window.close() on self is refused by browsers; do not rely on it")
	}
	// Order matters: close the helper, then navigate. Navigating first would
	// destroy the script before it can close anything.
	closeAt := strings.Index(page, "helper.close()")
	navAt := strings.Index(page, "window.location.href = CONSOLE_URL")
	if closeAt < 0 || navAt < 0 || closeAt > navAt {
		t.Errorf("helper.close() at %d must precede the navigation at %d", closeAt, navAt)
	}
	// The login POST must target the helper, not this page: posting to _self
	// would strand us on the BMC with no way to reach the console.
	if !strings.Contains(page, "form.target = 'supermicro_login'") {
		t.Error("the login form must post into the helper window")
	}
}

// The Console button must open a full tab, not a sized popup, because that tab
// becomes the console. A 600x400 KVM window is unusable.
func TestConsoleOpensFullTabNotSizedPopup(t *testing.T) {
	srv, c := proxyTestServer(t)
	authenticateAndSeed(t, srv.URL, c)
	seedSupermicro(t, srv.URL, c)

	_, body := get(t, c, srv.URL+"/")
	if strings.Contains(body, "width=600,height=400") {
		t.Error("Console must not open a sized popup; that window becomes the console")
	}
	if !strings.Contains(body, "window.open(data.auto_login_url, '_blank')") {
		t.Error("Console should open a plain new tab")
	}
}

// Console pages can carry BMC credentials; they must never be cached.
func TestConsolePagesAreNotCached(t *testing.T) {
	srv, c := proxyTestServer(t)
	authenticateAndSeed(t, srv.URL, c)

	resp, err := c.Get(srv.URL + "/server/1/console/manual")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	launch, err := c.Get(srv.URL + resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = launch.Body.Close()
	if cc := launch.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("credentials page Cache-Control = %q, want no-store", cc)
	}
}
