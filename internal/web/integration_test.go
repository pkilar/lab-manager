package web

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/pkilar/lab-manager/internal/secret"
	"github.com/pkilar/lab-manager/internal/store"
)

var csrfInputRE = regexp.MustCompile(`name="csrf_token" value="([a-f0-9]+)"`)

// testServer spins up the full app (real middleware chain) backed by a throwaway
// database, returning the server, a cookie-keeping non-redirecting client, and
// the store for direct inspection.
func testServer(t *testing.T) (*httptest.Server, *http.Client, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	keyB64, err := secret.LoadEncryptionKey(dir)
	if err != nil {
		t.Fatalf("LoadEncryptionKey: %v", err)
	}
	cipher, err := secret.NewFernet(keyB64)
	if err != nil {
		t.Fatalf("NewFernet: %v", err)
	}
	st, err := store.Open(filepath.Join(dir, "servers.db"), cipher)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.InitDefaultUser(); err != nil {
		t.Fatalf("InitDefaultUser: %v", err)
	}

	app, err := New(st, []byte("integration-secret"), false, "")
	if err != nil {
		t.Fatalf("web.New: %v", err)
	}
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return srv, client, st
}

func get(t *testing.T, c *http.Client, target string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	return resp, readBody(t, resp)
}

func postForm(t *testing.T, c *http.Client, target string, form url.Values) *http.Response {
	t.Helper()
	resp, err := c.PostForm(target, form)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
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

func csrfFrom(t *testing.T, body string) string {
	t.Helper()
	m := csrfInputRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no csrf token found in page")
	}
	return m[1]
}

func mustRedirect(t *testing.T, resp *http.Response, where string) {
	t.Helper()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != where {
		t.Fatalf("status=%d loc=%q, want 302 %q", resp.StatusCode, resp.Header.Get("Location"), where)
	}
}

// TestFullAuthFlow walks unauthenticated -> login -> forced password change ->
// authenticated CRUD through the real middleware chain.
func TestFullAuthFlow(t *testing.T) {
	srv, c, st := testServer(t)
	base := srv.URL

	// 1. Unauthenticated index redirects to /login.
	resp, _ := get(t, c, base+"/")
	mustRedirect(t, resp, "/login")

	// 2. Login page renders and seeds a CSRF token.
	resp, body := get(t, c, base+"/login")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "<title>Login") {
		t.Fatalf("GET /login: status=%d", resp.StatusCode)
	}
	csrf := csrfFrom(t, body)

	// 3. POST without a CSRF token is rejected with 400.
	if resp := postForm(t, c, base+"/login", url.Values{"username": {"admin"}, "password": {"admin"}}); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST /login without csrf: status=%d, want 400", resp.StatusCode)
	}

	// 4. Correct login redirects to /change-password (default account must change).
	resp = postForm(t, c, base+"/login", url.Values{"username": {"admin"}, "password": {"admin"}, "csrf_token": {csrf}})
	mustRedirect(t, resp, "/change-password")

	// 5. The gate redirects every other authed page until the password changes.
	resp, _ = get(t, c, base+"/")
	mustRedirect(t, resp, "/change-password")

	// 6. Change the password.
	_, cpBody := get(t, c, base+"/change-password")
	resp = postForm(t, c, base+"/change-password", url.Values{
		"current_password": {"admin"}, "new_password": {"labpass123"},
		"confirm_password": {"labpass123"}, "csrf_token": {csrfFrom(t, cpBody)},
	})
	mustRedirect(t, resp, "/")

	// 7. Index now renders for the authenticated user.
	resp, body = get(t, c, base+"/")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "No servers configured yet") {
		t.Fatalf("GET / authed: status=%d", resp.StatusCode)
	}

	// 8. Add a server and confirm it round-trips onto the index.
	_, newBody := get(t, c, base+"/server/new")
	resp = postForm(t, c, base+"/server/new", url.Values{
		"name": {"r630"}, "ip_address": {"10.22.40.50"}, "bmc_type": {"idrac"},
		"redfish_user": {"root"}, "redfish_password": {"calvin"},
		"notes": {"test box"}, "csrf_token": {csrfFrom(t, newBody)},
	})
	mustRedirect(t, resp, "/")
	if _, body = get(t, c, base+"/"); !strings.Contains(body, "<strong>r630</strong>") {
		t.Fatal("new server not visible on index")
	}

	// 9. The changed password persists in scrypt format.
	u, err := st.GetUserByUsername("admin")
	if err != nil {
		t.Fatalf("get admin: %v", err)
	}
	if !strings.HasPrefix(u.PasswordHash, "scrypt:32768:8:1$") || u.PasswordChangeRequired {
		t.Fatalf("admin hash=%q pcr=%v", u.PasswordHash, u.PasswordChangeRequired)
	}
	if !secret.CheckPasswordHash(u.PasswordHash, "labpass123") {
		t.Fatal("changed password does not verify")
	}
}

// TestInvalidLoginAndLogout covers the failure and logout branches.
func TestInvalidLoginAndLogout(t *testing.T) {
	srv, c, _ := testServer(t)
	base := srv.URL

	_, body := get(t, c, base+"/login")
	resp := postForm(t, c, base+"/login", url.Values{
		"username": {"admin"}, "password": {"wrong"}, "csrf_token": {csrfFrom(t, body)},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bad login: status=%d, want 200", resp.StatusCode)
	}
	if b := readBody(t, resp); !strings.Contains(b, "Invalid username or password") {
		t.Fatal("bad login missing error flash")
	}

	resp, _ = get(t, c, base+"/logout")
	mustRedirect(t, resp, "/login")
}

// TestSecurityHeaders confirms the hardening headers are present on responses.
func TestSecurityHeaders(t *testing.T) {
	srv, c, _ := testServer(t)
	resp, _ := get(t, c, srv.URL+"/login")
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
}

// TestEditCredentialRules verifies the edit-form credential semantics:
// empty username removes that protocol's credentials; a blank password keeps the
// stored one; a new password updates it.
func TestEditCredentialRules(t *testing.T) {
	srv, c, st := testServer(t)
	authenticateAndSeed(t, srv.URL, c) // server 1: iDRAC, redfish root/calvin, no IPMI

	if s, err := st.GetServer(1); err != nil {
		t.Fatal(err)
	} else if s.RedfishUser != "root" || s.RedfishPassword != "calvin" {
		t.Fatalf("seed creds: user=%q pw_set=%v", s.RedfishUser, s.RedfishPassword != "")
	}

	// Edit with EMPTY redfish_user -> clears redfish user + password; sets IPMI.
	_, eb := get(t, c, srv.URL+"/server/1/edit")
	mustRedirect(t, postForm(t, c, srv.URL+"/server/1/edit", url.Values{
		"name": {"r630"}, "ip_address": {"10.22.40.50"}, "bmc_type": {"idrac"},
		"redfish_user": {""}, "redfish_password": {""},
		"ipmi_user": {"root"}, "ipmi_password": {"secret"},
		"csrf_token": {csrfFrom(t, eb)},
	}), "/")

	s2, err := st.GetServer(1)
	if err != nil {
		t.Fatal(err)
	}
	if s2.RedfishUser != "" || s2.RedfishPassword != "" {
		t.Fatalf("empty redfish user should clear creds: user=%q pw_set=%v", s2.RedfishUser, s2.RedfishPassword != "")
	}
	if s2.IPMIUser != "root" || s2.IPMIPassword != "secret" {
		t.Fatalf("ipmi creds: user=%q pw=%q", s2.IPMIUser, s2.IPMIPassword)
	}

	// Edit again: set redfish user + password; leave IPMI password BLANK (keep).
	_, eb2 := get(t, c, srv.URL+"/server/1/edit")
	mustRedirect(t, postForm(t, c, srv.URL+"/server/1/edit", url.Values{
		"name": {"r630"}, "ip_address": {"10.22.40.50"}, "bmc_type": {"idrac"},
		"redfish_user": {"root"}, "redfish_password": {"calvin"},
		"ipmi_user": {"root"}, "ipmi_password": {""},
		"csrf_token": {csrfFrom(t, eb2)},
	}), "/")

	s3, err := st.GetServer(1)
	if err != nil {
		t.Fatal(err)
	}
	if s3.RedfishUser != "root" || s3.RedfishPassword != "calvin" {
		t.Fatalf("redfish should be set: user=%q pw_set=%v", s3.RedfishUser, s3.RedfishPassword != "")
	}
	if s3.IPMIUser != "root" || s3.IPMIPassword != "secret" {
		t.Fatalf("blank ipmi password should keep current: user=%q pw=%q", s3.IPMIUser, s3.IPMIPassword)
	}
}
