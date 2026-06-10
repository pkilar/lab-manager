package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

// authenticateAndSeed logs the default admin in, clears the forced-password
// gate, and adds one server (id 1, Redfish creds) so /server/1/sol exists.
func authenticateAndSeed(t *testing.T, base string, c *http.Client) {
	t.Helper()
	_, body := get(t, c, base+"/login")
	resp := postForm(t, c, base+"/login", url.Values{
		"username": {"admin"}, "password": {"admin"}, "csrf_token": {csrfFrom(t, body)},
	})
	mustRedirect(t, resp, "/change-password")
	_, cp := get(t, c, base+"/change-password")
	resp = postForm(t, c, base+"/change-password", url.Values{
		"current_password": {"admin"}, "new_password": {"labpass123"},
		"confirm_password": {"labpass123"}, "csrf_token": {csrfFrom(t, cp)},
	})
	mustRedirect(t, resp, "/")
	_, nb := get(t, c, base+"/server/new")
	resp = postForm(t, c, base+"/server/new", url.Values{
		"name": {"r630"}, "ip_address": {"10.22.40.50"}, "bmc_type": {"idrac"},
		"redfish_user": {"root"}, "redfish_password": {"calvin"},
		"csrf_token": {csrfFrom(t, nb)},
	})
	mustRedirect(t, resp, "/")
}

func wsURL(base string, id int64) string {
	return strings.Replace(base, "http", "ws", 1) + "/server/" + strconv.FormatInt(id, 10) + "/sol"
}

func cookieHeader(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	var parts []string
	for _, ck := range c.Jar.Cookies(u) {
		parts = append(parts, ck.Name+"="+ck.Value)
	}
	return strings.Join(parts, "; ")
}

func TestSOLSocketRequiresLogin(t *testing.T) {
	srv, _, _ := testServer(t)
	// Same-origin header so we get past CheckOrigin and prove auth is what blocks.
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL(srv.URL, 1), http.Header{"Origin": {srv.URL}})
	if err == nil {
		_ = conn.Close()
		t.Fatal("unauthenticated SOL upgrade should fail")
	}
	if resp == nil || resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatalf("expected a non-101 response for unauthenticated upgrade, got %v", resp)
	}
}

func TestSOLSocketRejectsForeignOrigin(t *testing.T) {
	srv, c, _ := testServer(t)
	authenticateAndSeed(t, srv.URL, c)
	h := http.Header{
		"Cookie": {cookieHeader(t, c, srv.URL)},
		"Origin": {"https://evil.example.com"},
	}
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL(srv.URL, 1), h)
	if err == nil {
		_ = conn.Close()
		t.Fatal("foreign-Origin upgrade should be rejected")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 on foreign Origin, got %v", resp)
	}
}
