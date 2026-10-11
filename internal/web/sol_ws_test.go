package web

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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

// TestSOLSocketUpgradeSucceeds guards the bug where the session middleware's
// ResponseWriter wrapper didn't implement http.Hijacker, so every SOL upgrade
// through the app chain failed with 500. A same-origin authenticated request
// must complete the WebSocket handshake (101).
func TestSOLSocketUpgradeSucceeds(t *testing.T) {
	// Without the stub the handler runs the real ipmitool against the seeded
	// 10.22.40.50 with root/calvin -- a live lab address.
	fakeIPMITool(t)
	srv, c, _ := testServer(t)
	authenticateAndSeed(t, srv.URL, c) // seeds an iDRAC server (id 1) with creds
	h := http.Header{
		"Cookie": {cookieHeader(t, c, srv.URL)},
		"Origin": {srv.URL}, // same origin
	}
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL(srv.URL, 1), h)
	if err != nil {
		t.Fatalf("SOL upgrade failed (session middleware must implement Hijack): %v (resp=%v)", err, resp)
	}
	defer func() { _ = conn.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status=%d, want 101", resp.StatusCode)
	}
}

// TestSOLSocketDropsSilentClient: a client that never reads (so never answers
// pings) must be disconnected once the read deadline lapses, which also
// releases ipmitool and the BMC payload.
func TestSOLSocketDropsSilentClient(t *testing.T) {
	fakeIPMITool(t)
	srv, c, _, _ := testServerApp(t, withSOLTiming(300*time.Millisecond, 100*time.Millisecond))
	authenticateAndSeed(t, srv.URL, c)
	h := http.Header{"Cookie": {cookieHeader(t, c, srv.URL)}, "Origin": {srv.URL}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL(srv.URL, 1), h)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Never call a read method: control frames go unanswered. Wait for the
	// server to give up, then drain; the stream must end in an error.
	time.Sleep(2 * time.Second)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				t.Fatalf("server never closed the silent connection: %v", err)
			}
			return
		}
	}
}

// TestSOLSocketKeepaliveSurvivesIdleClient: a client that is reading (gorilla
// answers pings automatically) stays connected well past solPongWait.
func TestSOLSocketKeepaliveSurvivesIdleClient(t *testing.T) {
	fakeIPMITool(t)
	srv, c, _, _ := testServerApp(t, withSOLTiming(400*time.Millisecond, 100*time.Millisecond))
	authenticateAndSeed(t, srv.URL, c)
	h := http.Header{"Cookie": {cookieHeader(t, c, srv.URL)}, "Origin": {srv.URL}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL(srv.URL, 1), h)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Reading processes pings (and sends pongs); expect only our own timeout.
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	for {
		_, _, err := conn.ReadMessage()
		if err == nil {
			continue // ipmitool output, if any
		}
		if ce, ok := err.(*websocket.CloseError); ok {
			t.Fatalf("server closed an answering client: %v", ce)
		}
		return // our own read deadline: still connected
	}
}

// withSOLTiming shrinks the SOL keepalive so a test can observe it quickly.
func withSOLTiming(pong, ping time.Duration) func(*App) {
	return func(a *App) {
		a.solTimings.pongWait, a.solTimings.pingPeriod = pong, ping
	}
}

// fakeIPMITool puts a stand-in ipmitool first on PATH so the handler never
// dials a real BMC: `activate` idles until stdin closes, `deactivate` is a no-op.
func fakeIPMITool(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\ncase \"$*\" in *activate*) ;; *) exit 0;; esac\ncase \"$*\" in *deactivate*) exit 0;; esac\ncat >/dev/null\n"
	if err := os.WriteFile(filepath.Join(dir, "ipmitool"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake ipmitool: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}
