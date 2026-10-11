package web

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkilar/lab-manager/internal/model"
)

// loginAs logs the default admin in on client c (changing the password on first
// use is the caller's job) and returns the response of the login POST.
func loginAs(t *testing.T, c *http.Client, base, user, pass string) *http.Response {
	t.Helper()
	_, body := get(t, c, base+"/login")
	return postForm(t, c, base+"/login", url.Values{
		"username": {user}, "password": {pass}, "csrf_token": {csrfFrom(t, body)},
	})
}

// readyUser clears the forced password change so the index is reachable.
func readyUser(t *testing.T, srv string, c *http.Client) {
	t.Helper()
	mustRedirect(t, loginAs(t, c, srv, "admin", "admin"), "/change-password")
	_, cp := get(t, c, srv+"/change-password")
	mustRedirect(t, postForm(t, c, srv+"/change-password", url.Values{
		"current_password": {"admin"}, "new_password": {"labpass123"},
		"confirm_password": {"labpass123"}, "csrf_token": {csrfFrom(t, cp)},
	}), "/")
}

func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestIndexPowerFormsUseBrowserRoutes(t *testing.T) {
	srv, c, st := testServer(t)
	readyUser(t, srv.URL, c)
	if err := st.CreateServer(&model.Server{Name: "box", IPAddress: "10.0.0.9", BMCType: "generic"}); err != nil {
		t.Fatalf("AddServer: %v", err)
	}
	_, body := get(t, c, srv.URL+"/")
	if strings.Contains(body, "/api/") {
		t.Fatal("index still posts to the JSON API")
	}
	for _, a := range []string{"start", "stop", "restart"} {
		if !strings.Contains(body, `action="/server/1/power/`+a+`"`) {
			t.Errorf("missing form for %s", a)
		}
	}
}

func TestPowerActionRedirects(t *testing.T) {
	srv, c, st := testServer(t)
	readyUser(t, srv.URL, c)
	if err := st.CreateServer(&model.Server{Name: "box", IPAddress: "10.0.0.9", BMCType: "generic"}); err != nil {
		t.Fatalf("AddServer: %v", err)
	}
	for _, action := range []string{"stop", "bogus"} {
		_, body := get(t, c, srv.URL+"/")
		resp := postForm(t, c, srv.URL+"/server/1/power/"+action, url.Values{"csrf_token": {csrfFrom(t, body)}})
		mustRedirect(t, resp, "/")
		_ = readBody(t, resp)
	}
	// Invalid action flashes an error (not JSON); the stop result is flashed too.
	_, body := get(t, c, srv.URL+"/")
	if !strings.Contains(body, "Invalid action") {
		t.Error("invalid action not flashed")
	}
}

func TestActionPastTense(t *testing.T) {
	for action, want := range map[string]string{"start": "started", "stop": "stopped", "restart": "restarted"} {
		if _, ok := actionToCommand(action); !ok {
			t.Fatalf("actionToCommand rejects %q", action)
		}
		if got := actionPastTense[action]; got != want {
			t.Errorf("%s -> %q, want %q", action, got, want)
		}
	}
}

// ---- sessions ------------------------------------------------------------

func TestSessionExpires(t *testing.T) {
	srv, c, _, app := testServerApp(t)
	readyUser(t, srv.URL, c)
	if resp, _ := get(t, c, srv.URL+"/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("fresh session: status=%d", resp.StatusCode)
	}
	base := app.now()
	app.now = func() time.Time { return base.Add(sessionMaxAge + time.Minute) }
	resp, _ := get(t, c, srv.URL+"/")
	mustRedirect(t, resp, "/login")
}

func TestPasswordChangeRevokesOtherSessions(t *testing.T) {
	srv, c1, _, _ := testServerApp(t)
	readyUser(t, srv.URL, c1)

	c2 := newClient()
	mustRedirect(t, loginAs(t, c2, srv.URL, "admin", "labpass123"), "/")
	if resp, _ := get(t, c2, srv.URL+"/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("second session: status=%d", resp.StatusCode)
	}

	_, cp := get(t, c1, srv.URL+"/change-password")
	mustRedirect(t, postForm(t, c1, srv.URL+"/change-password", url.Values{
		"current_password": {"labpass123"}, "new_password": {"another-pass-1"},
		"confirm_password": {"another-pass-1"}, "csrf_token": {csrfFrom(t, cp)},
	}), "/")

	if resp, _ := get(t, c1, srv.URL+"/"); resp.StatusCode != http.StatusOK {
		t.Fatalf("changing session was logged out: status=%d", resp.StatusCode)
	}
	resp, _ := get(t, c2, srv.URL+"/")
	mustRedirect(t, resp, "/login")
}

func TestCookieWithoutIATRejected(t *testing.T) {
	srv, c, _, app := testServerApp(t)
	readyUser(t, srv.URL, c)
	payload, _ := json.Marshal(map[string]any{"uid": 1, "csrf": "abc"})
	old := newClient()
	u, _ := url.Parse(srv.URL)
	old.Jar.SetCookies(u, []*http.Cookie{{Name: sessionCookie, Value: app.signSession(payload), Path: "/"}})
	resp, _ := get(t, old, srv.URL+"/")
	mustRedirect(t, resp, "/login")
}

// ---- login throttling ----------------------------------------------------

func TestLoginLimiter(t *testing.T) {
	l := newLoginLimiter()
	t0 := time.Unix(1_000_000, 0)
	for i := range 5 {
		if ok, _ := l.allow("u", t0); !ok {
			t.Fatalf("attempt %d rejected", i+1)
		}
		l.fail("u", t0)
	}
	ok, retry := l.allow("u", t0)
	if ok || retry != time.Second {
		t.Fatalf("6th attempt: ok=%v retry=%v, want rejected with 1s", ok, retry)
	}
	t1 := t0.Add(time.Second)
	if ok, _ := l.allow("u", t1); !ok {
		t.Fatal("attempt after cooldown rejected")
	}
	l.fail("u", t1) // 6 fails -> 2s
	if ok, retry := l.allow("u", t1); ok || retry != 2*time.Second {
		t.Fatalf("after 6 fails: ok=%v retry=%v, want 2s", ok, retry)
	}
}

func TestLoginCooldownCaps(t *testing.T) {
	want := map[int]time.Duration{4: 0, 5: time.Second, 6: 2 * time.Second, 7: 4 * time.Second, 13: 256 * time.Second, 14: 5 * time.Minute, 100: 5 * time.Minute}
	for fails, d := range want {
		if got := loginCooldown(fails); got != d {
			t.Errorf("loginCooldown(%d)=%v, want %v", fails, got, d)
		}
	}
}

func TestLoginLimiterSuccessAndIdleReset(t *testing.T) {
	l := newLoginLimiter()
	t0 := time.Unix(1_000_000, 0)
	for range 5 {
		l.fail("u", t0)
	}
	l.succeed("u")
	if ok, _ := l.allow("u", t0); !ok {
		t.Fatal("success did not reset")
	}
	for range 5 {
		l.fail("v", t0)
	}
	if ok, _ := l.allow("v", t0); ok {
		t.Fatal("v should be throttled")
	}
	if ok, _ := l.allow("v", t0.Add(loginIdleReset+time.Second)); !ok {
		t.Fatal("idle entry did not reset")
	}
}

func TestLoginLimiterReservation(t *testing.T) {
	l := newLoginLimiter()
	t0 := time.Unix(1_000_000, 0)
	for range 5 {
		l.fail("u", t0)
	}
	t1 := t0.Add(time.Second)
	var granted atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if ok, _ := l.allow("u", t1); ok {
				granted.Add(1)
			}
		})
	}
	wg.Wait()
	if granted.Load() != 1 {
		t.Fatalf("granted=%d, want exactly 1", granted.Load())
	}
}

func TestLoginLimiterBounded(t *testing.T) {
	l := newLoginLimiter()
	t0 := time.Unix(1_000_000, 0)
	for i := range loginMaxEntries + 5 {
		l.fail(string(rune('a'))+time.Duration(i).String(), t0)
	}
	if n := len(l.entries); n > loginMaxEntries {
		t.Fatalf("entries=%d exceeds cap", n)
	}
}

func TestLoginThrottleHTTP(t *testing.T) {
	srv, c, _, app := testServerApp(t)
	fixed := time.Unix(2_000_000_000, 0)
	app.now = func() time.Time { return fixed }

	// Unknown and known usernames throttle identically.
	for _, user := range []string{"nobody", "admin"} {
		for range 5 {
			resp := loginAs(t, c, srv.URL, user, "wrong")
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: failed attempt status=%d", user, resp.StatusCode)
			}
			_ = readBody(t, resp)
		}
	}
	// Even the correct password is refused while throttled, and not logged in.
	resp := loginAs(t, c, srv.URL, " ADMIN ", "admin")
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("throttled status=%d, want 429", resp.StatusCode)
	}
	if b := readBody(t, resp); !strings.Contains(b, "Too many failed login attempts. Try again in 1 seconds.") {
		t.Fatal("missing throttle message")
	}
	resp, _ = get(t, c, srv.URL+"/")
	mustRedirect(t, resp, "/login")
	if resp := loginAs(t, c, srv.URL, "nobody", "x"); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("unknown user status=%d, want 429", resp.StatusCode)
	}
}
