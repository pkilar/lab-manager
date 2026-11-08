package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkilar/lab-manager/internal/model"
)

// ---- scrypt gate ----------------------------------------------------------

func smallGate(a *App) { a.loginLimit.gate = newScryptGate(1, 20*time.Millisecond) }

func TestLoginBusyWhenScryptGateFull(t *testing.T) {
	srv, c, _, app := testServerApp(t, smallGate)
	app.loginLimit.gate.sem <- struct{}{} // all slots taken

	// Correct credentials: with a full gate nothing may be verified, so no login.
	resp := loginAs(t, c, srv.URL, "admin", "admin")
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("status=%d retry-after=%q, want 503 / 1", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	if body := readBody(t, resp); !strings.Contains(body, "busy") {
		t.Error("busy flash missing")
	}
	if n := len(app.loginLimit.entries); n != 0 {
		t.Errorf("busy attempt left %d limiter entries; it must count as neither fail nor success", n)
	}
	if r, _ := get(t, c, srv.URL+"/"); r.StatusCode != http.StatusFound || r.Header.Get("Location") != "/login" {
		t.Error("busy login still produced a session")
	}

	<-app.loginLimit.gate.sem
	mustRedirect(t, loginAs(t, c, srv.URL, "admin", "admin"), "/change-password")
}

func TestChangePasswordBusyWhenScryptGateFull(t *testing.T) {
	srv, c, _, app := testServerApp(t)
	mustRedirect(t, loginAs(t, c, srv.URL, "admin", "admin"), "/change-password")
	smallGate(app)
	app.loginLimit.gate.sem <- struct{}{}
	_, cp := get(t, c, srv.URL+"/change-password")
	resp := postForm(t, c, srv.URL+"/change-password", url.Values{
		"current_password": {"admin"}, "new_password": {"labpass123"},
		"confirm_password": {"labpass123"}, "csrf_token": {csrfFrom(t, cp)},
	})
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("status=%d, want 503 with Retry-After", resp.StatusCode)
	}
}

func TestScryptGateRespectsContext(t *testing.T) {
	g := newScryptGate(1, time.Minute)
	g.sem <- struct{}{}
	req := httptest.NewRequest("GET", "/", nil)
	ctx, cancel := contextWithCancel(req)
	cancel()
	start := time.Now()
	if _, ok := g.acquire(ctx); ok || time.Since(start) > time.Second {
		t.Fatal("acquire did not give up on a cancelled context")
	}
}

func TestScryptGateRefusesWhenQueueFull(t *testing.T) {
	g := newScryptGate(1, time.Minute)
	g.maxWaiters = 1
	g.sem <- struct{}{} // the only slot is busy

	queued := make(chan bool)
	go func() {
		_, ok := g.acquire(context.Background())
		queued <- ok
	}()
	for g.waiters.Load() != 1 {
		time.Sleep(time.Millisecond)
	}
	start := time.Now()
	if _, ok := g.acquire(context.Background()); ok || time.Since(start) > time.Second {
		t.Fatal("acquire waited although the queue was full")
	}
	<-g.sem // free the slot: the queued waiter gets it
	if !<-queued {
		t.Fatal("queued waiter did not get the freed slot")
	}
}

// ---- input caps -----------------------------------------------------------

func TestOversizedLoginInputRejected(t *testing.T) {
	srv, c, _, app := testServerApp(t)
	_, body := get(t, c, srv.URL+"/login")
	csrf := csrfFrom(t, body)
	for name, form := range map[string]url.Values{
		"username": {"username": {strings.Repeat("u", maxUsernameBytes+1)}, "password": {"x"}},
		"password": {"username": {"admin"}, "password": {strings.Repeat("p", maxPasswordBytes+1)}},
	} {
		form.Set("csrf_token", csrf)
		resp := postForm(t, c, srv.URL+"/login", form)
		b := readBody(t, resp)
		if resp.StatusCode != http.StatusOK || !strings.Contains(b, "Invalid username or password") {
			t.Errorf("%s: status=%d, want 200 with invalid message", name, resp.StatusCode)
		}
	}
	if _, ok := app.loginLimit.entries[strings.Repeat("u", maxUsernameBytes+1)]; ok {
		t.Error("oversized username became a limiter key")
	}
	if n := len(app.loginLimit.entries); n != 1 { // only "admin", from the long password
		t.Errorf("entries=%d, want 1", n)
	}
}

func TestChangePasswordLengthCaps(t *testing.T) {
	srv, c, _, _ := testServerApp(t)
	mustRedirect(t, loginAs(t, c, srv.URL, "admin", "admin"), "/change-password")
	long := strings.Repeat("p", maxPasswordBytes+1)
	for name, form := range map[string]url.Values{
		"new":     {"current_password": {"admin"}, "new_password": {long}, "confirm_password": {long}},
		"current": {"current_password": {long}, "new_password": {"labpass123"}, "confirm_password": {"labpass123"}},
	} {
		_, cp := get(t, c, srv.URL+"/change-password")
		form.Set("csrf_token", csrfFrom(t, cp))
		resp := postForm(t, c, srv.URL+"/change-password", form)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status=%d", name, resp.StatusCode)
		}
		if b := readBody(t, resp); strings.Contains(b, "Password changed") {
			t.Errorf("%s: oversized password accepted", name)
		}
	}
}

// ---- limiter --------------------------------------------------------------

func TestLoginLimiterCapsInFlightBurst(t *testing.T) {
	l := newLoginLimiter()
	t0 := time.Unix(1_000_000, 0)
	var mu sync.Mutex
	admitted := 0
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if ok, _ := l.allow("u", t0); ok {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if admitted != loginFreeFailures {
		t.Fatalf("admitted=%d concurrent attempts before any result, want %d", admitted, loginFreeFailures)
	}
	// A busy abort frees a slot without counting as a failure.
	l.abort("u")
	if ok, _ := l.allow("u", t0); !ok {
		t.Fatal("abort did not release its in-flight slot")
	}
}

func TestLoginLimiterAbortLeavesNoEntry(t *testing.T) {
	l := newLoginLimiter()
	t0 := time.Unix(1_000_000, 0)
	l.allow("u", t0)
	l.abort("u")
	if len(l.entries) != 0 {
		t.Fatal("aborted attempt left an entry")
	}
}

func TestLoginLimiterSprayKeepsLockout(t *testing.T) {
	l := newLoginLimiter()
	l.maxEntries = 50
	t0 := time.Unix(1_000_000, 0)
	for range loginFreeFailures {
		l.fail("admin", t0)
	}
	for i := range 500 {
		l.fail("spray"+strconv.Itoa(i), t0.Add(time.Duration(i+1)*time.Millisecond))
	}
	if len(l.entries) > l.maxEntries {
		t.Fatalf("entries=%d exceeds cap", len(l.entries))
	}
	if ok, _ := l.allow("admin", t0.Add(time.Millisecond)); ok {
		t.Fatal("username spray wiped the lockout on admin")
	}
}

func TestChangePasswordThrottled(t *testing.T) {
	srv, c, _, _ := testServerApp(t)
	mustRedirect(t, loginAs(t, c, srv.URL, "admin", "admin"), "/change-password")
	var last *http.Response
	for range loginFreeFailures + 1 {
		_, cp := get(t, c, srv.URL+"/change-password")
		last = postForm(t, c, srv.URL+"/change-password", url.Values{
			"current_password": {"wrong"}, "new_password": {"labpass123"},
			"confirm_password": {"labpass123"}, "csrf_token": {csrfFrom(t, cp)},
		})
		_ = readBody(t, last)
	}
	if last.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want 429 after repeated wrong current password", last.StatusCode)
	}
}

// ---- sessions -------------------------------------------------------------

func doReq(t *testing.T, method, target string, hdr map[string]string, cookies []*http.Cookie, form url.Values) *http.Response {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func setCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestSessionCookieNameFollowsScheme(t *testing.T) {
	srv, _, _, _ := testServerApp(t)
	https := map[string]string{"X-Forwarded-Proto": "https"}

	resp := doReq(t, "GET", srv.URL+"/login", nil, nil, nil)
	if setCookie(resp, "session") == nil || setCookie(resp, hostSessionCookie) != nil {
		t.Fatal("plain HTTP must use the 'session' cookie")
	}

	// A stale plain-name cookie is expired when the HTTPS name is written.
	stale := []*http.Cookie{{Name: "session", Value: "junk"}}
	resp = doReq(t, "GET", srv.URL+"/login", https, stale, nil)
	hc := setCookie(resp, hostSessionCookie)
	if hc == nil || !hc.Secure || hc.Path != "/" || hc.Domain != "" || !hc.HttpOnly {
		t.Fatalf("__Host- cookie wrong: %+v", hc)
	}
	if old := setCookie(resp, "session"); old == nil || old.MaxAge >= 0 {
		t.Fatalf("legacy cookie not expired: %+v", old)
	}

	// Over HTTPS the plain-name cookie is not read: a planted one cannot log in.
	srv2, c2, _, app := testServerApp(t)
	readyUser(t, srv2.URL, c2)
	u, _ := url.Parse(srv2.URL)
	planted := c2.Jar.Cookies(u)
	resp = doReq(t, "GET", srv2.URL+"/", https, planted, nil)
	mustRedirect(t, resp, "/login")
	_ = app
}

func TestHTTPSLoginUsesHostCookie(t *testing.T) {
	srv, _, _, _ := testServerApp(t)
	https := map[string]string{"X-Forwarded-Proto": "https"}
	resp := doReq(t, "GET", srv.URL+"/login", https, nil, nil)
	sess := setCookie(resp, hostSessionCookie)
	csrf := csrfFrom(t, readBody(t, resp))
	resp = doReq(t, "POST", srv.URL+"/login", https, []*http.Cookie{sess},
		url.Values{"username": {"admin"}, "password": {"admin"}, "csrf_token": {csrf}})
	mustRedirect(t, resp, "/change-password")
	sess = setCookie(resp, hostSessionCookie)
	if sess == nil {
		t.Fatal("no __Host-session after login")
	}
	resp = doReq(t, "GET", srv.URL+"/change-password", https, []*http.Cookie{sess}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session cookie not honoured over HTTPS: %d", resp.StatusCode)
	}
}

// Traefik sends X-Forwarded-Proto: wss (not https) on a WebSocket upgrade. Read
// as-is, the SOL socket looked for the plain-HTTP cookie name and every
// connection was redirected to /login.
func TestRequestSchemeMapsWebSocketProtos(t *testing.T) {
	for proto, want := range map[string]string{
		"https": "https", "wss": "https", "WSS": "https", "wss, https": "https",
		"http": "http", "ws": "http",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("X-Forwarded-Proto", proto)
		if got := requestScheme(r); got != want {
			t.Errorf("X-Forwarded-Proto %q: scheme %q, want %q", proto, got, want)
		}
	}
}

func TestSOLSocketHonoursHostCookieBehindTraefik(t *testing.T) {
	srv, _, _, _ := testServerApp(t)
	// A cookie jar won't send a Secure __Host- cookie to the http:// test
	// server, so carry the latest one by hand, as a browser would.
	var sess *http.Cookie
	do := func(method, path, proto string, form url.Values) *http.Response {
		var cookies []*http.Cookie
		if sess != nil {
			cookies = []*http.Cookie{sess}
		}
		resp := doReq(t, method, srv.URL+path, map[string]string{"X-Forwarded-Proto": proto}, cookies, form)
		if c := setCookie(resp, hostSessionCookie); c != nil {
			sess = c
		}
		return resp
	}
	csrf := csrfFrom(t, readBody(t, do("GET", "/login", "https", nil)))
	mustRedirect(t, do("POST", "/login", "https",
		url.Values{"username": {"admin"}, "password": {"admin"}, "csrf_token": {csrf}}), "/change-password")
	// The password-change gate would redirect too; clear it so a redirect below
	// can only mean the session wasn't recognised.
	csrf = csrfFrom(t, readBody(t, do("GET", "/change-password", "https", nil)))
	mustRedirect(t, do("POST", "/change-password", "https", url.Values{
		"current_password": {"admin"}, "new_password": {"labpass123"},
		"confirm_password": {"labpass123"}, "csrf_token": {csrf},
	}), "/")

	resp := do("GET", "/server/1/sol", "wss", nil)
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		t.Fatalf("SOL socket behind Traefik (X-Forwarded-Proto: wss) redirected to %q: session cookie not honoured",
			resp.Header.Get("Location"))
	}
}

func TestRequestSchemeDirectTLS(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("X-Forwarded-Proto", "http")
	if requestScheme(r) != "https" || sessionCookieName(r) != hostSessionCookie {
		t.Fatal("direct TLS must count as https")
	}
}

func TestLogoutRevokesCopiedCookie(t *testing.T) {
	srv, c, _, _ := testServerApp(t)
	readyUser(t, srv.URL, c)
	u, _ := url.Parse(srv.URL)
	copied := c.Jar.Cookies(u)
	if resp := doReq(t, "GET", srv.URL+"/", nil, copied, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("copied cookie should work before logout: %d", resp.StatusCode)
	}
	_, body := get(t, c, srv.URL+"/")
	mustRedirect(t, postForm(t, c, srv.URL+"/logout", url.Values{"csrf_token": {csrfFrom(t, body)}}), "/login")
	resp := doReq(t, "GET", srv.URL+"/", nil, copied, nil)
	mustRedirect(t, resp, "/login")
}

func TestSessionWithoutSIDRejected(t *testing.T) {
	srv, c, _, app := testServerApp(t)
	readyUser(t, srv.URL, c)
	u, _ := url.Parse(srv.URL)
	var cur *sessionData
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == sessionCookie {
			cur = app.parseSession(ck.Value)
		}
	}
	if cur == nil || cur.SID == "" {
		t.Fatal("login did not mint a sid")
	}
	cur.SID = ""
	payload, _ := jsonMarshal(cur)
	resp := doReq(t, "GET", srv.URL+"/", nil, []*http.Cookie{{Name: sessionCookie, Value: app.signSession(payload)}}, nil)
	mustRedirect(t, resp, "/login")
}

func TestFlashTruncatedAndSanitized(t *testing.T) {
	s := &sessionData{}
	s.flash("error", "Error: "+strings.Repeat("é", 1000)+"\r\nX\x00")
	got := s.Flashes[0].Message
	if n := len([]rune(got)); n != maxFlashRunes+1 || !strings.HasSuffix(got, "…") {
		t.Fatalf("len=%d runes, want %d with ellipsis", n, maxFlashRunes+1)
	}
	s.flash("error", "a\r\nb\x00c")
	if m := s.Flashes[1].Message; m != "abc" {
		t.Fatalf("control chars not stripped: %q", m)
	}
}

// ---- cross-site GETs ------------------------------------------------------

func TestCrossSiteGETsRejected(t *testing.T) {
	srv, c, st := testServer(t)
	readyUser(t, srv.URL, c)
	if err := st.CreateServer(&model.Server{Name: "box", IPAddress: "10.0.0.9", BMCType: "generic", RedfishUser: "u", RedfishPassword: "p"}); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	cookies := c.Jar.Cookies(u)
	for _, path := range []string{"/server/1/kvm", "/server/1/console", "/server/1/console/manual", "/server/1/console/launch"} {
		for site, want403 := range map[string]bool{
			"cross-site": true, "same-origin": false, "same-site": false, "none": false, "": false,
		} {
			hdr := map[string]string{}
			if site != "" {
				hdr["Sec-Fetch-Site"] = site
			}
			resp := doReq(t, "GET", srv.URL+path, hdr, cookies, nil)
			if got := resp.StatusCode == http.StatusForbidden; got != want403 {
				t.Errorf("%s Sec-Fetch-Site=%q: status=%d, want403=%v", path, site, resp.StatusCode, want403)
			}
		}
	}
}

func TestConsoleJSONNotCached(t *testing.T) {
	srv, c, st := testServer(t)
	readyUser(t, srv.URL, c)
	if err := st.CreateServer(&model.Server{Name: "box", IPAddress: "10.0.0.9", BMCType: "generic", RedfishUser: "u", RedfishPassword: "p"}); err != nil {
		t.Fatal(err)
	}
	resp, body := get(t, c, srv.URL+"/server/1/console")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "token=") {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control=%q, want no-store", cc)
	}
}

// ---- IP validation, links -------------------------------------------------

func TestIPAddressValidationRejectsUnusable(t *testing.T) {
	for _, ip := range []string{"0.0.0.0", "::", "127.0.0.1", "::1", "224.0.0.1", "ff02::1", "255.255.255.255", "nope"} {
		if msg := ipAddressError(ip); msg == "" || validateIPAddress(ip) {
			t.Errorf("%q accepted", ip)
		}
	}
	for _, ip := range []string{"10.22.40.5", "169.254.1.1", "fe80::1", "2001:db8::1"} {
		if msg := ipAddressError(ip); msg != "" {
			t.Errorf("%q rejected: %s", ip, msg)
		}
	}
}

func TestBlankTargetLinksHaveNoopener(t *testing.T) {
	files, _ := filepath.Glob("templates/*.html")
	tag := regexp.MustCompile(`<a [^>]*target="_blank"[^>]*>`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range tag.FindAllString(string(b), -1) {
			if !strings.Contains(m, `rel="noopener"`) || strings.Contains(m, "noreferrer") {
				t.Errorf("%s: %s", f, m)
			}
		}
	}
}

func contextWithCancel(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithCancel(r.Context())
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
