package console

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkilar/lab-manager/internal/model"
)

func TestConsoleTokenRoundTrip(t *testing.T) {
	m := NewManager([]byte("test-secret-key"))
	tok := m.GenerateToken(7, 3)
	if !m.VerifyToken(tok, 7, 3) {
		t.Fatal("valid token rejected")
	}
	if m.VerifyToken(tok, 8, 3) {
		t.Fatal("token accepted for wrong server")
	}
	if m.VerifyToken(tok, 7, 4) {
		t.Fatal("token accepted for wrong user")
	}
	if m.VerifyToken("garbage", 7, 3) {
		t.Fatal("garbage token accepted")
	}
}

// recorder tracks which "METHOD path" combinations a fake iDRAC saw, so tests
// can assert the canonical endpoint was used and any session was cleaned up.
type recorder struct {
	mu   sync.Mutex
	hits map[string]int
}

func (r *recorder) note(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits[req.Method+" "+req.URL.Path]++
}

func (r *recorder) count(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits[key]
}

func hostOf(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return strings.TrimPrefix(srv.URL, "https://")
}

// TestIDRACRedfishPreAuthUsesCanonicalEndpoint verifies the pre-flight creates
// its session at /redfish/v1/Sessions (the ServiceRoot-advertised collection),
// reports method "redfish", reads the firmware version, deletes the session it
// created, and never touches the legacy /data/login endpoint.
func TestIDRACRedfishPreAuthUsesCanonicalEndpoint(t *testing.T) {
	rec := &recorder{hits: map[string]int{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.note(r)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/redfish/v1/Sessions":
			w.Header().Set("X-Auth-Token", "tok-123")
			w.Header().Set("Location", "/redfish/v1/Sessions/9")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && r.URL.Path == "/redfish/v1/Managers/iDRAC.Embedded.1":
			_, _ = w.Write([]byte(`{"FirmwareVersion":"3.21.21.21"}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/redfish/v1/Sessions/9":
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	m := NewManager([]byte("k"))
	res := m.PreAuthenticateIDRAC(t.Context(), &model.Server{
		IPAddress: hostOf(t, srv), BMCType: model.BMCIDRAC,
		RedfishUser: "root", RedfishPassword: "calvin",
	})

	if !res.Success || res.Method != "redfish" {
		t.Fatalf("want redfish success, got success=%v method=%q err=%q", res.Success, res.Method, res.Error)
	}
	if res.IDRACVersion != "3.21.21.21" {
		t.Errorf("firmware version = %q, want 3.21.21.21", res.IDRACVersion)
	}
	if rec.count("POST /redfish/v1/Sessions") != 1 {
		t.Errorf("expected one POST to /redfish/v1/Sessions, got %d", rec.count("POST /redfish/v1/Sessions"))
	}
	if rec.count("DELETE /redfish/v1/Sessions/9") != 1 {
		t.Errorf("session was not cleaned up (DELETE count=%d)", rec.count("DELETE /redfish/v1/Sessions/9"))
	}
	if rec.count("POST /data/login") != 0 {
		t.Errorf("legacy /data/login should not be reached on Redfish success")
	}
	if rec.count("POST /redfish/v1/SessionService/Sessions") != 0 {
		t.Errorf("must not POST to the SessionService alias")
	}
}

// TestIDRACRedfishPreAuthNeverLeaksSession guards the firmware quirk where a
// non-2xx response still carries a usable X-Auth-Token: the session must still
// be deleted (no session-table exhaustion) even as the code falls through to
// the working legacy login.
func TestIDRACRedfishPreAuthNeverLeaksSession(t *testing.T) {
	rec := &recorder{hits: map[string]int{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.note(r)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/redfish/v1/Sessions":
			// Firmware quirk: 405, yet a session is minted anyway.
			w.Header().Set("X-Auth-Token", "tok-leak")
			w.Header().Set("Location", "/redfish/v1/Sessions/13")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte(`{"error":{}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/redfish/v1/Sessions/13":
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/data/login":
			_, _ = w.Write([]byte(`<root><status>ok</status><authResult>0</authResult></root>`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	m := NewManager([]byte("k"))
	res := m.PreAuthenticateIDRAC(t.Context(), &model.Server{
		IPAddress: hostOf(t, srv), BMCType: model.BMCIDRAC,
		RedfishUser: "root", RedfishPassword: "calvin",
	})

	if !res.Success || res.Method != "legacy" {
		t.Fatalf("want legacy success after Redfish 405, got success=%v method=%q err=%q", res.Success, res.Method, res.Error)
	}
	if rec.count("DELETE /redfish/v1/Sessions/13") != 1 {
		t.Errorf("leaked session: DELETE count=%d, want 1", rec.count("DELETE /redfish/v1/Sessions/13"))
	}
}

const legacyLoginOK = `<root><status>ok</status><authResult>0</authResult></root>`

// legacyOnlyServer fakes an iDRAC 7/8 without Redfish: /data/login answers with
// body (setting a session cookie when cookie is true) and /data/logout is
// recorded along with the cookie it carried.
func legacyOnlyServer(t *testing.T, body string, cookie bool) (*httptest.Server, *recorder, *string) {
	t.Helper()
	rec := &recorder{hits: map[string]int{}}
	var mu sync.Mutex
	var logoutCookie string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.note(r)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/data/login":
			if cookie {
				http.SetCookie(w, &http.Cookie{Name: "-http-session-", Value: "sess-abc", Path: "/"})
			}
			_, _ = w.Write([]byte(body))
		case r.Method == http.MethodGet && r.URL.Path == "/data/logout":
			if c, err := r.Cookie("-http-session-"); err == nil {
				mu.Lock()
				logoutCookie = c.Value
				mu.Unlock()
			}
		default:
			w.WriteHeader(http.StatusNotFound) // Redfish absent -> legacy fallback
		}
	}))
	t.Cleanup(srv.Close)
	return srv, rec, &logoutCookie
}

func TestIDRACLegacyPreAuthLogsOutSession(t *testing.T) {
	srv, rec, logoutCookie := legacyOnlyServer(t, legacyLoginOK, true)

	m := NewManager([]byte("k"))
	res := m.PreAuthenticateIDRAC(t.Context(), &model.Server{
		IPAddress: hostOf(t, srv), BMCType: model.BMCIDRAC,
		RedfishUser: "root", RedfishPassword: "calvin",
	})
	if !res.Success || res.Method != "legacy" {
		t.Fatalf("want legacy success, got success=%v method=%q err=%q", res.Success, res.Method, res.Error)
	}
	if n := rec.count("GET /data/logout"); n != 1 {
		t.Errorf("GET /data/logout count = %d, want 1", n)
	}
	if *logoutCookie != "sess-abc" {
		t.Errorf("logout carried session cookie %q, want sess-abc", *logoutCookie)
	}
}

func TestIDRACLegacyPreAuthNoLogoutWithoutCookieOrOnFailure(t *testing.T) {
	cases := map[string]struct {
		body   string
		cookie bool
	}{
		"bad credentials":       {`<root><authResult>1</authResult></root>`, true},
		"success but no cookie": {legacyLoginOK, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv, rec, _ := legacyOnlyServer(t, tc.body, tc.cookie)
			m := NewManager([]byte("k"))
			_ = m.PreAuthenticateIDRAC(t.Context(), &model.Server{
				IPAddress: hostOf(t, srv), BMCType: model.BMCIDRAC,
				RedfishUser: "root", RedfishPassword: "calvin",
			})
			if n := rec.count("GET /data/logout"); n != 0 {
				t.Errorf("GET /data/logout count = %d, want 0", n)
			}
		})
	}
}

func TestConsoleTokenExpiryBoundary(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	now := base
	m := NewManager([]byte("k"))
	m.now = func() time.Time { return now }
	tok := m.GenerateToken(7, 3)

	for _, tc := range []struct {
		offset time.Duration
		want   bool
	}{
		{0, true},
		{29 * time.Second, true},
		{TokenValiditySeconds * time.Second, true}, // age > 30 expires; exactly 30 is still valid
		{31 * time.Second, false},
		{time.Hour, false},
	} {
		now = base.Add(tc.offset)
		if got := m.VerifyToken(tok, 7, 3); got != tc.want {
			t.Errorf("VerifyToken at +%v = %v, want %v", tc.offset, got, tc.want)
		}
	}
}

func TestConsoleTokenTamperAndWrongKey(t *testing.T) {
	m := NewManager([]byte("key-a"))
	tok := m.GenerateToken(7, 3)
	raw, err := base64.URLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatal(err)
	}
	tsStr, sig, _ := strings.Cut(string(raw), ":")
	ts, _ := strconv.ParseInt(tsStr, 10, 64)
	enc := func(ts int64, sig string) string {
		return base64.URLEncoding.EncodeToString(fmt.Appendf(nil, "%d:%s", ts, sig))
	}

	flipped := []byte(sig)
	if flipped[0] == '0' {
		flipped[0] = '1'
	} else {
		flipped[0] = '0'
	}
	for name, bad := range map[string]string{
		"tampered signature":  enc(ts, string(flipped)),
		"tampered timestamp":  enc(ts+1, sig),
		"truncated signature": enc(ts, sig[:len(sig)-2]),
		"empty signature":     enc(ts, ""),
		"no separator":        base64.URLEncoding.EncodeToString([]byte("nocolon")),
		"non-numeric ts":      base64.URLEncoding.EncodeToString([]byte("abc:" + sig)),
	} {
		if m.VerifyToken(bad, 7, 3) {
			t.Errorf("%s: token accepted", name)
		}
	}
	if m.VerifyToken(tok, 70, 3) {
		t.Error("tampered server id accepted")
	}
	if m.VerifyToken(tok, 7, 30) {
		t.Error("tampered user id accepted")
	}
	if !m.VerifyToken(tok, 7, 3) {
		t.Error("control: untampered token rejected")
	}
	if NewManager([]byte("key-b")).VerifyToken(tok, 7, 3) {
		t.Error("token from a different key accepted")
	}
}

// TestIDRACRedfishPreAuthDoesNotFollowRedirect: a 307 on the session POST must
// not replay the credentials to the redirect target; the pre-flight fails.
func TestIDRACRedfishPreAuthDoesNotFollowRedirect(t *testing.T) {
	other := &recorder{hits: map[string]int{}}
	otherSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		other.note(r)
	}))
	defer otherSrv.Close()

	bmc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redfish/v1/Sessions" {
			http.Redirect(w, r, otherSrv.URL+"/redfish/v1/Sessions", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusNotFound) // legacy fallback
	}))
	defer bmc.Close()

	res := NewManager([]byte("k")).PreAuthenticateIDRAC(t.Context(), &model.Server{
		IPAddress: hostOf(t, bmc), BMCType: model.BMCIDRAC,
		RedfishUser: "root", RedfishPassword: "calvin",
	})
	if res.Success {
		t.Fatal("pre-auth succeeded through a redirect")
	}
	if !strings.Contains(res.Error, "307") {
		t.Errorf("error %q should name the 307 status", res.Error)
	}
	if n := len(other.hits); n != 0 {
		t.Errorf("redirect target received %d request(s): %v", n, other.hits)
	}
}

// TestIDRACCleanupSessionStaysOnBMC: whatever host the session Location names,
// the DELETE (with X-Auth-Token) goes to the BMC itself.
func TestIDRACCleanupSessionStaysOnBMC(t *testing.T) {
	other := &recorder{hits: map[string]int{}}
	otherSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		other.note(r)
	}))
	defer otherSrv.Close()

	for name, loc := range map[string]string{
		"absolute other host": otherSrv.URL + "/redfish/v1/Sessions/5",
		"relative":            "/redfish/v1/Sessions/5",
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{hits: map[string]int{}}
			var token string
			bmc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rec.note(r)
				token = r.Header.Get("X-Auth-Token")
			}))
			defer bmc.Close()

			idracCleanupSession(hostOf(t, bmc), "tok", loc)

			if rec.count("DELETE /redfish/v1/Sessions/5") != 1 || token != "tok" {
				t.Errorf("BMC hits=%v token=%q, want one authenticated DELETE", rec.hits, token)
			}
			if len(other.hits) != 0 {
				t.Errorf("other host received %v", other.hits)
			}
		})
	}

	// Unusable locations are skipped entirely.
	rec := &recorder{hits: map[string]int{}}
	bmc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { rec.note(r) }))
	defer bmc.Close()
	for _, loc := range []string{"https://evil.example", "/", "%zz"} {
		idracCleanupSession(hostOf(t, bmc), "tok", loc)
	}
	if len(rec.hits) != 0 {
		t.Errorf("unusable Location produced requests: %v", rec.hits)
	}
}
