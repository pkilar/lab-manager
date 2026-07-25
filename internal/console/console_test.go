package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

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
