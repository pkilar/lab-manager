package web

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pkilar/lab-manager/internal/console"
	"github.com/pkilar/lab-manager/internal/model"
)

func TestTemplatesRenderAllPages(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	a := &App{tmpl: tmpl, wolEnabled: true}

	base := baseData{WolEnabled: true, CSRF: "csrf-token-123", Flashes: []Flash{{Category: "success", Message: "<ok>"}}}

	pages := map[string]any{
		"index": indexData{baseData: base, Servers: []serverRow{{
			ID: 1, Name: "r630 <test>", NotesPreview: "a note", NotesTruncated: true,
			IPAddress: "10.0.0.1", BMCType: "idrac", HasCreds: true, HasMAC: true,
			Status: "On", StatusOn: true, HasLastUpdated: true,
			LastUpdatedUTC: "2026-04-22T14:07:43.000000", LastUpdatedLocal: "2026-04-22 14:07:43 UTC",
		}}},
		"new_server":      simplePage{base},
		"login":           simplePage{base},
		"change_password": simplePage{base},
		"edit_server": editData{baseData: base, Server: editServerRow{
			ID: 1, Name: "r630", IPAddress: "10.0.0.1", BMCType: "idrac",
			RedfishUser: "root", HasRedfishUser: true,
		}},
	}
	for name, data := range pages {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			a.renderPage(rec, name, 200, data)
			if rec.Code != 200 || rec.Body.Len() == 0 {
				t.Fatalf("render %s: status %d, len %d", name, rec.Code, rec.Body.Len())
			}
		})
	}

	rec := httptest.NewRecorder()
	a.renderPage(rec, "index", 200, pages["index"])
	body := rec.Body.String()
	if !strings.Contains(body, "csrf-token-123") {
		t.Error("index missing CSRF token")
	}
	if strings.Contains(body, "<test>") {
		t.Error("index did not escape server name")
	}
}

func TestTemplatesRenderConsolePages(t *testing.T) {
	tmpl, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}
	a := &App{tmpl: tmpl}

	cases := map[string]any{
		"console_launch": consoleGenericData{
			ServerName: "r630", BMCType: "generic", ConsoleURL: "https://10.0.0.1/",
			Username: "root", Password: "pa'ss\"word", HasUsername: true,
		},
		"console_launch_supermicro": consoleSupermicroData{
			ServerName: "andromeda", IPAddress: "10.0.0.2",
			LoginURL: "https://10.0.0.2/cgi/login.cgi", ConsoleURL: "https://10.0.0.2/cgi/x",
			Username: "ADMIN", Password: "p\"w'd", HasUsername: true,
		},
		"console_launch_idrac": consoleIdracData{
			ServerID: 1, ServerName: "r630", IPAddress: "10.0.0.1", ConsoleURL: "https://10.0.0.1/console",
			Username: "root", Password: "cal'vin\"", HasUsername: true,
			Auth: console.IDRACAuthResult{Success: true, Method: "redfish", IDRACVersion: "5.10.00"},
		},
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			a.renderConsole(rec, name, data)
			if rec.Code != 200 || rec.Body.Len() == 0 {
				t.Fatalf("render %s: status %d, len %d", name, rec.Code, rec.Body.Len())
			}
		})
	}
}

func TestSessionSignRoundTrip(t *testing.T) {
	a := &App{secretKey: []byte("another-secret")}
	in := &sessionData{UID: 42, CSRF: "abc", Flashes: []Flash{{Category: "error", Message: "boom"}}}
	payload, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	cookie := a.signSession(payload)
	out := a.parseSession(cookie)
	if out.UID != 42 || out.CSRF != "abc" || len(out.Flashes) != 1 || out.Flashes[0].Message != "boom" {
		t.Fatalf("session round-trip mismatch: %+v", out)
	}
	if got := a.parseSession(cookie + "x"); got.UID != 0 {
		t.Fatalf("tampered cookie produced UID %d", got.UID)
	}
}

func TestValidation(t *testing.T) {
	if !validateIPAddress("192.168.1.1") || !validateIPAddress("::1") {
		t.Error("valid IPs rejected")
	}
	if validateIPAddress("999.1.1.1") || validateIPAddress("nope") {
		t.Error("invalid IPs accepted")
	}
	if !validateMACAddress("") || !validateMACAddress("AA:BB:CC:DD:EE:FF") || !validateMACAddress("aa-bb-cc-dd-ee-ff") {
		t.Error("valid MACs rejected")
	}
	if validateMACAddress("AA:BB:CC:DD:EE") || validateMACAddress("zz:bb:cc:dd:ee:ff") {
		t.Error("invalid MACs accepted")
	}
	if got := sanitizeServerName("a<b>c\"d'e&f"); got != "abcdef" {
		t.Errorf("sanitize = %q, want abcdef", got)
	}
}

func TestRequestScheme(t *testing.T) {
	cases := []struct {
		name   string
		setTLS bool
		xfp    string
		want   string
	}{
		{"plain-http", false, "", "http"},
		{"direct-tls", true, "", "https"},
		{"proxy-https", false, "https", "https"},
		{"proxy-http", false, "http", "http"},
		{"proxy-https-list", false, "https, http", "https"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://example/", nil)
			if c.setTLS {
				r.TLS = &tls.ConnectionState{}
			}
			if c.xfp != "" {
				r.Header.Set("X-Forwarded-Proto", c.xfp)
			}
			if got := requestScheme(r); got != c.want {
				t.Fatalf("requestScheme = %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseSOLInstance(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"", model.DefaultSOLInstance, true}, // unspecified: every existing server
		{"1", 1, true},
		{"2", 2, true},
		{" 2 ", 2, true},
		{"15", 15, true}, // ipmitool's documented ceiling
		{"0", 0, false},  // ipmitool: "Instance must range from 1 to 15"
		{"16", 0, false}, // one past the ceiling
		{"-1", 0, false},
		{"COM2", 0, false},        // the label, not the value
		{"2; rm -rf /", 0, false}, // never reaches argv, but reject loudly
	}
	for _, c := range cases {
		got, ok := parseSOLInstance(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("parseSOLInstance(%q) = (%d, %v), want (%d, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
