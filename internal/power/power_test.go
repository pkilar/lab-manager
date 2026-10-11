package power

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pkilar/lab-manager/internal/model"
	"github.com/pkilar/lab-manager/internal/secret"
	"github.com/pkilar/lab-manager/internal/store"
)

const testFernetKey = "VTfdkyi4hZ3WvGv84jig3XyW_OUl6ovpe1ZU7UUIgRM="

func TestIPMIArgsKeepPasswordOffArgv(t *testing.T) {
	s := &model.Server{IPAddress: "10.0.0.5", IPMIUser: "admin", IPMIPassword: "s3cret-pw"}
	for _, cmd := range [][]string{{"power", "on"}, {"power", "off"}, {"power", "cycle"}, {"power", "status"}} {
		args := ipmiArgs(s, cmd...)
		if !slices.Contains(args, "-E") {
			t.Errorf("%v: argv %v missing -E", cmd, args)
		}
		if slices.Contains(args, "-P") {
			t.Errorf("%v: argv %v must not contain -P", cmd, args)
		}
		if strings.Contains(strings.Join(args, " "), s.IPMIPassword) {
			t.Errorf("%v: argv %v leaks the password", cmd, args)
		}
		if !slices.Equal(args[len(args)-len(cmd):], cmd) {
			t.Errorf("%v: argv %v does not end with the command", cmd, args)
		}
	}
	if !slices.Contains(ipmiEnv(s), "IPMI_PASSWORD=s3cret-pw") {
		t.Error("ipmiEnv must carry IPMI_PASSWORD")
	}
}

func newWoLController(t *testing.T, send func([]byte, string, int) error) (*Controller, *store.Store) {
	t.Helper()
	f, err := secret.NewFernet([]byte(testFernetKey))
	if err != nil {
		t.Fatalf("NewFernet: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "servers.db"), f)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	c := NewController(st, true)
	c.sendWoL = send
	return c, st
}

func newWoLServer(t *testing.T, st *store.Store) *model.Server {
	t.Helper()
	s := &model.Server{Name: "wol", IPAddress: "192.168.1.20", MACAddress: "aa:bb:cc:dd:ee:ff", BMCType: model.BMCGeneric, Status: "Off"}
	if err := st.CreateServer(s); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	return s
}

func TestWoLAllSendsFailReportsFailure(t *testing.T) {
	boom := errors.New("network is unreachable")
	c, st := newWoLController(t, func([]byte, string, int) error { return boom })
	s := newWoLServer(t, st)

	ok, msg := c.wolCommand(s)
	if ok {
		t.Fatal("wolCommand reported success although every send failed")
	}
	if !strings.Contains(msg, boom.Error()) {
		t.Errorf("message %q does not contain the send error", msg)
	}
	if s.Status != "Off" {
		t.Errorf("in-memory status = %q, want untouched Off", s.Status)
	}
	got, err := st.GetServer(s.ID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if got.Status != "Off" {
		t.Errorf("persisted status = %q, want untouched Off", got.Status)
	}
}

func TestWoLPartialSuccessIsSuccess(t *testing.T) {
	calls := 0
	c, st := newWoLController(t, func(_ []byte, _ string, _ int) error {
		calls++
		if calls == 1 {
			return nil
		}
		return errors.New("later send failed")
	})
	s := newWoLServer(t, st)

	ok, msg := c.wolCommand(s)
	if !ok {
		t.Fatalf("wolCommand = false (%q), want true when one send succeeded", msg)
	}
	if calls != 3 {
		t.Errorf("sends = %d, want 3 (255.255.255.255:9, :7, subnet:9)", calls)
	}
	if s.Status != "On" {
		t.Errorf("status = %q, want On", s.Status)
	}
}

func TestBuildMagicPacket(t *testing.T) {
	p, err := buildMagicPacket("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("buildMagicPacket: %v", err)
	}
	if len(p) != 102 {
		t.Fatalf("len = %d, want 102", len(p))
	}
	if !bytes.Equal(p[:6], bytes.Repeat([]byte{0xFF}, 6)) {
		t.Errorf("header = % x, want 6x FF", p[:6])
	}
	mac := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	for i := range 16 {
		if got := p[6+i*6 : 12+i*6]; !bytes.Equal(got, mac) {
			t.Errorf("repetition %d = % x, want % x", i, got, mac)
		}
	}
	// Dash separators are accepted too.
	if _, err := buildMagicPacket("AA-BB-CC-DD-EE-FF"); err != nil {
		t.Errorf("dash-separated MAC: %v", err)
	}
	for _, bad := range []string{"", "not-a-mac", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00"} {
		if _, err := buildMagicPacket(bad); err == nil {
			t.Errorf("buildMagicPacket(%q) succeeded, want error", bad)
		}
	}
}

func TestIPMIEnvStripsAppSecrets(t *testing.T) {
	t.Setenv("LAB_MANAGER_SECRET_KEY", "topsecret")
	t.Setenv("LAB_MANAGER_ENCRYPTION_KEY", "alsosecret")
	t.Setenv("IPMI_PASSWORD", "inherited")
	t.Setenv("KEEP_ME", "yes")

	env := ipmiEnv(&model.Server{IPMIPassword: "real"})
	for _, kv := range env {
		if strings.HasPrefix(kv, "LAB_MANAGER_") {
			t.Errorf("env leaks %q", kv)
		}
	}
	if n := countPrefix(env, "IPMI_PASSWORD="); n != 1 || !slices.Contains(env, "IPMI_PASSWORD=real") {
		t.Errorf("IPMI_PASSWORD entries = %d, want exactly one with the server's password", n)
	}
	if !slices.Contains(env, "KEEP_ME=yes") {
		t.Error("unrelated variables must be preserved")
	}
	// The process's own environment is untouched.
	if os.Getenv("LAB_MANAGER_SECRET_KEY") != "topsecret" {
		t.Error("ipmiEnv mutated the process environment")
	}
}

func countPrefix(env []string, p string) (n int) {
	for _, kv := range env {
		if strings.HasPrefix(kv, p) {
			n++
		}
	}
	return n
}

// redfishFixture starts a fake TLS BMC running handler and returns a controller,
// a stored server whose IP is the fake's host:port, and the store.
func redfishFixture(t *testing.T, handler http.HandlerFunc) (*Controller, *model.Server, *store.Store) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	c, st := newWoLController(t, nil)
	s := &model.Server{
		Name: "rf", IPAddress: strings.TrimPrefix(srv.URL, "https://"), BMCType: model.BMCIDRAC,
		RedfishUser: "root", RedfishPassword: "calvin", Status: "Unknown",
	}
	if err := st.CreateServer(s); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	return c, s, st
}

func TestRedfishCommandResetTypes(t *testing.T) {
	for _, tc := range []struct {
		command, resetType, status string
	}{
		{"power on", "On", "On"},
		{"power off", "GracefulShutdown", "Off"},
		{"power cycle", "ForceRestart", "On"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			var got map[string]string
			var path, user string
			c, s, st := redfishFixture(t, func(w http.ResponseWriter, r *http.Request) {
				path = r.URL.Path
				user, _, _ = r.BasicAuth()
				_ = json.NewDecoder(r.Body).Decode(&got)
				w.WriteHeader(http.StatusNoContent)
			})
			ok, msg := c.Send(t.Context(), s, tc.command)
			if !ok {
				t.Fatalf("Send = false (%q)", msg)
			}
			if got["ResetType"] != tc.resetType {
				t.Errorf("ResetType = %q, want %q", got["ResetType"], tc.resetType)
			}
			if path != "/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset" || user != "root" {
				t.Errorf("path=%q user=%q", path, user)
			}
			persisted, err := st.GetServer(s.ID)
			if err != nil {
				t.Fatal(err)
			}
			if s.Status != tc.status || persisted.Status != tc.status {
				t.Errorf("status mem=%q db=%q, want %q", s.Status, persisted.Status, tc.status)
			}
		})
	}
}

func TestRedfishUnsupportedCommandSendsNothing(t *testing.T) {
	hit := false
	c, s, _ := redfishFixture(t, func(http.ResponseWriter, *http.Request) { hit = true })
	for _, cmd := range []string{"reset", "bogus", ""} {
		ok, msg := c.Send(t.Context(), s, cmd)
		if ok || msg != "Command not implemented" {
			t.Errorf("Send(%q) = %v, %q", cmd, ok, msg)
		}
	}
	if hit {
		t.Error("unsupported command reached the BMC")
	}
}

func TestRedfishNonOKStatusMessages(t *testing.T) {
	c, s, _ := redfishFixture(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	for cmd, want := range map[string]string{
		"power off":   "Power off failed: HTTP 500",
		"power cycle": "Restart failed: HTTP 500",
		"power on":    "Command not implemented",
	} {
		if ok, msg := c.Send(t.Context(), s, cmd); ok || msg != want {
			t.Errorf("Send(%q) = %v, %q; want false, %q", cmd, ok, msg, want)
		}
	}
	if s.Status != "Unknown" {
		t.Errorf("failed commands changed status to %q", s.Status)
	}
}

// TestRedfishDoesNotFollowRedirect: a 307 must not replay the credentialed POST
// to the redirect target, and is reported as a failure.
func TestRedfishDoesNotFollowRedirect(t *testing.T) {
	other := 0
	otherSrv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { other++ }))
	defer otherSrv.Close()

	c, s, _ := redfishFixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherSrv.URL+r.URL.Path, http.StatusTemporaryRedirect)
	})
	for _, cmd := range []string{"power on", "power off", "power cycle"} {
		if ok, msg := c.Send(t.Context(), s, cmd); ok {
			t.Errorf("Send(%q) succeeded through a redirect (%q)", cmd, msg)
		}
	}
	if got := c.CheckStatus(t.Context(), s); got != "Unknown" {
		t.Errorf("CheckStatus through redirect = %q, want cached Unknown", got)
	}
	if other != 0 {
		t.Errorf("redirect target received %d request(s)", other)
	}
}

func TestCheckStatusRedfish(t *testing.T) {
	for _, tc := range []struct{ state, body, want string }{
		{"On", `{"PowerState":"On"}`, "On"},
		{"Off", `{"PowerState":"Off"}`, "Off"},
		{"missing", `{}`, "Unknown"},
	} {
		t.Run(tc.state, func(t *testing.T) {
			c, s, st := redfishFixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/redfish/v1/Systems/System.Embedded.1/" {
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
				}
				_, _ = w.Write([]byte(tc.body))
			})
			s.Status = "Off"
			if got := c.CheckStatus(t.Context(), s); got != tc.want {
				t.Fatalf("CheckStatus = %q, want %q", got, tc.want)
			}
			persisted, err := st.GetServer(s.ID)
			if err != nil {
				t.Fatal(err)
			}
			if s.Status != tc.want || persisted.Status != tc.want {
				t.Errorf("status mem=%q db=%q, want %q", s.Status, persisted.Status, tc.want)
			}
		})
	}
}

func TestCheckStatusRedfishErrorKeepsCachedStatus(t *testing.T) {
	c, s, _ := redfishFixture(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	s.Status = "On"
	if got := c.CheckStatus(t.Context(), s); got != "On" {
		t.Errorf("CheckStatus = %q, want cached On", got)
	}
	c2, s2, _ := redfishFixture(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("not json")) })
	s2.Status = "Off"
	if got := c2.CheckStatus(t.Context(), s2); got != "Off" {
		t.Errorf("CheckStatus (bad JSON) = %q, want cached Off", got)
	}
}

func TestParseIPMIPowerStatus(t *testing.T) {
	for _, tc := range []struct {
		out    string
		want   string
		wantOK bool
	}{
		{"Chassis Power is on\n", "On", true},
		{"Chassis Power is off\n", "Off", true},
		{"CHASSIS POWER IS ON", "On", true},
		{"", "", false},
		{"unexpected output", "", false},
		// A bare substring test for "on" matched these.
		{"Unable to establish IPMI v2 / RMCP+ session", "", false},
		{"Error: Unable to establish LAN session\nChassis Power is off\n", "Off", true},
		{"Chassis Power is unknown", "", false},
	} {
		got, ok := parseIPMIPowerStatus(tc.out)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("parseIPMIPowerStatus(%q) = %q, %v; want %q, %v", tc.out, got, ok, tc.want, tc.wantOK)
		}
	}
}
