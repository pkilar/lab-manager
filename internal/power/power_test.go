package power

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
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

// addRedfishBMC starts a fake TLS BMC running handler and stores a server named
// name in st whose IP is the fake's host:port.
func addRedfishBMC(t *testing.T, st *store.Store, name string, handler http.HandlerFunc) *model.Server {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	allowTestHost(t)
	s := &model.Server{
		Name: name, IPAddress: strings.TrimPrefix(srv.URL, "https://"), BMCType: model.BMCIDRAC,
		RedfishUser: "root", RedfishPassword: "calvin", Status: "Unknown",
	}
	if err := st.CreateServer(s); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	return s
}

// redfishFixture starts a fake TLS BMC running handler and returns a controller,
// a stored server whose IP is the fake's host:port, and the store.
func redfishFixture(t *testing.T, handler http.HandlerFunc) (*Controller, *model.Server, *store.Store) {
	t.Helper()
	c, st := newWoLController(t, nil)
	return c, addRedfishBMC(t, st, "rf", handler), st
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

type pikvmCall struct{ method, path, action, user, pass string }

// newPiKVM starts a TLS httptest server and a stored PiKVM row pointing at it.
func newPiKVM(t *testing.T, redfishUser, ipmiUser string, h func(w http.ResponseWriter, r *http.Request)) (*Controller, *model.Server, *[]pikvmCall) {
	t.Helper()
	var calls []pikvmCall
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, pikvmCall{r.Method, r.URL.Path, r.URL.Query().Get("action"), r.Header.Get("X-KVMD-User"), r.Header.Get("X-KVMD-Passwd")})
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	allowTestHost(t)
	c, st := newWoLController(t, nil)
	s := &model.Server{
		Name: "pikvm", IPAddress: strings.TrimPrefix(srv.URL, "https://"), BMCType: model.BMCPiKVM, Status: "Unknown",
		RedfishUser: redfishUser, RedfishPassword: "rf-pw", IPMIUser: ipmiUser, IPMIPassword: "ipmi-pw",
	}
	if err := st.CreateServer(s); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	return c, s, &calls
}

func okJSON(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte(`{"ok": true, "result": {}}`))
}

func TestPiKVMSendCommands(t *testing.T) {
	for _, tc := range []struct{ cmd, action, status string }{
		{"power on", "on", "On"},
		{"power off", "off", "Off"},
		{"power cycle", "reset_hard", "On"},
		{"reset", "reset_hard", "On"},
	} {
		t.Run(tc.cmd, func(t *testing.T) {
			c, s, calls := newPiKVM(t, "admin", "", okJSON)
			ok, msg := c.Send(t.Context(), s, tc.cmd)
			if !ok {
				t.Fatalf("Send = false (%q)", msg)
			}
			want := pikvmCall{http.MethodPost, "/api/atx/power", tc.action, "admin", "rf-pw"}
			if len(*calls) != 1 || (*calls)[0] != want {
				t.Fatalf("calls = %+v, want [%+v]", *calls, want)
			}
			if s.Status != tc.status {
				t.Errorf("status = %q, want %q", s.Status, tc.status)
			}
			got, err := c.store.GetServer(s.ID)
			if err != nil || got.Status != tc.status {
				t.Errorf("persisted status = %q (err %v), want %q", got.Status, err, tc.status)
			}
		})
	}
}

func TestPiKVMSendErrorJSON(t *testing.T) {
	c, s, _ := newPiKVM(t, "admin", "", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"ok": false, "result": {"error": "AtxIsBusyError", "error_msg": "Performing another ATX operation"}}`))
	})
	ok, msg := c.Send(t.Context(), s, "power on")
	if ok || !strings.Contains(msg, "AtxIsBusyError") || !strings.Contains(msg, "another ATX operation") {
		t.Errorf("Send = %v, %q; want failure naming the kvmd error", ok, msg)
	}
	if strings.Contains(msg, "rf-pw") {
		t.Error("message leaks the password")
	}
	if s.Status != "Unknown" {
		t.Errorf("status = %q, want untouched", s.Status)
	}
	c2, s2, _ := newPiKVM(t, "admin", "", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	if ok, msg := c2.Send(t.Context(), s2, "power off"); ok || !strings.Contains(msg, "HTTP 403") {
		t.Errorf("Send = %v, %q; want HTTP 403 failure", ok, msg)
	}
}

func TestPiKVMNeverHitsRedfish(t *testing.T) {
	c, s, calls := newPiKVM(t, "admin", "", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/redfish/") {
			t.Errorf("PiKVM request hit Redfish path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ok": true, "result": {"enabled": true, "leds": {"power": true}}}`))
	})
	c.Send(t.Context(), s, "power on")
	c.CheckStatus(t.Context(), s)
	for _, call := range *calls {
		if strings.Contains(call.path, "redfish") {
			t.Errorf("hit %s", call.path)
		}
	}
	if len(*calls) != 2 {
		t.Errorf("calls = %d, want 2", len(*calls))
	}
}

func TestPiKVMIPMICredsAndNoCreds(t *testing.T) {
	c, s, calls := newPiKVM(t, "", "ipmiuser", okJSON)
	if ok, msg := c.Send(t.Context(), s, "power on"); !ok {
		t.Fatalf("Send = false (%q)", msg)
	}
	if got := (*calls)[0]; got.user != "ipmiuser" || got.pass != "ipmi-pw" {
		t.Errorf("headers = %q/%q, want IPMI creds", got.user, got.pass)
	}

	c, s, calls = newPiKVM(t, "", "", okJSON)
	if ok, _ := c.Send(t.Context(), s, "power on"); ok || len(*calls) != 0 {
		t.Errorf("no-credential PiKVM must fail without any request (calls %d)", len(*calls))
	}
	if got := c.CheckStatus(t.Context(), s); got != "Unknown" || len(*calls) != 0 {
		t.Errorf("CheckStatus = %q with %d calls, want cached and no request", got, len(*calls))
	}
}

func TestPiKVMSendUnknownCommand(t *testing.T) {
	c, s, calls := newPiKVM(t, "admin", "", okJSON)
	if ok, msg := c.Send(t.Context(), s, "bogus"); ok || msg != "Command not implemented" || len(*calls) != 0 {
		t.Errorf("Send = %v, %q, calls %d", ok, msg, len(*calls))
	}
}

func TestPiKVMCheckStatus(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		code       int
		want       string
	}{
		{"on", `{"ok":true,"result":{"enabled":true,"busy":false,"leds":{"power":true,"hdd":false}}}`, 200, "On"},
		{"forbidden", `{"ok":false,"result":{"error":"ForbiddenError"}}`, 403, "Unknown"},
		{"garbage", `not json`, 200, "Unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s, calls := newPiKVM(t, "admin", "", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			})
			if got := c.CheckStatus(t.Context(), s); got != tc.want {
				t.Errorf("CheckStatus = %q, want %q", got, tc.want)
			}
			want := pikvmCall{http.MethodGet, "/api/atx", "", "admin", "rf-pw"}
			if len(*calls) != 1 || (*calls)[0] != want {
				t.Errorf("calls = %+v, want [%+v]", *calls, want)
			}
			got, err := c.store.GetServer(s.ID)
			if err != nil || got.Status != tc.want {
				t.Errorf("persisted = %q (err %v), want %q", got.Status, err, tc.want)
			}
		})
	}
}

// pikvmVideoFixture is a PiKVM fake serving /api/atx and the kvmd event
// WebSocket. wsEvents are written as text frames after the upgrade, then the
// connection is held open until the client leaves.
type pikvmVideoFixture struct {
	mu                sync.Mutex
	atxHits, wsHits   int
	atxCode           int
	atxEnabled, atxOn bool
	wsEvents          []string
	wsRefuse          bool
}

func newPiKVMVideo(t *testing.T, f *pikvmVideoFixture) (*Controller, *model.Server) {
	t.Helper()
	old := pikvmVideoWindow
	pikvmVideoWindow = 300 * time.Millisecond
	t.Cleanup(func() { pikvmVideoWindow = old })
	up := websocket.Upgrader{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authOK := r.Header.Get("X-KVMD-User") == "admin" && r.Header.Get("X-KVMD-Passwd") == "rf-pw"
		switch r.URL.Path {
		case "/api/atx":
			f.mu.Lock()
			f.atxHits++
			code, en, on := f.atxCode, f.atxEnabled, f.atxOn
			f.mu.Unlock()
			if code == 0 {
				code = 200
			}
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"ok":true,"result":{"enabled":` + boolStr(en) + `,"leds":{"power":` + boolStr(on) + `}}}`))
		case "/api/ws":
			f.mu.Lock()
			f.wsHits++
			refuse := f.wsRefuse
			evs := f.wsEvents
			f.mu.Unlock()
			if r.URL.Query().Get("stream") != "1" {
				t.Errorf("ws query = %q, want stream=1", r.URL.RawQuery)
			}
			if !authOK || refuse {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			conn, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			for _, e := range evs {
				if conn.WriteMessage(websocket.TextMessage, []byte(e)) != nil {
					return
				}
			}
			for { // hold open until the client closes
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	allowTestHost(t)
	c, st := newWoLController(t, nil)
	s := &model.Server{
		Name: "pikvm", IPAddress: strings.TrimPrefix(srv.URL, "https://"), BMCType: model.BMCPiKVM, Status: "Unknown",
		RedfishUser: "admin", RedfishPassword: "rf-pw",
	}
	if err := st.CreateServer(s); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	return c, s
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func streamerEv(source string) string {
	return `{"event_type":"streamer","event":{"streamer":{"source":` + source + `}}}`
}

func TestPiKVMVideoStatus(t *testing.T) {
	const offline = `{"online":false,"resolution":{"width":640,"height":480}}`
	const online = `{"online":true,"resolution":{"width":1280,"height":720}}`
	for _, tc := range []struct {
		name      string
		f         *pikvmVideoFixture
		want      string
		persisted string
		wantWS    int
		maxDur    time.Duration // 0 = no bound
	}{
		{"led on short-circuits", &pikvmVideoFixture{atxEnabled: true, atxOn: true}, "On", "On", 0, 0},
		{"led off, video comes online", &pikvmVideoFixture{atxEnabled: true, wsEvents: []string{
			streamerEv("null"), streamerEv(offline), streamerEv(online)}}, "On", "On", 1, 250 * time.Millisecond},
		{"led off, stays offline", &pikvmVideoFixture{atxEnabled: true, wsEvents: []string{
			streamerEv("null"), streamerEv(offline)}}, "Off", "Off", 1, 0},
		{"led off, capture never starts", &pikvmVideoFixture{atxEnabled: true, wsEvents: []string{
			streamerEv("null"), streamerEv("null")}}, "Unknown", "Unknown", 1, 0},
		{"atx disabled, video online", &pikvmVideoFixture{wsEvents: []string{streamerEv(online)}}, "On", "On", 1, 0},
		{"ws refuses auth", &pikvmVideoFixture{atxEnabled: true, wsRefuse: true}, "Unknown", "Unknown", 1, 0},
		{"partial event shape and legacy name", &pikvmVideoFixture{atxEnabled: true, wsEvents: []string{
			`{"event_type":"info","event":{"streamer":{"source":{"online":true}}}}`,
			`{"event_type":"streamer_state","event":{"streamer":{"source":{"online":true}}}}`}}, "On", "On", 1, 0},
		{"atx forbidden", &pikvmVideoFixture{atxCode: 403, wsEvents: []string{streamerEv(online)}}, "Unknown", "Unknown", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, s := newPiKVMVideo(t, tc.f)
			start := time.Now()
			if got := c.CheckStatus(t.Context(), s); got != tc.want {
				t.Errorf("CheckStatus = %q, want %q", got, tc.want)
			}
			if tc.maxDur > 0 && time.Since(start) > tc.maxDur {
				t.Errorf("took %v, want under %v (must return before the window elapses)", time.Since(start), tc.maxDur)
			}
			tc.f.mu.Lock()
			ws, atx := tc.f.wsHits, tc.f.atxHits
			tc.f.mu.Unlock()
			if ws != tc.wantWS || atx != 1 {
				t.Errorf("wsHits = %d (want %d), atxHits = %d (want 1)", ws, tc.wantWS, atx)
			}
			got, err := c.store.GetServer(s.ID)
			if err != nil || got.Status != tc.persisted {
				t.Errorf("persisted = %q (err %v), want %q", got.Status, err, tc.persisted)
			}
		})
	}
}

// TestSendIPMICommandMapping runs Send through a stub ipmitool (first on PATH,
// as in the sol tests) that echoes its argv, so the command mapping is checked
// without a BMC. Unmapped commands are refused before ipmitool runs.
func TestSendIPMICommandMapping(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stub ipmitool needs a POSIX shell")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ipmitool"), []byte("#!/bin/sh\necho \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	c, st := newWoLController(t, nil)
	newIPMIServer := func() *model.Server {
		s := &model.Server{Name: "ipmi", IPAddress: "192.0.2.1", BMCType: model.BMCGeneric, IPMIUser: "admin", IPMIPassword: "pw", Status: "Unknown"}
		if err := st.CreateServer(s); err != nil {
			t.Fatalf("CreateServer: %v", err)
		}
		return s
	}

	for _, tc := range []struct{ command, ipmi, status string }{
		{"power on", "power on", "On"},
		{"power off", "power off", "Off"},
		{"reset", "power reset", "On"},
		{"power cycle", "power cycle", "On"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			s := newIPMIServer()
			ok, msg := c.Send(t.Context(), s, tc.command)
			want := strings.Join(ipmiArgs(s, strings.Fields(tc.ipmi)...), " ")
			if !ok || msg != want {
				t.Errorf("Send = %v, %q; want true, %q", ok, msg, want)
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
	for _, cmd := range []string{"bogus", ""} {
		s := newIPMIServer()
		if ok, msg := c.Send(t.Context(), s, cmd); ok || msg != "Invalid command" {
			t.Errorf("Send(%q) = %v, %q; want false, %q", cmd, ok, msg, "Invalid command")
		}
		if s.Status != "Unknown" {
			t.Errorf("Send(%q) changed status to %q", cmd, s.Status)
		}
	}
}

// TestSendWithoutBMC pins what Send and CheckStatus do for servers with no BMC
// to talk to (a MAC address only, or nothing at all): the missing-credential
// messages, Wake-on-LAN's power-on-only rule and its WOL_ENABLED gate, and the
// cached status. The WoL send is stubbed, so nothing here touches the network.
func TestSendWithoutBMC(t *testing.T) {
	const (
		mac     = "aa:bb:cc:dd:ee:ff"
		wolOnly = "No authentication credentials configured (Wake-on-LAN only supports power on)"
	)
	c, st := newWoLController(t, func([]byte, string, int) error { return nil })
	for _, tc := range []struct {
		name, mac, command string
		wolDisabled        bool
		wantOK             bool
		wantMsg            string
	}{
		{"no creds, power on", "", "power on", false, false, "No authentication credentials or MAC address configured"},
		{"no creds, power off", "", "power off", false, false, wolOnly},
		{"no creds, unknown command", "", "bogus", false, false, wolOnly},
		{"mac only, power off", mac, "power off", false, false, wolOnly},
		{"mac only, power cycle", mac, "power cycle", false, false, wolOnly},
		{"mac only, reset", mac, "reset", false, false, wolOnly},
		{"mac only, power on", mac, "power on", false, true, "Wake-on-LAN packets sent to " + mac + " on ports 7 and 9 (check logs for details)"},
		{"mac only, power on, WoL disabled", mac, "power on", true, false, "Wake-on-LAN is disabled. Set WOL_ENABLED=true to enable it (see README)."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c.wolEnabled = !tc.wolDisabled
			s := &model.Server{Name: "x", IPAddress: "192.0.2.20", MACAddress: tc.mac, BMCType: model.BMCGeneric, Status: "Off"}
			if err := st.CreateServer(s); err != nil {
				t.Fatalf("CreateServer: %v", err)
			}
			// Neither can read a power state, so CheckStatus hands back the cache.
			if got := c.CheckStatus(t.Context(), s); got != "Off" || !s.LastUpdated.IsZero() {
				t.Errorf("CheckStatus = %q (touched: %v), want cached Off untouched", got, !s.LastUpdated.IsZero())
			}
			ok, msg := c.Send(t.Context(), s, tc.command)
			if ok != tc.wantOK || msg != tc.wantMsg {
				t.Errorf("Send(%q) = %v, %q; want %v, %q", tc.command, ok, msg, tc.wantOK, tc.wantMsg)
			}
			// Only a sent magic packet changes the (optimistic) status.
			wantStatus := "Off"
			if tc.wantOK {
				wantStatus = "On"
			}
			if s.Status != wantStatus {
				t.Errorf("status = %q, want %q", s.Status, wantStatus)
			}
		})
	}
}

func TestProtocolFor(t *testing.T) {
	const mac = "aa:bb:cc:dd:ee:ff"
	for _, tc := range []struct {
		name string
		s    model.Server
		want Protocol // spelled as strings so the names themselves are pinned
	}{
		{"pikvm beats redfish creds", model.Server{BMCType: model.BMCPiKVM, RedfishUser: "admin", IPMIUser: "ipmi", MACAddress: mac}, "pikvm"},
		{"pikvm without creds never falls through", model.Server{BMCType: model.BMCPiKVM, MACAddress: mac}, "pikvm"},
		{"redfish beats ipmi and mac", model.Server{BMCType: model.BMCIDRAC, RedfishUser: "root", IPMIUser: "ipmi", MACAddress: mac}, "redfish"},
		{"ipmi beats mac", model.Server{BMCType: model.BMCGeneric, IPMIUser: "ipmi", MACAddress: mac}, "ipmi"},
		{"mac only", model.Server{BMCType: model.BMCGeneric, MACAddress: mac}, "wake-on-lan"},
		{"nothing", model.Server{BMCType: model.BMCGeneric}, "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProtocolFor(&tc.s); got != tc.want {
				t.Errorf("ProtocolFor = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCheckAll(t *testing.T) {
	c, st := newWoLController(t, nil)

	// More servers than checkAllConcurrency, so the loop has to wait for a free
	// slot. Each fake BMC reports its own state, so a result written to the wrong
	// server (or not at all) shows up.
	const n = checkAllConcurrency + 4
	servers := make([]*model.Server, 0, n+1)
	want := map[int64]string{}
	for i := range n {
		state := "On"
		if i%2 == 1 {
			state = "Off"
		}
		s := addRedfishBMC(t, st, "rf"+strconv.Itoa(i), func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/redfish/v1/Systems/System.Embedded.1/" {
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			}
			_, _ = w.Write([]byte(`{"PowerState":"` + state + `"}`))
		})
		servers = append(servers, s)
		want[s.ID] = state
	}
	// No credentials: nothing to query, so it must keep its cached status.
	idle := &model.Server{Name: "idle", IPAddress: "192.0.2.30", BMCType: model.BMCGeneric, Status: "Off"}
	if err := st.CreateServer(idle); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	servers = append(servers, idle)
	want[idle.ID] = "Off"

	c.CheckAll(t.Context(), servers)

	for _, s := range servers {
		persisted, err := st.GetServer(s.ID)
		if err != nil {
			t.Fatal(err)
		}
		if s.Status != want[s.ID] || persisted.Status != want[s.ID] {
			t.Errorf("%s: status mem=%q db=%q, want %q", s.Name, s.Status, persisted.Status, want[s.ID])
		}
		// Only a server that was actually queried gets a fresh timestamp.
		if stamped, wantStamped := !s.LastUpdated.IsZero(), s != idle; stamped != wantStamped {
			t.Errorf("%s: LastUpdated set = %v, want %v", s.Name, stamped, wantStamped)
		}
	}
}

// allowTestHost lets the BMC URL builders take an httptest "host:port" address,
// which BMCHost (IP literals only) rightly refuses.
func allowTestHost(t *testing.T) {
	t.Helper()
	old := bmcHost
	bmcHost = func(s *model.Server) (string, bool) { return s.IPAddress, true }
	t.Cleanup(func() { bmcHost = old })
}

func TestBMCTextTruncatesAndStrips(t *testing.T) {
	long := strings.Repeat("é", 150) // 300 bytes
	got := bmcText("a\x00b\x1b[31m\nc" + long)
	if len(got) > maxBMCText || !utf8.ValidString(got) {
		t.Errorf("len=%d valid=%v", len(got), utf8.ValidString(got))
	}
	if strings.ContainsAny(got, "\x00\x1b\n") || !strings.HasPrefix(got, "ab[31mc") {
		t.Errorf("control chars survived: %q", got)
	}
}

func TestCappedBufferDiscardsExcessWithoutError(t *testing.T) {
	var b cappedBuffer
	chunk := bytes.Repeat([]byte("x"), 40<<10)
	for range 3 {
		if n, err := b.Write(chunk); n != len(chunk) || err != nil {
			t.Fatalf("Write = %d, %v; want full success", n, err)
		}
	}
	if len(b.String()) != maxOutputBytes {
		t.Errorf("kept %d bytes, want %d", len(b.String()), maxOutputBytes)
	}
}

func TestPiKVMErrorTextIsSanitized(t *testing.T) {
	c, s, _ := newPiKVM(t, "admin", "", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"result":{"error":"E","error_msg":"` + strings.Repeat("z", 5000) + `\u001b[2J"}}`))
	})
	ok, msg := c.Send(t.Context(), s, "power on")
	if ok || len(msg) > 300 || strings.ContainsRune(msg, 0x1b) {
		t.Errorf("Send = %v, %d bytes %q", ok, len(msg), msg)
	}
}

func TestRedfishPowerStateWhitelist(t *testing.T) {
	for state, want := range map[string]string{
		"On": "On", "Off": "Off", "PoweringOn": "PoweringOn", "PoweringOff": "PoweringOff", "Paused": "Paused",
		"<script>x</script>": "Unknown", "on": "Unknown", "": "Unknown",
	} {
		c, s, _ := redfishFixture(t, func(w http.ResponseWriter, _ *http.Request) {
			b, _ := json.Marshal(map[string]string{"PowerState": state})
			_, _ = w.Write(b)
		})
		if got := c.CheckStatus(t.Context(), s); got != want {
			t.Errorf("PowerState %q -> %q, want %q", state, got, want)
		}
	}
}

func TestInvalidAddressNoNetwork(t *testing.T) {
	// No allowTestHost: the real BMCHost applies. A host:port value is not an IP.
	hit := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	t.Cleanup(srv.Close)
	c, st := newWoLController(t, nil)
	for _, s := range []*model.Server{
		{Name: "rf", IPAddress: strings.TrimPrefix(srv.URL, "https://"), RedfishUser: "r", RedfishPassword: "p", Status: "Off"},
		{Name: "pk", IPAddress: strings.TrimPrefix(srv.URL, "https://"), BMCType: model.BMCPiKVM, RedfishUser: "r", RedfishPassword: "p", Status: "Off"},
		{Name: "ip", IPAddress: "-oProxyCommand=x", IPMIUser: "u", IPMIPassword: "p", Status: "Off"},
	} {
		if err := st.CreateServer(s); err != nil {
			t.Fatal(err)
		}
		if ok, msg := c.Send(t.Context(), s, "power on"); ok || msg != errBadAddress {
			t.Errorf("%s Send = %v, %q", s.Name, ok, msg)
		}
		if got := c.CheckStatus(t.Context(), s); got != "Off" {
			t.Errorf("%s CheckStatus = %q, want cached Off", s.Name, got)
		}
	}
	if hit {
		t.Error("an invalid address reached the network")
	}
}

func TestBMCHostBracketsIPv6(t *testing.T) {
	if h, ok := (&model.Server{IPAddress: "::1"}).BMCHost(); !ok || h != "[::1]" {
		t.Errorf("BMCHost = %q, %v", h, ok)
	}
}

func TestUnreadableCredentialsNoContact(t *testing.T) {
	hit := false
	c, s, _ := newPiKVM(t, "admin", "", func(w http.ResponseWriter, _ *http.Request) { hit = true; okJSON(w, nil) })
	rf, rs, _ := redfishFixture(t, func(w http.ResponseWriter, _ *http.Request) { hit = true })
	ip := &model.Server{Name: "i", IPAddress: "192.0.2.1", IPMIUser: "u", Status: "Off"}
	for _, tc := range []struct {
		c *Controller
		s *model.Server
	}{{c, s}, {rf, rs}, {c, ip}} {
		tc.s.CredentialsUnreadable = true
		tc.s.Status = "Off"
		tc.s.LastUpdated = time.Time{}
		if ok, msg := tc.c.Send(t.Context(), tc.s, "power on"); ok || !strings.Contains(msg, "can't be decrypted") {
			t.Errorf("%s Send = %v, %q", tc.s.Name, ok, msg)
		}
		if got := tc.c.CheckStatus(t.Context(), tc.s); got != "Off" || !tc.s.LastUpdated.IsZero() {
			t.Errorf("%s CheckStatus = %q, LastUpdated %v", tc.s.Name, got, tc.s.LastUpdated)
		}
	}
	if hit {
		t.Error("BMC contacted with unreadable credentials")
	}
}
