package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pkilar/lab-manager/internal/model"
	"github.com/pkilar/lab-manager/internal/power"
	"github.com/pkilar/lab-manager/internal/store"
)

// The real store and controller must satisfy the interfaces New takes; this
// breaks the build, rather than the wiring step, if either drifts.
var (
	_ Store = (*store.Store)(nil)
	_ Power = (*power.Controller)(nil)
)

const testToken = "test-token-3f9c1d7a5b"

// Distinctive credential strings seeded into the fake inventory. None of them
// may ever appear in a response.
const (
	secretRedfishUser = "rf-user-Zk3J2"
	secretRedfishPass = "rf-pass-Q9x7V"
	secretIPMIUser    = "ipmi-user-M4w8L"
	secretIPMIPass    = "ipmi-pass-T2z5N"
	secretMAC         = "de:ad:be:ef:00:01"
)

var secrets = []string{secretRedfishUser, secretRedfishPass, secretIPMIUser, secretIPMIPass, secretMAC}

// lastRead is the recorded LastUpdated of the seeded servers. A live read in
// fakePower stamps the current time, which is always later.
var lastRead = time.Date(2026, 10, 1, 12, 30, 0, 0, time.UTC)

// seedServers is the fake inventory, one server per power-control path. The
// addresses are RFC 5737 documentation addresses: the fakes never dial, and if
// anything ever did, it could not reach a real lab device.
func seedServers() []*model.Server {
	return []*model.Server{
		{ID: 1, Name: "dell-r640", IPAddress: "192.0.2.11", BMCType: model.BMCIDRAC,
			RedfishUser: secretRedfishUser, RedfishPassword: secretRedfishPass,
			Status: "Off", LastUpdated: lastRead, Notes: "rack 1, top shelf"},
		// A PiKVM with Redfish credentials set must still report pikvm.
		{ID: 2, Name: "pikvm-bench", IPAddress: "192.0.2.12", BMCType: model.BMCPiKVM,
			RedfishUser: secretRedfishUser, RedfishPassword: secretRedfishPass,
			Status: "On", LastUpdated: lastRead},
		{ID: 3, Name: "supermicro-nas", IPAddress: "192.0.2.13", BMCType: model.BMCSupermicro,
			IPMIUser: secretIPMIUser, IPMIPassword: secretIPMIPass, SOLInstance: 3,
			Status: "On", LastUpdated: lastRead},
		{ID: 4, Name: "wol-desktop", IPAddress: "192.0.2.14", BMCType: model.BMCGeneric,
			MACAddress: secretMAC, Status: "Off", LastUpdated: lastRead},
		{ID: 5, Name: "bare-box", IPAddress: "192.0.2.15", BMCType: model.BMCGeneric, Status: "Off"},
	}
}

// fakeStore serves a fixed inventory. Like the real store it returns fresh
// copies per call (the tools mutate them) and a nil slice when empty.
type fakeStore struct {
	mu      sync.Mutex
	servers []*model.Server
	err     error
}

func (f *fakeStore) AllServers() ([]*model.Server, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	var out []*model.Server
	for _, s := range f.servers {
		c := *s
		out = append(out, &c)
	}
	return out, nil
}

func (f *fakeStore) GetServer(id int64) (*model.Server, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	for _, s := range f.servers {
		if s.ID == id {
			c := *s
			return &c, nil
		}
	}
	return nil, store.ErrNotFound
}

func (f *fakeStore) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

type sendCall struct {
	ServerID int64
	Command  string
}

type sendResult struct {
	ok  bool
	msg string
}

// fakePower records every command and models a BMC that is readable for some
// servers only. It never dials anything.
type fakePower struct {
	mu        sync.Mutex
	sends     []sendCall
	checks    []int64
	results   map[int64]sendResult                       // scripted Send outcomes; success by default
	reachable map[int64]string                           // server id -> status its BMC reports; absent = unreadable
	panicOn   map[int64]bool                             // Send panics for these servers
	onCall    func(ctx context.Context, s *model.Server) // runs first in Send and CheckStatus
}

func (f *fakePower) Send(ctx context.Context, s *model.Server, command string) (bool, string) {
	f.mu.Lock()
	f.sends = append(f.sends, sendCall{s.ID, command})
	boom := f.panicOn[s.ID]
	res, scripted := f.results[s.ID]
	hook := f.onCall
	f.mu.Unlock()

	if hook != nil {
		hook(ctx, s)
	}
	if boom {
		panic("fake BMC exploded")
	}
	if scripted {
		return res.ok, res.msg
	}
	return true, "fake accepted " + command
}

// CheckStatus mimics the controller: a readable BMC updates Status and stamps
// LastUpdated in place; an unreadable one leaves the server, and so the cached
// status, untouched.
func (f *fakePower) CheckStatus(ctx context.Context, s *model.Server) string {
	f.mu.Lock()
	f.checks = append(f.checks, s.ID)
	status, live := f.reachable[s.ID]
	hook := f.onCall
	f.mu.Unlock()

	if hook != nil {
		hook(ctx, s)
	}
	if live {
		s.Status = status
		s.LastUpdated = time.Now().UTC()
	}
	return s.Status
}

func (f *fakePower) CheckAll(ctx context.Context, servers []*model.Server) {
	for _, s := range servers {
		f.CheckStatus(ctx, s)
	}
}

func (f *fakePower) setResult(id int64, ok bool, msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.results == nil {
		f.results = map[int64]sendResult{}
	}
	f.results[id] = sendResult{ok, msg}
}

func (f *fakePower) setPanic(id int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.panicOn == nil {
		f.panicOn = map[int64]bool{}
	}
	f.panicOn[id] = true
}

func (f *fakePower) setHook(fn func(ctx context.Context, s *model.Server)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onCall = fn
}

func (f *fakePower) sent() []sendCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.sends)
}

func (f *fakePower) checked() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.checks)
}

// fixture is a served handler over the fakes.
type fixture struct {
	ts *httptest.Server
	st *fakeStore
	pw *fakePower
}

// newFixture serves New over the seeded inventory. The BMCs of servers 1 and 2
// are readable and report a different state than the cached one, so a live
// reading is distinguishable from a stale one; the others cannot be read.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWith(t, seedServers())
}

func newFixtureWith(t *testing.T, servers []*model.Server) *fixture {
	t.Helper()
	st := &fakeStore{servers: servers}
	pw := &fakePower{reachable: map[int64]string{1: "On", 2: "Off"}}
	ts := httptest.NewServer(New(st, pw, testToken))
	t.Cleanup(ts.Close)
	return &fixture{ts: ts, st: st, pw: pw}
}

// bearerTransport adds the bearer token to every request.
type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

// connect opens an SDK client session; version "" selects the SDK's default
// (2026-07-28, the server/discover flow).
func (fx *fixture) connect(t *testing.T, version string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   fx.ts.URL,
		HTTPClient: &http.Client{Transport: bearerTransport{testToken, fx.ts.Client().Transport}},
	}, &mcp.ClientSessionOptions{ProtocolVersion: version})
	if err != nil {
		t.Fatalf("connect (protocol %q): %v", version, err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// forEachProtocol runs f against both the default (2026-07-28) and a legacy
// protocol version, which take different paths through the SDK.
func forEachProtocol(t *testing.T, f func(t *testing.T, version string)) {
	t.Helper()
	for _, pv := range []struct{ name, version string }{
		{"2026-07-28", ""},
		{"2025-06-18", "2025-06-18"},
	} {
		t.Run(pv.name, func(t *testing.T) { f(t, pv.version) })
	}
}

func call(t *testing.T, s *mcp.ClientSession, tool string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", tool, err)
	}
	return res
}

func resultText(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// decode unmarshals a successful result's structured output into out. Unknown
// fields fail the test, so a field nobody meant to expose cannot slip in.
func decode(t *testing.T, res *mcp.CallToolResult, out any) {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool error: %s", resultText(res))
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		t.Fatalf("decode structured output %s: %v", raw, err)
	}
}

func wantToolError(t *testing.T, res *mcp.CallToolResult, contains ...string) {
	t.Helper()
	if !res.IsError {
		t.Fatalf("expected a tool error, got %s", resultText(res))
	}
	text := resultText(res)
	for _, want := range contains {
		if !strings.Contains(text, want) {
			t.Errorf("error text %q does not contain %q", text, want)
		}
	}
}

// hint renders a tri-state annotation: nil means the server left it unset.
func hint(p *bool) string {
	switch {
	case p == nil:
		return "unset"
	case *p:
		return "true"
	default:
		return "false"
	}
}

func TestInitialize(t *testing.T) {
	forEachProtocol(t, func(t *testing.T, version string) {
		res := newFixture(t).connect(t, version).InitializeResult()
		if res == nil {
			t.Fatal("no initialize result")
		}
		if res.Instructions != instructions {
			t.Errorf("instructions = %q", res.Instructions)
		}
		if info := res.ServerInfo; info == nil || info.Name != "lab-manager" || info.Title != "Lab Manager" || info.Version != buildVersion() {
			t.Errorf("server info = %+v", info)
		}
		caps := res.Capabilities
		if caps == nil || caps.Tools == nil {
			t.Fatalf("capabilities = %+v, want tools", caps)
		}
		// listChanged and logging would make a 2026-07-28 client park a
		// subscriptions/listen stream against a server that never changes.
		// Logging is deprecated in the SDK, so look at the wire form.
		wire, err := json.Marshal(caps)
		if err != nil {
			t.Fatal(err)
		}
		if caps.Tools.ListChanged || strings.Contains(string(wire), `"logging"`) {
			t.Errorf("capabilities = %s, want tools without listChanged and no logging", wire)
		}
	})
}

func TestListTools(t *testing.T) {
	type want struct {
		title       string
		readOnly    bool
		destructive string // hint(): the annotation is a tri-state pointer
		idempotent  bool
		openWorld   string
		perServer   bool // takes server_id
	}
	wants := map[string]want{
		"list_servers":           {title: "List servers", readOnly: true, destructive: "unset", openWorld: "false"},
		"check_power_status":     {title: "Check power status", readOnly: true, destructive: "unset", openWorld: "true", perServer: true},
		"check_all_power_status": {title: "Check all power statuses", readOnly: true, destructive: "unset", openWorld: "true"},
		"power_on":               {title: "Power on server", destructive: "false", idempotent: true, openWorld: "true", perServer: true},
		"power_off":              {title: "Power off server", destructive: "true", idempotent: true, openWorld: "true", perServer: true},
		"power_cycle":            {title: "Power-cycle server", destructive: "true", openWorld: "true", perServer: true},
	}

	forEachProtocol(t, func(t *testing.T, version string) {
		session := newFixture(t).connect(t, version)
		res, err := session.ListTools(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}

		if len(res.Tools) != len(wants) {
			t.Errorf("%d tools, want %d", len(res.Tools), len(wants))
		}
		for _, tool := range res.Tools {
			w, ok := wants[tool.Name]
			if !ok {
				t.Errorf("unexpected tool %q", tool.Name)
				continue
			}
			t.Run(tool.Name, func(t *testing.T) {
				if tool.Title != w.title {
					t.Errorf("title = %q, want %q", tool.Title, w.title)
				}
				if tool.Description == "" {
					t.Error("no description")
				}
				if tool.OutputSchema == nil {
					t.Error("no output schema")
				}
				a := tool.Annotations
				if a == nil {
					t.Fatal("no annotations")
				}
				if a.ReadOnlyHint != w.readOnly {
					t.Errorf("readOnlyHint = %v, want %v", a.ReadOnlyHint, w.readOnly)
				}
				if got := hint(a.DestructiveHint); got != w.destructive {
					t.Errorf("destructiveHint = %s, want %s", got, w.destructive)
				}
				if a.IdempotentHint != w.idempotent {
					t.Errorf("idempotentHint = %v, want %v", a.IdempotentHint, w.idempotent)
				}
				if got := hint(a.OpenWorldHint); got != w.openWorld {
					t.Errorf("openWorldHint = %s, want %s", got, w.openWorld)
				}

				in, _ := tool.InputSchema.(map[string]any)
				required, _ := in["required"].([]any)
				props, _ := in["properties"].(map[string]any)
				if w.perServer {
					if len(required) != 1 || required[0] != "server_id" {
						t.Errorf("required = %v, want [server_id]", required)
					}
					id, _ := props["server_id"].(map[string]any)
					if id["type"] != "integer" || id["description"] == "" {
						t.Errorf("server_id schema = %v", id)
					}
				} else if len(required) != 0 || len(props) != 0 {
					t.Errorf("input schema takes arguments: %v", in)
				}
				if in["additionalProperties"] != false {
					t.Errorf("additionalProperties = %v, want false", in["additionalProperties"])
				}
			})
		}
	})
}

func TestListServers(t *testing.T) {
	stamp := lastRead.Format(time.RFC3339)
	want := []serverInfo{
		{ID: 1, Name: "dell-r640", IPAddress: "192.0.2.11", BMCType: "idrac", PowerControl: "redfish", Status: "Off", LastUpdated: stamp, Notes: "rack 1, top shelf"},
		{ID: 2, Name: "pikvm-bench", IPAddress: "192.0.2.12", BMCType: "pikvm", PowerControl: "pikvm", Status: "On", LastUpdated: stamp},
		{ID: 3, Name: "supermicro-nas", IPAddress: "192.0.2.13", BMCType: "supermicro", PowerControl: "ipmi", Status: "On", LastUpdated: stamp},
		{ID: 4, Name: "wol-desktop", IPAddress: "192.0.2.14", BMCType: "generic", PowerControl: "wake-on-lan", Status: "Off", LastUpdated: stamp},
		{ID: 5, Name: "bare-box", IPAddress: "192.0.2.15", BMCType: "generic", PowerControl: "none", Status: "Off"},
	}

	forEachProtocol(t, func(t *testing.T, version string) {
		fx := newFixture(t)
		var got serverList
		decode(t, call(t, fx.connect(t, version), "list_servers", nil), &got)

		if !slices.Equal(got.Servers, want) {
			t.Errorf("servers =\n%+v\nwant\n%+v", got.Servers, want)
		}
		// Reading the inventory must not contact a single BMC.
		if len(fx.pw.checked()) != 0 || len(fx.pw.sent()) != 0 {
			t.Errorf("list_servers touched the BMC layer: checks %v, sends %v", fx.pw.checked(), fx.pw.sent())
		}
	})
}

// The real store returns a nil slice for an empty inventory; the output must
// still be [] rather than null.
func TestEmptyInventory(t *testing.T) {
	forEachProtocol(t, func(t *testing.T, version string) {
		session := newFixtureWith(t, nil).connect(t, version)
		for _, tool := range []string{"list_servers", "check_all_power_status"} {
			res := call(t, session, tool, nil)
			if res.IsError {
				t.Fatalf("%s: %s", tool, resultText(res))
			}
			out, _ := res.StructuredContent.(map[string]any)
			servers, ok := out["servers"].([]any)
			if !ok || servers == nil || len(servers) != 0 {
				t.Errorf("%s: servers = %#v, want an empty array", tool, out["servers"])
			}
		}
	})
}

func TestCheckPowerStatus(t *testing.T) {
	stamp := lastRead.Format(time.RFC3339)
	tests := []struct {
		name        string
		id          int64
		status      string
		live        bool
		lastUpdated string // "" = absent, "now" = a fresh timestamp
	}{
		{"readable redfish BMC", 1, "On", true, "now"},
		{"readable pikvm", 2, "Off", true, "now"},
		{"unreadable ipmi BMC keeps its cached status", 3, "On", false, stamp},
		{"wake-on-lan has no state to read", 4, "Off", false, stamp},
		{"no power control, never updated", 5, "Off", false, ""},
	}

	forEachProtocol(t, func(t *testing.T, version string) {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fx := newFixture(t)
				var got serverStatus
				decode(t, call(t, fx.connect(t, version), "check_power_status", map[string]any{"server_id": tt.id}), &got)

				if got.ID != tt.id || got.Status != tt.status || got.Live != tt.live {
					t.Errorf("got %+v, want id %d status %q live %v", got, tt.id, tt.status, tt.live)
				}
				if tt.lastUpdated == "now" {
					if !isFresh(got.LastUpdated) {
						t.Errorf("last_updated = %q, want a fresh RFC 3339 timestamp", got.LastUpdated)
					}
				} else if got.LastUpdated != tt.lastUpdated {
					t.Errorf("last_updated = %q, want %q", got.LastUpdated, tt.lastUpdated)
				}
				if c := fx.pw.checked(); !slices.Equal(c, []int64{tt.id}) {
					t.Errorf("checked servers = %v, want only %d", c, tt.id)
				}
			})
		}
	})
}

func TestCheckAllPowerStatus(t *testing.T) {
	stamp := lastRead.Format(time.RFC3339)
	want := []serverStatus{
		{ID: 1, Name: "dell-r640", Status: "On", Live: true},
		{ID: 2, Name: "pikvm-bench", Status: "Off", Live: true},
		{ID: 3, Name: "supermicro-nas", Status: "On", LastUpdated: stamp},
		{ID: 4, Name: "wol-desktop", Status: "Off", LastUpdated: stamp},
		{ID: 5, Name: "bare-box", Status: "Off"},
	}

	forEachProtocol(t, func(t *testing.T, version string) {
		fx := newFixture(t)
		var got statusList
		decode(t, call(t, fx.connect(t, version), "check_all_power_status", nil), &got)

		// A live reading carries a timestamp that cannot be predicted: check it
		// is fresh, then blank it for the comparison.
		for i, s := range got.Servers {
			if s.Live {
				if !isFresh(s.LastUpdated) {
					t.Errorf("server %d: last_updated = %q, want a fresh RFC 3339 timestamp", s.ID, s.LastUpdated)
				}
				got.Servers[i].LastUpdated = ""
			}
		}
		if !slices.Equal(got.Servers, want) {
			t.Errorf("readings =\n%+v\nwant\n%+v", got.Servers, want)
		}
		if c := fx.pw.checked(); !slices.Equal(c, []int64{1, 2, 3, 4, 5}) {
			t.Errorf("checked servers = %v, want all five", c)
		}
	})
}

// isFresh reports whether stamp is an RFC 3339 time from just now rather than
// the seeded lastRead.
func isFresh(stamp string) bool {
	at, err := time.Parse(time.RFC3339, stamp)
	return err == nil && at.After(lastRead) && time.Since(at) < time.Minute
}

func TestPowerCommands(t *testing.T) {
	tests := []struct {
		tool, command, name string
		id                  int64
	}{
		{"power_on", "power on", "wol-desktop", 4},
		{"power_off", "power off", "supermicro-nas", 3},
		{"power_cycle", "power cycle", "dell-r640", 1},
	}

	forEachProtocol(t, func(t *testing.T, version string) {
		for _, tt := range tests {
			t.Run(tt.tool, func(t *testing.T) {
				fx := newFixture(t)
				var got powerResult
				decode(t, call(t, fx.connect(t, version), tt.tool, map[string]any{"server_id": tt.id}), &got)

				want := powerResult{ID: tt.id, Name: tt.name, Action: tt.tool, Message: "fake accepted " + tt.command}
				if got != want {
					t.Errorf("result = %+v, want %+v", got, want)
				}
				if sent := fx.pw.sent(); !slices.Equal(sent, []sendCall{{tt.id, tt.command}}) {
					t.Errorf("sent = %+v, want exactly {%d %q}", sent, tt.id, tt.command)
				}
			})
		}
	})
}

func TestPowerCommandOutcomes(t *testing.T) {
	tests := []struct {
		name    string
		tool    string
		ok      bool
		msg     string
		wantErr string // full error text; "" for success
		wantMsg string
	}{
		{"refused", "power_off", false, "Power off failed: HTTP 503", "power_off failed for supermicro-nas: Power off failed: HTTP 503", ""},
		{"ipmitool output ends in a newline", "power_cycle", false, "Unable to establish session\n", "power_cycle failed for supermicro-nas: Unable to establish session", ""},
		{"ipmitool can fail with no output", "power_on", false, "", "power_on failed for supermicro-nas: the BMC gave no details", ""},
		{"success message is trimmed", "power_on", true, "Chassis Power Control: Up/On\n", "", "Chassis Power Control: Up/On"},
	}

	forEachProtocol(t, func(t *testing.T, version string) {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				fx := newFixture(t)
				fx.pw.setResult(3, tt.ok, tt.msg)
				res := call(t, fx.connect(t, version), tt.tool, map[string]any{"server_id": 3})

				if tt.wantErr != "" {
					wantToolError(t, res)
					if text := resultText(res); text != tt.wantErr {
						t.Errorf("error = %q, want %q", text, tt.wantErr)
					}
					if res.StructuredContent != nil {
						t.Errorf("a failed command carried structured output: %v", res.StructuredContent)
					}
					return
				}
				var got powerResult
				decode(t, res, &got)
				if got.Message != tt.wantMsg {
					t.Errorf("message = %q, want %q", got.Message, tt.wantMsg)
				}
			})
		}
	})
}

func TestUnknownServer(t *testing.T) {
	forEachProtocol(t, func(t *testing.T, version string) {
		fx := newFixture(t)
		session := fx.connect(t, version)
		for _, tool := range []string{"check_power_status", "power_on", "power_off", "power_cycle"} {
			t.Run(tool, func(t *testing.T) {
				wantToolError(t, call(t, session, tool, map[string]any{"server_id": 99}),
					"no server with id 99", "list_servers")
			})
		}
		if len(fx.pw.sent()) != 0 || len(fx.pw.checked()) != 0 {
			t.Errorf("a missing server still reached the BMC layer: sends %v, checks %v", fx.pw.sent(), fx.pw.checked())
		}
	})
}

// A store failure is logged but never described to the agent.
func TestInventoryErrorIsGeneric(t *testing.T) {
	forEachProtocol(t, func(t *testing.T, version string) {
		fx := newFixture(t)
		session := fx.connect(t, version)
		fx.st.fail(errors.New("sqlite: disk I/O error reading /srv/instance/servers.db"))

		for _, tool := range []string{"list_servers", "check_all_power_status", "check_power_status", "power_on", "power_off", "power_cycle"} {
			t.Run(tool, func(t *testing.T) {
				args := map[string]any{"server_id": 1}
				if tool == "list_servers" || tool == "check_all_power_status" {
					args = nil
				}
				res := call(t, session, tool, args)
				wantToolError(t, res)
				if text := resultText(res); text != "could not read the server inventory" {
					t.Errorf("error = %q", text)
				}
			})
		}
		if len(fx.pw.sent()) != 0 || len(fx.pw.checked()) != 0 {
			t.Errorf("a store failure still reached the BMC layer: sends %v, checks %v", fx.pw.sent(), fx.pw.checked())
		}
	})
}

// The input schema is the only thing between a sloppy argument and a power
// command: a missing id must not default to a server, and an argument the
// tools do not take (a "force" flag, say) must be refused rather than ignored.
func TestInvalidArgumentsRunNothing(t *testing.T) {
	tests := []struct {
		name string
		args map[string]any
	}{
		{"missing server_id", map[string]any{}},
		{"string server_id", map[string]any{"server_id": "1"}},
		{"fractional server_id", map[string]any{"server_id": 1.5}},
		{"unknown argument", map[string]any{"server_id": 1, "force": true}},
	}

	forEachProtocol(t, func(t *testing.T, version string) {
		fx := newFixture(t)
		session := fx.connect(t, version)
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				for _, tool := range []string{"power_on", "power_off", "power_cycle", "check_power_status"} {
					wantToolError(t, call(t, session, tool, tt.args))
				}
			})
		}
		if len(fx.pw.sent()) != 0 || len(fx.pw.checked()) != 0 {
			t.Errorf("invalid arguments still reached the BMC layer: sends %v, checks %v", fx.pw.sent(), fx.pw.checked())
		}
	})
}

// Tool handlers run on SDK goroutines, so an unrecovered panic would kill the
// whole test binary (and, in production, the web UI with it).
func TestToolPanicIsRecovered(t *testing.T) {
	forEachProtocol(t, func(t *testing.T, version string) {
		fx := newFixture(t)
		fx.pw.setPanic(2)
		session := fx.connect(t, version)

		res := call(t, session, "power_off", map[string]any{"server_id": 2})
		wantToolError(t, res, "internal error")
		if text := resultText(res); strings.Contains(text, "exploded") {
			t.Errorf("panic value leaked to the client: %q", text)
		}

		// The server keeps serving afterwards.
		var list serverList
		decode(t, call(t, session, "list_servers", nil), &list)
		if len(list.Servers) != 5 {
			t.Errorf("list_servers after the panic returned %d servers", len(list.Servers))
		}
		var off powerResult
		decode(t, call(t, session, "power_off", map[string]any{"server_id": 1}), &off)
		if off.ID != 1 {
			t.Errorf("power_off after the panic = %+v", off)
		}
	})
}

func TestRecoverPanicsOtherMethods(t *testing.T) {
	boom := recoverPanics(func(context.Context, string, mcp.Request) (mcp.Result, error) { panic("boom") })

	res, err := boom(t.Context(), "tools/list", nil)
	var wire *jsonrpc.Error
	if res != nil || !errors.As(err, &wire) || wire.Code != jsonrpc.CodeInternalError || wire.Message != "internal error" {
		t.Errorf("tools/list panic = (%v, %v), want a JSON-RPC internal error", res, err)
	}

	res, err = boom(t.Context(), "tools/call", nil)
	if tool, ok := res.(*mcp.CallToolResult); err != nil || !ok || !tool.IsError || resultText(tool) != "internal error" {
		t.Errorf("tools/call panic = (%v, %v), want an isError tool result", res, err)
	}
}

// With the 2026-07-28 protocol a client that gives up cancels the handler's
// context, so the BMC call is abandoned rather than left to run to its timeout.
// That only works if every tool hands that context to the power layer.
func TestClientCancellationReachesPower(t *testing.T) {
	byServer := map[string]any{"server_id": 1}
	tests := []struct {
		tool string
		args map[string]any
	}{
		{"check_power_status", byServer},
		{"check_all_power_status", nil},
		{"power_on", byServer},
		{"power_off", byServer},
		{"power_cycle", byServer},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			fx := newFixture(t)
			started := make(chan struct{})
			cancelled := make(chan struct{})
			release := make(chan struct{})
			var startedOnce, cancelledOnce sync.Once // check_all calls the hook once per server
			fx.pw.setHook(func(ctx context.Context, _ *model.Server) {
				startedOnce.Do(func() { close(started) })
				select {
				case <-ctx.Done():
					cancelledOnce.Do(func() { close(cancelled) })
				case <-release:
				}
			})
			// Registered after the server's own cleanup, so it runs first and a
			// failed test cannot leave ts.Close waiting on the blocked handler.
			t.Cleanup(func() { close(release) })

			session := fx.connect(t, "")
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = session.CallTool(ctx, &mcp.CallToolParams{Name: tt.tool, Arguments: tt.args})
			}()

			waitFor(t, started, "the tool to reach the power layer")
			cancel()
			waitFor(t, cancelled, "the power layer's context to be cancelled")
			waitFor(t, done, "the client call to return")
		})
	}
}

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestNewPanicsOnEmptyToken(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error(`New(..., "") did not panic: an empty token must never mean "no auth"`)
		}
	}()
	New(&fakeStore{}, &fakePower{}, "")
}

// rawPost sends body to the MCP endpoint without the SDK client. Headers in
// hdr override the defaults; an empty value removes the header.
func rawPost(t *testing.T, fx *fixture, hdr map[string]string, body string) (status int, header http.Header, respBody string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, fx.ts.URL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-06-18")
	req.Header.Set("Authorization", "Bearer "+testToken)
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := fx.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, resp.Header, string(b)
}

// powerOffBody is a request that would act on a server if it got through.
const powerOffBody = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"power_off","arguments":{"server_id":1}}}`

func TestBearerAuth(t *testing.T) {
	const realm = `Bearer realm="lab-manager"`
	tests := []struct {
		name          string
		authorization string
		status        int
		challenge     string
	}{
		{"no header", "", http.StatusUnauthorized, realm},
		{"wrong token", "Bearer not-the-token", http.StatusUnauthorized, realm + `, error="invalid_token"`},
		{"token prefix", "Bearer " + testToken[:len(testToken)-1], http.StatusUnauthorized, realm + `, error="invalid_token"`},
		{"token plus a suffix", "Bearer " + testToken + "x", http.StatusUnauthorized, realm + `, error="invalid_token"`},
		{"other scheme", "Basic dXNlcjpwYXNz", http.StatusUnauthorized, realm},
		{"token without scheme", testToken, http.StatusUnauthorized, realm},
		{"scheme without token", "Bearer", http.StatusUnauthorized, realm},
		{"empty token", "Bearer ", http.StatusUnauthorized, realm},
		{"valid", "Bearer " + testToken, http.StatusOK, ""},
		{"lowercase scheme", "bearer " + testToken, http.StatusOK, ""},
		{"uppercase scheme", "BEARER " + testToken, http.StatusOK, ""},
		{"extra spaces", "Bearer   " + testToken, http.StatusOK, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newFixture(t)
			status, header, body := rawPost(t, fx, map[string]string{"Authorization": tt.authorization}, powerOffBody)

			if status != tt.status {
				t.Fatalf("status = %d, want %d (body %q)", status, tt.status, body)
			}
			if got := header.Get("WWW-Authenticate"); got != tt.challenge {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tt.challenge)
			}
			// A rejected request must run no tool at all.
			wantSends := 0
			if tt.status == http.StatusOK {
				wantSends = 1
				if !strings.Contains(body, `"result"`) {
					t.Errorf("body %q has no JSON-RPC result", body)
				}
			}
			if n := len(fx.pw.sent()); n != wantSends {
				t.Errorf("%d power commands sent, want %d", n, wantSends)
			}
		})
	}
}

// A token, correct or not, must never be written to the log.
func TestUnauthorizedLogsNoToken(t *testing.T) {
	var logs syncBuffer
	oldLogger, oldWriter, oldFlags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() {
		// SetDefault also redirects the log package; put that back too.
		slog.SetDefault(oldLogger)
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
	})

	const wrong = "wrong-token-do-not-log-me"
	fx := newFixture(t)
	if status, _, _ := rawPost(t, fx, map[string]string{"Authorization": "Bearer " + wrong}, powerOffBody); status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", status)
	}

	out := logs.String()
	if !strings.Contains(out, "mcp unauthorized request") || !strings.Contains(out, "127.0.0.1") {
		t.Errorf("rejection not logged with the client address: %q", out)
	}
	for _, token := range []string{wrong, testToken} {
		if strings.Contains(out, token) {
			t.Errorf("log contains a bearer token: %q", out)
		}
	}
}

// syncBuffer is a bytes.Buffer safe for the server's goroutines to log into
// while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A browser's cross-site POST is turned away even with a valid token (a page
// the operator visits must not be able to drive the lab), while a CLI client,
// which sends neither header, is not affected.
func TestCrossOriginProtection(t *testing.T) {
	tests := []struct {
		name   string
		hdr    map[string]string
		status int
	}{
		{"no browser headers", nil, http.StatusOK},
		{"cross-site fetch", map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"foreign Origin alone", map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"cross-site Sec-Fetch-Site alone", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newFixture(t)
			status, _, body := rawPost(t, fx, tt.hdr, powerOffBody)
			if status != tt.status {
				t.Fatalf("status = %d, want %d (body %q)", status, tt.status, body)
			}
			wantSends := 0
			if tt.status == http.StatusOK {
				wantSends = 1
			}
			if n := len(fx.pw.sent()); n != wantSends {
				t.Errorf("%d power commands sent, want %d", n, wantSends)
			}
		})
	}
}

// The endpoint is POST-only: stateless mode has no stream to open or session
// to end. Authentication still comes first.
func TestOnlyPostIsServed(t *testing.T) {
	tests := []struct {
		method, auth string
		status       int
	}{
		{http.MethodGet, "Bearer " + testToken, http.StatusMethodNotAllowed},
		{http.MethodDelete, "Bearer " + testToken, http.StatusMethodNotAllowed},
		{http.MethodGet, "", http.StatusUnauthorized},
		{http.MethodDelete, "", http.StatusUnauthorized},
	}

	fx := newFixture(t)
	for _, tt := range tests {
		req, err := http.NewRequestWithContext(t.Context(), tt.method, fx.ts.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "application/json, text/event-stream")
		if tt.auth != "" {
			req.Header.Set("Authorization", tt.auth)
		}
		resp, err := fx.ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tt.status {
			t.Errorf("%s with auth %q: status = %d, want %d", tt.method, tt.auth, resp.StatusCode, tt.status)
		}
	}
}

// The responses an agent can obtain must contain no credential, MAC address or
// other field outside the documented set, whichever tool produced them.
func TestNoCredentialsInResponses(t *testing.T) {
	bodies := map[string]string{
		"list_servers":           `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_servers","arguments":{}}}`,
		"check_all_power_status": `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"check_all_power_status","arguments":{}}}`,
		"check_power_status":     `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check_power_status","arguments":{"server_id":1}}}`,
		"power_on":               `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"power_on","arguments":{"server_id":4}}}`,
		"tools/list":             `{"jsonrpc":"2.0","id":5,"method":"tools/list"}`,
	}
	allowed := []string{"servers", "id", "name", "ip_address", "bmc_type", "power_control", "status", "last_updated", "notes", "live", "action", "message"}

	fx := newFixture(t)
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			status, header, resp := rawPost(t, fx, nil, body)
			if status != http.StatusOK {
				t.Fatalf("status = %d, body %q", status, resp)
			}
			if ct := header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q, want a plain JSON response", ct)
			}
			for _, secret := range secrets {
				if strings.Contains(resp, secret) {
					t.Errorf("response contains %q:\n%s", secret, resp)
				}
			}

			var rpc struct {
				Result struct {
					StructuredContent any `json:"structuredContent"`
				} `json:"result"`
			}
			if err := json.Unmarshal([]byte(resp), &rpc); err != nil {
				t.Fatalf("response is not JSON-RPC: %v\n%s", err, resp)
			}
			for _, key := range jsonKeys(rpc.Result.StructuredContent) {
				if !slices.Contains(allowed, key) {
					t.Errorf("structured output carries undocumented field %q", key)
				}
			}
			// Not vacuous: the inventory really is in the response.
			if name == "list_servers" && !strings.Contains(resp, "supermicro-nas") {
				t.Errorf("list_servers response lacks the inventory:\n%s", resp)
			}
		})
	}
}

// jsonKeys returns every object key anywhere in a decoded JSON value.
func jsonKeys(v any) []string {
	var keys []string
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			keys = append(keys, k)
			keys = append(keys, jsonKeys(child)...)
		}
	case []any:
		for _, child := range v {
			keys = append(keys, jsonKeys(child)...)
		}
	}
	return keys
}

// blockingHook parks every power call until release is closed, counting how
// many are inside at once.
type blockingHook struct {
	inside, peak int
	mu           sync.Mutex
	entered      chan struct{}
	release      chan struct{}
	once         sync.Once
}

func (h *blockingHook) open() { h.once.Do(func() { close(h.release) }) }

func newBlockingHook(t *testing.T) *blockingHook {
	h := &blockingHook{entered: make(chan struct{}, 64), release: make(chan struct{})}
	// Registered after the server's own cleanup, so it runs first.
	t.Cleanup(h.open)
	return h
}

func (h *blockingHook) hook(ctx context.Context, _ *model.Server) {
	h.mu.Lock()
	h.inside++
	h.peak = max(h.peak, h.inside)
	h.mu.Unlock()
	h.entered <- struct{}{}
	select {
	case <-h.release:
	case <-ctx.Done():
	}
	h.mu.Lock()
	h.inside--
	h.mu.Unlock()
}

func setSlotWait(t *testing.T, d time.Duration) {
	old := slotWait
	slotWait = d
	t.Cleanup(func() { slotWait = old })
}

func TestToolConcurrencyCap(t *testing.T) {
	setSlotWait(t, 300*time.Millisecond)
	fx := newFixture(t)
	bh := newBlockingHook(t)
	fx.pw.setHook(bh.hook)
	session := fx.connect(t, "")

	var wg sync.WaitGroup
	for range maxConcurrentTools {
		wg.Go(func() {
			_, _ = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "power_on", Arguments: map[string]any{"server_id": 1}})
		})
	}
	for range maxConcurrentTools {
		waitFor(t, bh.entered, "a call to reach the power layer")
	}
	// The cap is full: the next call waits, then is turned away.
	res := call(t, session, "power_on", map[string]any{"server_id": 1})
	wantToolError(t, res, "server busy, try again")
	if got := len(fx.pw.sent()); got != maxConcurrentTools {
		t.Errorf("Send ran %d times, want %d", got, maxConcurrentTools)
	}
	bh.open()
	wg.Wait()
	bh.mu.Lock()
	peak := bh.peak
	bh.mu.Unlock()
	if peak > maxConcurrentTools {
		t.Errorf("peak concurrency %d > %d", peak, maxConcurrentTools)
	}
	// Slots are free again.
	fx.pw.setHook(nil)
	var out powerResult
	decode(t, call(t, session, "power_on", map[string]any{"server_id": 1}), &out)
}

func TestCheckAllRunsOneAtATime(t *testing.T) {
	setSlotWait(t, 300*time.Millisecond)
	fx := newFixture(t)
	bh := newBlockingHook(t)
	fx.pw.setHook(bh.hook)
	session := fx.connect(t, "")

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "check_all_power_status"})
	}()
	waitFor(t, bh.entered, "check_all to start")

	wantToolError(t, call(t, session, "check_all_power_status", nil), "server busy, try again")
	// Other tools are not held up by the running check-all.
	var list serverList
	decode(t, call(t, session, "list_servers", nil), &list)

	bh.mu.Lock()
	defer bh.mu.Unlock()
	if bh.peak != 1 {
		t.Errorf("peak concurrent check-all hook calls = %d, want 1", bh.peak)
	}
}
