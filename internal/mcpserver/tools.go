package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pkilar/lab-manager/internal/model"
	"github.com/pkilar/lab-manager/internal/power"
	"github.com/pkilar/lab-manager/internal/store"
)

// errInventory is all an agent learns about a store failure; the real error is
// logged, not leaked.
var errInventory = errors.New("could not read the server inventory")

// serverInput is the argument of every per-server tool.
type serverInput struct {
	ServerID int64 `json:"server_id" jsonschema:"The server's id, as returned by list_servers."`
}

// serverInfo is one list_servers entry. Credentials, the MAC address and the
// SOL instance are left out on purpose: an agent needs none of them to drive
// the tools, and none should reach a model's context.
type serverInfo struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	IPAddress    string `json:"ip_address"`
	BMCType      string `json:"bmc_type" jsonschema:"BMC vendor: idrac, supermicro, ilo, pikvm or generic."`
	PowerControl string `json:"power_control" jsonschema:"How power commands reach the server: pikvm, redfish, ipmi, wake-on-lan (power on only, and only if Wake-on-LAN is enabled) or none."`
	Status       string `json:"status" jsonschema:"Last recorded power state, such as On or Off. May be stale; see check_power_status."`
	LastUpdated  string `json:"last_updated,omitempty" jsonschema:"When status was last recorded, as an RFC 3339 UTC timestamp. Absent if never recorded."`
	Notes        string `json:"notes,omitempty"`
}

type serverList struct {
	Servers []serverInfo `json:"servers"`
}

// serverStatus is one power-status reading.
type serverStatus struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	Live        bool   `json:"live" jsonschema:"True if the BMC was read just now; false if it could not be read and status is the last recorded value."`
	LastUpdated string `json:"last_updated,omitempty" jsonschema:"When status was last recorded, as an RFC 3339 UTC timestamp. Absent if never recorded."`
}

type statusList struct {
	Servers []serverStatus `json:"servers"`
}

// powerResult is the outcome of an accepted power command.
type powerResult struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Action  string `json:"action"`
	Message string `json:"message"`
}

const (
	// maxConcurrentTools caps tool handlers running at once: each can hold a
	// BMC call open for up to 30s, and the endpoint is reachable by any holder
	// of the token.
	maxConcurrentTools = 4
	// maxConcurrentCheckAll allows one check_all_power_status run at a time,
	// since each fans out to many BMCs by itself.
	maxConcurrentCheckAll = 1
)

// slotWait is how long a call waits for a free slot before giving up. A var so
// tests can shorten it.
var slotWait = 10 * time.Second

// errBusy is the tool error of a call that found no free slot in time.
var errBusy = errors.New("server busy, try again")

// limiter bounds tool concurrency.
type limiter struct {
	all      chan struct{}
	checkAll chan struct{}
}

func newLimiter() *limiter {
	return &limiter{
		all:      make(chan struct{}, maxConcurrentTools),
		checkAll: make(chan struct{}, maxConcurrentCheckAll),
	}
}

// acquire takes one slot of each given semaphore, in order, within slotWait or
// until ctx is done. It returns a release func, or errBusy.
func acquire(ctx context.Context, sems ...chan struct{}) (func(), error) {
	timer := time.NewTimer(slotWait)
	defer timer.Stop()
	var held []chan struct{}
	release := func() {
		for _, s := range held {
			<-s
		}
	}
	for _, s := range sems {
		select {
		case s <- struct{}{}:
			held = append(held, s)
		case <-timer.C:
			release()
			return nil, errBusy
		case <-ctx.Done():
			release()
			return nil, errBusy
		}
	}
	return release, nil
}

// limit wraps a tool handler so it runs only while holding a slot. extra
// semaphores (the check-all one) are taken first, so a call queued behind a
// running check-all does not also hold one of the general slots.
func limit[In, Out any](l *limiter, h mcp.ToolHandlerFor[In, Out], extra ...chan struct{}) mcp.ToolHandlerFor[In, Out] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		release, err := acquire(ctx, append(slices.Clone(extra), l.all)...)
		if err != nil {
			var zero Out
			return nil, zero, err
		}
		defer release()
		return h(ctx, req, in)
	}
}

// handlers binds the tool implementations to the inventory and the BMC layer.
type handlers struct {
	st Store
	pw Power
}

// registerTools adds the fixed tool set to srv. Names, titles, descriptions and
// annotations are what a client (and its model) sees, so they are the product
// surface of this package.
func registerTools(srv *mcp.Server, st Store, pw Power) {
	h := &handlers{st: st, pw: pw}
	lim := newLimiter()

	mcp.AddTool(srv, &mcp.Tool{
		Name:  "list_servers",
		Title: "List servers",
		Description: "List every server in the lab with its id, name, IP address, BMC type, power-control path and last recorded power status. " +
			"Reads Lab Manager's database only; no BMC is contacted, so the status may be stale (use check_power_status for a live reading).",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(false)},
	}, limit(lim, h.listServers))

	mcp.AddTool(srv, &mcp.Tool{
		Name:  "check_power_status",
		Title: "Check power status",
		Description: "Query one server's BMC for its live power state and record it. Can take up to about 30 seconds when the BMC is slow or unreachable. " +
			"If the BMC cannot be read, the last recorded status is returned with live set to false.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(true)},
	}, limit(lim, h.checkPowerStatus))

	mcp.AddTool(srv, &mcp.Tool{
		Name:  "check_all_power_status",
		Title: "Check all power statuses",
		Description: "Query every server's BMC concurrently for its live power state and record the results. " +
			"Can take 30 seconds or more when some BMCs are unreachable; a server whose BMC could not be read reports its last recorded status with live set to false.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: new(true)},
	}, limit(lim, h.checkAllPowerStatus, lim.checkAll))

	for _, p := range []struct {
		tool    *mcp.Tool
		command string
	}{
		{&mcp.Tool{
			Name:  "power_on",
			Title: "Power on server",
			Description: "Power on a server through its power-control path (PiKVM ATX button, Redfish, IPMI, or a Wake-on-LAN packet when only a MAC address is configured). " +
				"Returns once the command is accepted, not when the server has booted; use check_power_status to confirm.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: new(false), IdempotentHint: true, OpenWorldHint: new(true)},
		}, "power on"},
		{&mcp.Tool{
			Name:  "power_off",
			Title: "Power off server",
			Description: "Power off a server. Redfish and PiKVM request a graceful shutdown (like a short press of the power button); " +
				"IPMI cuts power immediately, so the operating system does not shut down cleanly. Servers reachable only by Wake-on-LAN cannot be powered off.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: new(true), IdempotentHint: true, OpenWorldHint: new(true)},
		}, "power off"},
		{&mcp.Tool{
			Name:  "power_cycle",
			Title: "Power-cycle server",
			Description: "Hard-reset a server (Redfish ForceRestart, IPMI power cycle, PiKVM reset button). " +
				"The operating system gets no chance to shut down cleanly; use it for a hung server or when explicitly asked.",
			Annotations: &mcp.ToolAnnotations{DestructiveHint: new(true), IdempotentHint: false, OpenWorldHint: new(true)},
		}, "power cycle"},
	} {
		mcp.AddTool(srv, p.tool, limit(lim, h.powerCommand(p.tool.Name, p.command)))
	}
}

func (h *handlers) listServers(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, serverList, error) {
	servers, err := h.allServers()
	if err != nil {
		return nil, serverList{}, err
	}
	// Never nil: the store returns a nil slice for an empty inventory, which
	// would marshal as null rather than the [] the output schema describes.
	out := serverList{Servers: make([]serverInfo, 0, len(servers))}
	for _, s := range servers {
		out.Servers = append(out.Servers, serverInfo{
			ID:           s.ID,
			Name:         s.Name,
			IPAddress:    s.IPAddress,
			BMCType:      s.BMCType,
			PowerControl: string(power.ProtocolFor(s)),
			Status:       s.Status,
			LastUpdated:  timestamp(s.LastUpdated),
			Notes:        s.Notes,
		})
	}
	return nil, out, nil
}

// checkPowerStatus reads one server's BMC. Whether the reading is live is not
// reported by Power.CheckStatus, so it is inferred: the controller updates the
// *model.Server in place and stamps LastUpdated with the current time only when
// it really read the BMC, otherwise it leaves the server, and so the cached
// status, untouched. A reading is therefore live exactly when LastUpdated moved.
func (h *handlers) checkPowerStatus(ctx context.Context, _ *mcp.CallToolRequest, in serverInput) (*mcp.CallToolResult, serverStatus, error) {
	s, err := h.server(in.ServerID)
	if err != nil {
		return nil, serverStatus{}, err
	}
	before := s.LastUpdated
	h.pw.CheckStatus(ctx, s)
	return nil, reading(s, !s.LastUpdated.Equal(before)), nil
}

// checkAllPowerStatus reads every server's BMC, telling live readings from
// cached ones the way checkPowerStatus does.
func (h *handlers) checkAllPowerStatus(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, statusList, error) {
	servers, err := h.allServers()
	if err != nil {
		return nil, statusList{}, err
	}
	before := make([]time.Time, len(servers))
	for i, s := range servers {
		before[i] = s.LastUpdated
	}
	h.pw.CheckAll(ctx, servers)
	out := statusList{Servers: make([]serverStatus, 0, len(servers))}
	for i, s := range servers {
		out.Servers = append(out.Servers, reading(s, !s.LastUpdated.Equal(before[i])))
	}
	return nil, out, nil
}

// powerCommand builds the handler of one power tool: it sends command to the
// server and relays what the controller said. A refused or failed command is a
// tool error, so the agent sees it as a failure rather than a result.
func (h *handlers) powerCommand(tool, command string) mcp.ToolHandlerFor[serverInput, powerResult] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in serverInput) (*mcp.CallToolResult, powerResult, error) {
		s, err := h.server(in.ServerID)
		if err != nil {
			return nil, powerResult{}, err
		}

		ok, msg := h.pw.Send(ctx, s, command)
		msg = strings.TrimSpace(msg) // ipmitool output ends in a newline
		level := slog.LevelInfo
		if !ok {
			level = slog.LevelWarn
		}
		slog.Log(ctx, level, "mcp power command", "command", command, "server_id", s.ID, "server", s.Name, "success", ok, "message", msg)

		if !ok {
			if msg == "" {
				msg = "the BMC gave no details" // ipmitool can exit non-zero with empty stderr
			}
			return nil, powerResult{}, fmt.Errorf("%s failed for %s: %s", tool, s.Name, msg)
		}
		return nil, powerResult{ID: s.ID, Name: s.Name, Action: tool, Message: msg}, nil
	}
}

// server loads one server for a tool call. A missing server is the agent's
// mistake and says how to fix it; any other store error is ours, and stays in
// the log.
func (h *handlers) server(id int64) (*model.Server, error) {
	s, err := h.st.GetServer(id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("no server with id %d; call list_servers for valid ids", id)
	}
	if err != nil {
		slog.Error("mcp inventory read failed", "server_id", id, "err", err)
		return nil, errInventory
	}
	return s, nil
}

// allServers loads the whole inventory for a tool call, hiding store errors
// from the agent as server does.
func (h *handlers) allServers() ([]*model.Server, error) {
	servers, err := h.st.AllServers()
	if err != nil {
		slog.Error("mcp inventory read failed", "err", err)
		return nil, errInventory
	}
	return servers, nil
}

func reading(s *model.Server, live bool) serverStatus {
	return serverStatus{ID: s.ID, Name: s.Name, Status: s.Status, Live: live, LastUpdated: timestamp(s.LastUpdated)}
}

// timestamp renders t as RFC 3339 UTC, or "" for the zero time ("never
// updated"), which omitempty then drops from the output.
func timestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
