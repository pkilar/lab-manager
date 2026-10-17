// Package mcpserver exposes the lab's servers to AI agents over the Model
// Context Protocol (MCP): tools to list servers, read their power state and
// power them on, off or cycle them. Commands go through the same
// power.Controller as the web UI, so a server is driven by the same single
// power-control path (PiKVM, Redfish, IPMI or Wake-on-LAN) either way.
//
// The endpoint is stateless streamable HTTP behind a static bearer token. None
// of a server's credentials, MAC address or serial-console settings are ever
// returned to the agent.
package mcpserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pkilar/lab-manager/internal/model"
)

// Store reads the server inventory; *store.Store satisfies it. The tools
// mutate the servers they are given (Power records live readings in place), so
// every call must return fresh values, never ones shared between calls.
type Store interface {
	AllServers() ([]*model.Server, error)
	GetServer(id int64) (*model.Server, error) // store.ErrNotFound when absent
}

// Power drives the BMCs; *power.Controller satisfies it. CheckStatus and
// CheckAll record a live reading by updating the server in place and stamping
// its LastUpdated; when a BMC cannot be read they leave that server untouched.
// The status tools rely on this to tell a live reading from a cached one.
type Power interface {
	Send(ctx context.Context, s *model.Server, command string) (bool, string)
	CheckStatus(ctx context.Context, s *model.Server) string
	CheckAll(ctx context.Context, servers []*model.Server)
}

// instructions is sent to every client on connect. It is the one place the
// confirm-before-acting expectation is stated for all agents, whatever they do
// with the per-tool annotations.
const instructions = "Lab Manager controls the power of physical servers in a home lab through their BMCs " +
	"(Dell iDRAC/Redfish, IPMI, PiKVM) or Wake-on-LAN. Start with list_servers to find a server's id. " +
	"The status in list_servers is the last recorded value; call check_power_status for a live reading. " +
	"power_off and power_cycle act on real hardware and interrupt whatever the server is running: " +
	"unless the user explicitly asked for that action on that server, confirm with them first."

// New returns the handler for the MCP endpoint. Panics if token is empty: an
// empty token must never mean "no auth" (the caller only builds this when the
// feature is enabled and has already validated the token).
func New(st Store, pw Power, token string) http.Handler {
	if token == "" {
		panic("mcpserver: empty bearer token")
	}

	srv := mcp.NewServer(&mcp.Implementation{Name: "lab-manager", Title: "Lab Manager", Version: buildVersion()}, &mcp.ServerOptions{
		Instructions: instructions,
		// The tool set is fixed and served statelessly, so advertise tools without
		// listChanged and without the logging capability the SDK adds by default
		// (nothing here sends log messages). A listChanged tool capability makes a
		// 2026-07-28 client park a subscriptions/listen stream, which holds a
		// goroutine and stalls graceful shutdown.
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}},
	})
	srv.AddReceivingMiddleware(recoverPanics)
	registerTools(srv, st, pw)

	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{
		// Every POST is self-contained and answered with plain JSON: no session
		// is kept and no SSE stream outlives its request.
		Stateless:    true,
		JSONResponse: true,
		// A client that disconnects or times out abandons the in-flight BMC call
		// instead of leaving it to run to its own timeout (2026-07-28 clients).
		PropagateRequestCancellation: true,
	})

	// Cross-origin protection is outermost: it turns a browser's cross-site POST
	// away before the token is even looked at. CLI clients send neither Origin
	// nor Sec-Fetch-Site, so they pass straight through to the token check.
	return http.NewCrossOriginProtection().Handler(requireBearer(token, h))
}

// requireBearer admits only requests carrying "Authorization: Bearer <token>".
// The SDK's own auth.RequireBearerToken is not used: it insists on a token
// expiration, which a static shared secret does not have. Both sides are
// hashed before the constant-time compare so that neither the content nor the
// length of the expected token leaks through timing.
func requireBearer(token string, next http.Handler) http.Handler {
	want := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented := bearerToken(r)
		got := sha256.Sum256([]byte(presented))
		if presented != "" && subtle.ConstantTimeCompare(got[:], want[:]) == 1 {
			next.ServeHTTP(w, r)
			return
		}

		slog.Warn("mcp unauthorized request", "remote", r.RemoteAddr, "method", r.Method)
		challenge := `Bearer realm="lab-manager"`
		if presented != "" {
			// RFC 6750 section 3.1: only name an error when credentials were
			// actually offered and wrong.
			challenge += `, error="invalid_token"`
		}
		w.Header().Set("WWW-Authenticate", challenge)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

// bearerToken returns the credential of an Authorization header that uses the
// Bearer scheme (matched case-insensitively), or "" when the header is absent,
// empty or uses another scheme.
func bearerToken(r *http.Request) string {
	scheme, credential, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(credential)
}

// recoverPanics turns a panic in any MCP method handler into an error reply.
// Tool handlers run on SDK-owned goroutines with no recover of their own, so
// without this one bad call would take down the whole process, web UI included.
func recoverPanics(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (res mcp.Result, err error) {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("mcp: panic in handler", "method", method, "err", r, "stack", string(debug.Stack()))
				if method == "tools/call" {
					res, err = &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "internal error"}}}, nil
				} else {
					res, err = nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "internal error"}
				}
			}
		}()
		return next(ctx, method, req)
	}
}

// buildVersion is the module version stamped into the binary, or "dev" for a
// local build, which carries none.
func buildVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}
