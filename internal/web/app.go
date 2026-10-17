// Package web wires the HTTP layer: routing, handlers, sessions, CSRF, and
// template rendering, delegating to the store, power, and console services.
package web

import (
	"net/http"
	"sync"
	"time"

	"github.com/pkilar/lab-manager/internal/bmcproxy"
	"github.com/pkilar/lab-manager/internal/console"
	"github.com/pkilar/lab-manager/internal/mcpserver"
	"github.com/pkilar/lab-manager/internal/power"
	"github.com/pkilar/lab-manager/internal/sol"
	"github.com/pkilar/lab-manager/internal/store"
)

// mcpPath is the Model Context Protocol endpoint. Handler dispatches it ahead
// of the session/CSRF chain, so it is not registered in routes().
const mcpPath = "/mcp"

// App holds the shared dependencies wired into every HTTP handler.
type App struct {
	store      *store.Store
	power      *power.Controller
	console    *console.Manager
	sol        *sol.Manager
	proxy      *bmcproxy.Manager
	mcp        http.Handler // the mcpPath endpoint; a 404 handler when the feature is off
	tmpl       *Templates
	secretKey  []byte
	wolEnabled bool
	now        func() time.Time // injectable clock for session expiry and login throttling
	loginLimit *loginLimiter
	solTimings solTimings // SOL WebSocket keepalive; tests shrink it
}

// New builds the web application: it parses the embedded templates and
// constructs the power and console services from the store and secret key,
// plus the MCP endpoint when mcpToken is non-empty.
func New(st *store.Store, secretKey []byte, wolEnabled bool, bmcProxyDomain, mcpToken string) (*App, error) {
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	a := &App{
		store:      st,
		power:      power.NewController(st, wolEnabled),
		console:    console.NewManager(secretKey),
		sol:        sol.NewManager(),
		proxy:      bmcproxy.NewManager(st, secretKey, bmcProxyDomain),
		tmpl:       tmpl,
		secretKey:  secretKey,
		wolEnabled: wolEnabled,
		now:        time.Now,
		loginLimit: newLoginLimiter(),
		solTimings: defaultSOLTimings,
	}
	a.mcp = a.mcpHandler(mcpToken)
	return a, nil
}

// mcpHandler builds the MCP endpoint on the app's own power controller, so an
// agent drives the BMCs exactly as the web UI does. An empty token leaves the
// feature off and the path answers 404.
func (a *App) mcpHandler(token string) http.Handler {
	if token == "" {
		return http.NotFoundHandler()
	}
	return mcpserver.New(a.store, a.power, token)
}

// Close releases BMC-side state that outlives any single request: it ends every
// live SOL session (each deactivates its single BMC payload) and logs the KVM
// proxy's sessions out of their iDRACs. Both are hijacked or in-memory, so
// http.Server.Shutdown neither waits for nor cleans up after them. Meant for
// process shutdown; the two run concurrently and each is bounded (~10s).
func (a *App) Close() {
	var wg sync.WaitGroup
	wg.Go(a.sol.CloseAll)
	wg.Go(a.proxy.Close)
	wg.Wait()
}

// Handler builds the full middleware chain, with a Host-based split: requests to
// an idrac-<id>.<proxy-domain> host go to the BMC reverse proxy (its own auth,
// no app middleware — the iDRAC SPA needs large bodies and self-framing); all
// other hosts go through the normal app chain, except mcpPath. MCP clients
// authenticate with a bearer token, not the session cookie, and withCSRF would
// reject every POST they send, so that one path keeps only the header and
// body-size layers.
func (a *App) Handler() http.Handler {
	app := securityHeaders(limitRequestBody(a.withSession(a.withCSRF(a.routes()))))
	mcpEndpoint := securityHeaders(limitRequestBody(a.mcp))
	proxied := a.proxy.Enabled()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if proxied {
			if _, ok := a.proxy.HostServerID(r.Host); ok {
				a.proxy.Handler(w, r)
				return
			}
		}
		if r.URL.Path == mcpPath {
			mcpEndpoint.ServeHTTP(w, r)
			return
		}
		app.ServeHTTP(w, r)
	})
}
