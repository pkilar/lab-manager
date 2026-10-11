// Package web wires the HTTP layer: routing, handlers, sessions, CSRF, and
// template rendering, delegating to the store, power, and console services.
package web

import (
	"net/http"
	"sync"
	"time"

	"github.com/pkilar/lab-manager/internal/bmcproxy"
	"github.com/pkilar/lab-manager/internal/console"
	"github.com/pkilar/lab-manager/internal/power"
	"github.com/pkilar/lab-manager/internal/sol"
	"github.com/pkilar/lab-manager/internal/store"
)

// App holds the shared dependencies wired into every HTTP handler.
type App struct {
	store      *store.Store
	power      *power.Controller
	console    *console.Manager
	sol        *sol.Manager
	proxy      *bmcproxy.Manager
	tmpl       *Templates
	secretKey  []byte
	wolEnabled bool
	now        func() time.Time // injectable clock for session expiry and login throttling
	loginLimit *loginLimiter
	solTimings solTimings // SOL WebSocket keepalive; tests shrink it
}

// New builds the web application: it parses the embedded templates and
// constructs the power and console services from the store and secret key.
func New(st *store.Store, secretKey []byte, wolEnabled bool, bmcProxyDomain string) (*App, error) {
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	return &App{
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
	}, nil
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
// other hosts go through the normal app chain.
func (a *App) Handler() http.Handler {
	app := securityHeaders(limitRequestBody(a.withSession(a.withCSRF(a.routes()))))
	if !a.proxy.Enabled() {
		return app
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := a.proxy.HostServerID(r.Host); ok {
			a.proxy.Handler(w, r)
			return
		}
		app.ServeHTTP(w, r)
	})
}
