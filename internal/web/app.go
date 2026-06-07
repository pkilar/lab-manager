// Package web wires the HTTP layer: routing, handlers, sessions, CSRF, and
// template rendering, delegating to the store, power, and console services.
package web

import (
	"net/http"

	"github.com/pkilar/lab-manager/internal/console"
	"github.com/pkilar/lab-manager/internal/power"
	"github.com/pkilar/lab-manager/internal/store"
)

// App holds the shared dependencies wired into every HTTP handler.
type App struct {
	store      *store.Store
	power      *power.Controller
	console    *console.Manager
	tmpl       *Templates
	secretKey  []byte
	wolEnabled bool
}

// New builds the web application: it parses the embedded templates and
// constructs the power and console services from the store and secret key.
func New(st *store.Store, secretKey []byte, wolEnabled bool) (*App, error) {
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	return &App{
		store:      st,
		power:      power.NewController(st, wolEnabled),
		console:    console.NewManager(secretKey),
		tmpl:       tmpl,
		secretKey:  secretKey,
		wolEnabled: wolEnabled,
	}, nil
}

// Handler builds the full middleware chain: session loading (outermost), then
// CSRF validation, then the router.
func (a *App) Handler() http.Handler {
	return a.withSession(a.withCSRF(a.routes()))
}
