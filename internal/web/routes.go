package web

import "net/http"

func (a *App) routes() *http.ServeMux {
	mux := http.NewServeMux()

	// Auth — no login required (change-password/logout require login but skip the
	// password-change gate, so a user with a forced password change can still
	// reach these endpoints).
	mux.HandleFunc("GET /login", a.handleLogin)
	mux.HandleFunc("POST /login", a.handleLogin)
	mux.HandleFunc("POST /logout", a.requireLogin(false, a.handleLogout))
	mux.HandleFunc("GET /change-password", a.requireLogin(false, a.handleChangePassword))
	mux.HandleFunc("POST /change-password", a.requireLogin(false, a.handleChangePassword))

	// Protected web UI.
	mux.HandleFunc("GET /{$}", a.requireLogin(true, a.handleIndex))
	mux.HandleFunc("GET /server/new", a.requireLogin(true, a.handleNewServer))
	mux.HandleFunc("POST /server/new", a.requireLogin(true, a.handleNewServer))
	mux.HandleFunc("GET /server/{id}/edit", a.requireLogin(true, a.handleEditServer))
	mux.HandleFunc("POST /server/{id}/edit", a.requireLogin(true, a.handleEditServer))
	mux.HandleFunc("POST /server/{id}/delete", a.requireLogin(true, a.handleDeleteServer))
	mux.HandleFunc("POST /server/{id}/power/{action}", a.requireLogin(true, a.handlePowerAction))
	mux.HandleFunc("POST /server/{id}/wol", a.requireLogin(true, a.handleWakeOnLAN))
	mux.HandleFunc("POST /check-all-servers", a.requireLogin(true, a.handleCheckAllServers))

	// JSON API.
	mux.HandleFunc("POST /api/server/{id}/power/{action}", a.requireLogin(true, a.handleAPIPowerAction))
	mux.HandleFunc("POST /api/server/{id}/power/check", a.requireLogin(true, a.handleAPICheckStatus))

	// Console.
	mux.HandleFunc("GET /server/{id}/console", a.requireLogin(true, a.handleServerConsole))
	mux.HandleFunc("GET /server/{id}/console/launch", a.requireLogin(true, a.handleConsoleLaunch))
	mux.HandleFunc("GET /server/{id}/console/manual", a.requireLogin(true, a.handleConsoleManual))

	// Serial-over-LAN console.
	mux.HandleFunc("GET /server/{id}/sol/launch", a.requireLogin(true, a.handleSOLLaunch))
	mux.HandleFunc("GET /server/{id}/sol", a.requireLogin(true, a.handleSOLSocket))

	// iDRAC KVM proxy initiator (no-op when the proxy is disabled).
	mux.HandleFunc("GET /server/{id}/kvm", a.requireLogin(true, a.handleKVM))

	// Static assets (vendored xterm.js); not sensitive, no auth needed.
	mux.Handle("GET /static/", staticHandler())

	return mux
}
