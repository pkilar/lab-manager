package web

import (
	"log/slog"
	"net/http"
	"strconv"
)

// handleKVM (main host) starts the iDRAC KVM proxy handshake: it mints a
// short-lived token and redirects the browser to the iDRAC's proxy subdomain.
func (a *App) handleKVM(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s, err := a.store.GetServer(id)
	if err != nil {
		a.notFoundOrError(w, r, err)
		return
	}
	// Console links here for proxy-capable rows, so anything that lands on this
	// route without auto-login available (proxy switched off, non-iDRAC vendor,
	// a page cached before the config changed) must degrade to the credentials
	// page rather than 404 or bounce to the index — otherwise the primary
	// console button looks like it silently does nothing.
	if a.consoleTarget(s) == "" {
		http.Redirect(w, r, "/server/"+strconv.FormatInt(id, 10)+"/console/manual", http.StatusFound)
		return
	}
	slog.Info("KVM proxy launch", "user_id", currentUser(r).ID, "server_id", id)
	token := a.proxy.MintToken(id)
	http.Redirect(w, r, a.proxy.AuthURL(requestScheme(r), r.Host, id, token), http.StatusFound)
}
