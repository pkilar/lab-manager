package web

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/pkilar/lab-manager/internal/bmcproxy"
)

// handleKVM (main host) starts the KVM proxy handshake: it mints a short-lived
// token and redirects the browser to the BMC's proxy subdomain. ?to=terminal
// lands on the BMC's web terminal instead of its KVM (PiKVM only; the proxy
// maps the name to a fixed path, so it is not a redirect parameter).
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
	// route without auto-login available (proxy switched off, unsupported vendor,
	// a page cached before the config changed) must degrade to the credentials
	// page rather than 404 or bounce to the index — otherwise the primary
	// console button looks like it silently does nothing.
	if a.kvmTarget(s) == "" {
		http.Redirect(w, r, "/server/"+strconv.FormatInt(id, 10)+"/console/manual", http.StatusFound)
		return
	}
	slog.Info("KVM proxy launch", "user_id", currentUser(r).ID, "server_id", id)
	target := ""
	if r.URL.Query().Get("to") == bmcproxy.TargetTerminal {
		target = bmcproxy.TargetTerminal
	}
	token := a.proxy.MintToken(id)
	http.Redirect(w, r, a.proxy.AuthURL(requestScheme(r), r.Host, s.BMCType, id, token, target), http.StatusFound) //nolint:gosec // G710: AuthURL builds <vendor>-<id>.<configured domain>; only the port comes from the request
}
