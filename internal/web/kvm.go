package web

import (
	"log/slog"
	"net/http"

	"github.com/pkilar/lab-manager/internal/model"
)

// handleKVM (main host) starts the iDRAC KVM proxy handshake: it mints a
// short-lived token and redirects the browser to the iDRAC's proxy subdomain.
func (a *App) handleKVM(w http.ResponseWriter, r *http.Request) {
	if !a.proxy.Enabled() {
		http.NotFound(w, r)
		return
	}
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
	if s.BMCType != model.BMCIDRAC {
		requestSession(r).flash("error", "KVM auto-login is only available for iDRAC servers")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if s.RedfishUser == "" && s.IPMIUser == "" {
		requestSession(r).flash("error", "No credentials configured for this server")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	slog.Info("KVM proxy launch", "user_id", currentUser(r).ID, "server_id", id)
	token := a.proxy.MintToken(id)
	http.Redirect(w, r, a.proxy.AuthURL(id, token), http.StatusFound)
}
