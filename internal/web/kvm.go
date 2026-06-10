package web

import (
	"log"
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
	log.Printf("KVM proxy launch: user=%d server=%d", currentUser(r).ID, id)
	token := a.proxy.MintToken(id)
	http.Redirect(w, r, a.proxy.AuthURL(id, token), http.StatusFound)
}
