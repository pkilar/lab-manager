package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkilar/lab-manager/internal/console"
	"github.com/pkilar/lab-manager/internal/model"
	"github.com/pkilar/lab-manager/internal/secret"
	"github.com/pkilar/lab-manager/internal/store"
)

// ---- shared helpers ------------------------------------------------------

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

func (a *App) serverError(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}

func (a *App) notFoundOrError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	a.serverError(w, r, err)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// actionPastTense maps a power action to the verb used in the success flash.
var actionPastTense = map[string]string{"start": "started", "stop": "stopped", "restart": "restarted"}

func actionToCommand(action string) (string, bool) {
	switch action {
	case "start":
		return "power on", true
	case "stop":
		return "power off", true
	case "restart":
		return "power cycle", true
	default:
		return "", false
	}
}

// requestScheme reports the external scheme, honouring a reverse proxy's
// X-Forwarded-Proto so console launch URLs and the Secure cookie flag are
// correct behind Traefik.
func requestScheme(r *http.Request) string {
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		first, _, _ := strings.Cut(proto, ",")
		return strings.ToLower(strings.TrimSpace(first))
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// ---- JSON API response shapes --------------------------------------------

type apiError struct {
	Error string `json:"error"`
}

type apiPowerResult struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	ServerID int64  `json:"server_id"`
	Action   string `json:"action"`
}

type apiStatusResult struct {
	Success  bool   `json:"success"`
	Status   string `json:"status"`
	ServerID int64  `json:"server_id"`
}

type consoleLaunchResponse struct {
	Success      bool   `json:"success"`
	AutoLoginURL string `json:"auto_login_url"`
	ServerName   string `json:"server_name"`
	BMCType      string `json:"bmc_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type consoleErrorResponse struct {
	Success     bool   `json:"success"`
	Error       string `json:"error"`
	FallbackURL string `json:"fallback_url"`
}

// ---- server form ---------------------------------------------------------

type serverForm struct {
	Name, IPAddress, MAC, BMCType                        string
	RedfishUser, RedfishPassword, IPMIUser, IPMIPassword string
	Notes                                                string
	SOLInstance                                          int
}

// parseServerForm reads and validates the shared add/edit form. On invalid
// input it returns a non-empty error message (and does not default the BMC
// type, which the caller does not use on the error path).
func parseServerForm(r *http.Request) (serverForm, string) {
	f := serverForm{
		Name:            sanitizeServerName(r.PostFormValue("name")),
		IPAddress:       strings.TrimSpace(r.PostFormValue("ip_address")),
		MAC:             strings.TrimSpace(r.PostFormValue("mac_address")),
		BMCType:         r.PostFormValue("bmc_type"),
		RedfishUser:     r.PostFormValue("redfish_user"),
		RedfishPassword: r.PostFormValue("redfish_password"),
		IPMIUser:        r.PostFormValue("ipmi_user"),
		IPMIPassword:    r.PostFormValue("ipmi_password"),
		Notes:           r.PostFormValue("notes"),
	}
	solInstance, solOK := parseSOLInstance(r.PostFormValue("sol_instance"))
	f.SOLInstance = solInstance
	switch {
	case f.Name == "":
		return f, "Server name is required"
	case !validateIPAddress(f.IPAddress):
		return f, "Invalid IP address format"
	case f.MAC != "" && !validateMACAddress(f.MAC):
		return f, "Invalid MAC address format (use AA:BB:CC:DD:EE:FF)"
	case !solOK:
		return f, "Serial console port must be a number from 1 to 15"
	}
	if !model.ValidBMCType(f.BMCType) {
		f.BMCType = model.BMCGeneric
	}
	return f, ""
}

// ---- web UI --------------------------------------------------------------

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	servers, err := a.store.AllServers()
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	rows := make([]serverRow, 0, len(servers))
	for _, s := range servers {
		row := serverRow{
			ID:               s.ID,
			Name:             s.Name,
			IPAddress:        s.IPAddress,
			BMCType:          s.BMCType,
			HasCreds:         s.RedfishUser != "" || s.IPMIUser != "",
			ConsoleHref:      a.consoleTarget(s),
			ConsoleAutoLogin: a.kvmTarget(s) != "",
			HasMAC:           s.MACAddress != "",
			Status:           s.Status,
			StatusOn:         s.Status == "On",
		}
		if s.Notes != "" {
			if rn := []rune(s.Notes); len(rn) > 50 {
				row.NotesPreview = string(rn[:50])
				row.NotesTruncated = true
			} else {
				row.NotesPreview = s.Notes
			}
		}
		if !s.LastUpdated.IsZero() {
			row.HasLastUpdated = true
			row.LastUpdatedUTC = s.LastUpdated.UTC().Format("2006-01-02T15:04:05.000000")
			row.LastUpdatedLocal = s.LastUpdated.Local().Format("2006-01-02 15:04:05 MST")
		}
		rows = append(rows, row)
	}
	a.renderPage(w, "index", http.StatusOK, indexData{baseData: a.baseData(r), Servers: rows})
}

func (a *App) handleNewServer(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		f, errMsg := parseServerForm(r)
		if errMsg != "" {
			a.flashSimple(w, r, "new_server", "error", errMsg)
			return
		}
		s := &model.Server{
			Name: f.Name, IPAddress: f.IPAddress, BMCType: f.BMCType,
			RedfishUser: f.RedfishUser, RedfishPassword: f.RedfishPassword,
			IPMIUser: f.IPMIUser, IPMIPassword: f.IPMIPassword,
			MACAddress: f.MAC, Status: "Off", LastUpdated: time.Now().UTC(), Notes: f.Notes,
			SOLInstance: f.SOLInstance,
		}
		if err := a.store.CreateServer(s); err != nil {
			a.serverError(w, r, err)
			return
		}
		requestSession(r).flash("success", "Server added successfully!")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	a.renderPage(w, "new_server", http.StatusOK, simplePage{a.baseData(r)})
}

func (a *App) handleEditServer(w http.ResponseWriter, r *http.Request) {
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
	if r.Method == http.MethodPost {
		a.updateServer(w, r, s)
		return
	}
	a.renderEdit(w, r, s)
}

// updateServer applies a validated form to s and persists it. On validation
// error it re-renders the edit page with the unmodified server.
func (a *App) updateServer(w http.ResponseWriter, r *http.Request, s *model.Server) {
	f, errMsg := parseServerForm(r)
	if errMsg != "" {
		a.editError(w, r, s, errMsg)
		return
	}
	s.Name = f.Name
	s.IPAddress = f.IPAddress
	s.BMCType = f.BMCType
	s.RedfishUser = f.RedfishUser
	s.IPMIUser = f.IPMIUser
	s.MACAddress = f.MAC
	s.Notes = f.Notes
	s.SOLInstance = f.SOLInstance
	s.LastUpdated = time.Now().UTC()

	// Credential rules, per protocol (Redfish / IPMI):
	//   - empty username   → remove the credentials (clear username AND password)
	//   - new password      → update the password
	//   - blank password    → keep the stored one (so edits don't require re-typing)
	setRedfish := false
	switch {
	case f.RedfishUser == "":
		s.RedfishPassword = ""
		setRedfish = true
	case f.RedfishPassword != "":
		s.RedfishPassword = f.RedfishPassword
		setRedfish = true
	}
	setIPMI := false
	switch {
	case f.IPMIUser == "":
		s.IPMIPassword = ""
		setIPMI = true
	case f.IPMIPassword != "":
		s.IPMIPassword = f.IPMIPassword
		setIPMI = true
	}
	if err := a.store.UpdateServer(s, setRedfish, setIPMI); err != nil {
		a.serverError(w, r, err)
		return
	}
	requestSession(r).flash("success", "Server updated successfully!")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *App) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, err := a.store.GetServer(id); err != nil {
		a.notFoundOrError(w, r, err)
		return
	}
	if err := a.store.DeleteServer(id); err != nil {
		a.serverError(w, r, err)
		return
	}
	requestSession(r).flash("success", "Server deleted successfully!")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *App) handlePowerAction(w http.ResponseWriter, r *http.Request) {
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
	action := r.PathValue("action")
	command, ok := actionToCommand(action)
	if !ok {
		// Browser form handler: flash and redirect rather than return JSON.
		requestSession(r).flash("error", "Invalid action")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	success, message := a.power.Send(r.Context(), s, command)
	if success {
		requestSession(r).flash("success", fmt.Sprintf("Server %s %s successfully!", s.Name, actionPastTense[action]))
	} else {
		requestSession(r).flash("error", "Error: "+message)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *App) handleWakeOnLAN(w http.ResponseWriter, r *http.Request) {
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
	if !a.wolEnabled {
		requestSession(r).flash("error", "Wake-on-LAN is disabled. Set WOL_ENABLED=true to enable it.")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if s.MACAddress == "" {
		requestSession(r).flash("error", fmt.Sprintf("Server %s does not have a MAC address configured for Wake-on-LAN", s.Name))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	success, message := a.power.Send(r.Context(), s, "power on")
	if success {
		requestSession(r).flash("success", fmt.Sprintf("Wake-on-LAN packet sent to %s", s.Name))
	} else {
		requestSession(r).flash("error", "Error: "+message)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// checkAllConcurrency bounds the parallel BMC status checks of /check-all-servers.
const checkAllConcurrency = 8

func (a *App) handleCheckAllServers(w http.ResponseWriter, r *http.Request) {
	servers, err := a.store.AllServers()
	if err != nil {
		a.serverError(w, r, err)
		return
	}
	// Each check can block for the full BMC timeout on an unreachable host, so
	// run them concurrently (bounded) rather than holding the request N x timeout.
	sem := make(chan struct{}, checkAllConcurrency)
	var wg sync.WaitGroup
	for _, s := range servers {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			a.power.CheckStatus(r.Context(), s)
		})
	}
	wg.Wait()
	requestSession(r).flash("success", fmt.Sprintf("Successfully updated status for all %d servers", len(servers)))
	http.Redirect(w, r, "/", http.StatusFound)
}

// ---- JSON API ------------------------------------------------------------

func (a *App) handleAPIPowerAction(w http.ResponseWriter, r *http.Request) {
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
	action := r.PathValue("action")
	command, ok := actionToCommand(action)
	if !ok {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "Invalid action"})
		return
	}
	success, message := a.power.Send(r.Context(), s, command)
	writeJSON(w, http.StatusOK, apiPowerResult{Success: success, Message: message, ServerID: id, Action: action})
}

func (a *App) handleAPICheckStatus(w http.ResponseWriter, r *http.Request) {
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
	status := a.power.CheckStatus(r.Context(), s)
	writeJSON(w, http.StatusOK, apiStatusResult{Success: true, Status: status, ServerID: id})
}

// ---- console -------------------------------------------------------------

// kvmTarget returns the iDRAC auto-login proxy path for s, or "" when that path
// does not apply (feature off, wrong vendor, no credentials). Only the iDRAC
// proxy achieves a real auto-login: Supermicro's cookie auth survives a
// cross-origin form POST, but the iDRAC SPA needs ST tokens the browser cannot
// read, so the server-side proxy is the only path that avoids hand-entered
// credentials.
//
// Single source of truth for the places that must agree — the button and the
// /kvm initiator (kvm.go) — or a row renders a link its handler then refuses.
func (a *App) kvmTarget(s *model.Server) string {
	if !a.proxy.Enabled() || s.BMCType != model.BMCIDRAC {
		return ""
	}
	if s.RedfishUser == "" && s.IPMIUser == "" {
		return ""
	}
	return "/server/" + strconv.FormatInt(s.ID, 10) + "/kvm"
}

// consoleTarget returns the href the primary "Console" button should use, or ""
// when the browser-side token flow (openConsole) should be used instead.
func (a *App) consoleTarget(s *model.Server) string {
	if href := a.kvmTarget(s); href != "" {
		return href
	}
	cfg := console.LoginConfigFor(s)
	if cfg == nil || cfg.SupportsAutoLogin {
		// No credentials at all, or a vendor whose launch page genuinely logs
		// in (Supermicro's browser-side form; iDRAC's pre-flight). Both need
		// the tokenised flow.
		return ""
	}
	// Nothing to log into automatically, so the launch page would be nothing but
	// the credential list — byte-for-byte the same document the 🔑 button
	// serves. Rendering it from "Console" made the two buttons duplicates and
	// put a credentials popup in front of every console launch. Send Console to
	// the BMC's own UI and leave credentials to 🔑.
	return cfg.ConsoleURL
}

// handleConsoleManual is the browser-navigable way to reach the credentials
// page. /server/{id}/console is a JSON API, so it cannot be linked directly;
// this mints the token the launch page requires and redirects to it. It is the
// fallback whenever the proxy path fails or is unavailable.
func (a *App) handleConsoleManual(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, err := a.store.GetServer(id); err != nil {
		a.notFoundOrError(w, r, err)
		return
	}
	token := a.console.GenerateToken(id, currentUser(r).ID)
	http.Redirect(w, r, "/server/"+strconv.FormatInt(id, 10)+
		"/console/launch?manual=1&token="+url.QueryEscape(token), http.StatusFound)
}

func (a *App) handleServerConsole(w http.ResponseWriter, r *http.Request) {
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
	if s.RedfishUser == "" && s.IPMIUser == "" {
		writeJSON(w, http.StatusBadRequest, consoleErrorResponse{
			Success:     false,
			Error:       "No credentials configured for this server",
			FallbackURL: "https://" + s.IPAddress + "/",
		})
		return
	}
	token := a.console.GenerateToken(id, currentUser(r).ID)
	launchURL := requestScheme(r) + "://" + r.Host + "/server/" + strconv.FormatInt(id, 10) +
		"/console/launch?token=" + url.QueryEscape(token)
	writeJSON(w, http.StatusOK, consoleLaunchResponse{
		Success:      true,
		AutoLoginURL: launchURL,
		ServerName:   s.Name,
		BMCType:      s.BMCType,
		ExpiresIn:    console.TokenValiditySeconds,
	})
}

func (a *App) handleConsoleLaunch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		requestSession(r).flash("error", "Invalid console access request - missing token")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if !a.console.VerifyToken(token, id, currentUser(r).ID) {
		requestSession(r).flash("error", "Console access token expired or invalid. Please try again.")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	s, err := a.store.GetServer(id)
	if err != nil {
		a.notFoundOrError(w, r, err)
		return
	}
	cfg := console.LoginConfigFor(s)
	if cfg == nil {
		requestSession(r).flash("error", "No credentials configured for this server")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	username, password := console.CredsFor(s)

	// manual=1 comes from the 🔑 button: the user wants the credentials, not an
	// auto-login. Only Supermicro branches on it, because only its launch page
	// logs in by submitting a form from the browser — which is precisely what
	// this path exists to skip. iDRAC's page does no auto-login of its own (the
	// proxy does), and it reports whether the stored credentials still work,
	// which is worth having on the copy/paste path rather than bypassing.
	manual := r.URL.Query().Get("manual") == "1"

	switch {
	case s.BMCType == model.BMCSupermicro && cfg.SupportsAutoLogin && !manual:
		a.renderConsole(w, "console_launch_supermicro", consoleSupermicroData{
			ServerID: s.ID, ServerName: s.Name, IPAddress: s.IPAddress,
			LoginURL: cfg.LoginURL, ConsoleURL: cfg.ConsoleURL,
			Username: username, Password: password, HasUsername: username != "",
		})
	case s.BMCType == model.BMCIDRAC && cfg.SupportsAutoLogin:
		a.renderConsole(w, "console_launch_idrac", consoleIdracData{
			ServerID: s.ID, ServerName: s.Name, IPAddress: s.IPAddress, ConsoleURL: cfg.ConsoleURL,
			Username: username, Password: password, HasUsername: username != "",
			Auth: a.console.PreAuthenticateIDRAC(r.Context(), s),
		})
	default:
		a.renderConsole(w, "console_launch", consoleGenericData{
			ServerName: s.Name, BMCType: s.BMCType, ConsoleURL: cfg.ConsoleURL,
			Username: username, Password: password, HasUsername: username != "",
		})
	}
}

// ---- auth ----------------------------------------------------------------

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := strings.TrimSpace(r.PostFormValue("username"))
		password := r.PostFormValue("password")

		now := a.now()
		key := loginKey(username)
		if ok, retry := a.loginLimit.allow(key, now); !ok {
			secs := int((retry + time.Second - 1) / time.Second)
			requestSession(r).flash("error", fmt.Sprintf("Too many failed login attempts. Try again in %d seconds.", secs))
			a.renderPage(w, "login", http.StatusTooManyRequests, simplePage{a.baseData(r)})
			return
		}

		// Always run one scrypt verification, even for unknown usernames, so
		// response time does not reveal which usernames exist.
		user, err := a.store.GetUserByUsername(username)
		if err != nil {
			secret.CheckPasswordHash(dummyPasswordHash(), password)
		} else if secret.CheckPasswordHash(user.PasswordHash, password) {
			a.loginLimit.succeed(key)
			sess := requestSession(r)
			sess.login(user.ID, now.Unix(), a.passwordVersion(user.PasswordHash))
			if user.PasswordChangeRequired {
				sess.flash("warning", "Please change your default password for security.")
				http.Redirect(w, r, "/change-password", http.StatusFound)
				return
			}
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		a.loginLimit.fail(key, now)
		requestSession(r).flash("error", "Invalid username or password")
	}
	a.renderPage(w, "login", http.StatusOK, simplePage{a.baseData(r)})
}

func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	if r.Method == http.MethodPost {
		current := r.PostFormValue("current_password")
		newPassword := r.PostFormValue("new_password")
		confirm := r.PostFormValue("confirm_password")

		switch {
		case !secret.CheckPasswordHash(user.PasswordHash, current):
			a.flashSimple(w, r, "change_password", "error", "Current password is incorrect")
			return
		case len([]rune(newPassword)) < 8:
			a.flashSimple(w, r, "change_password", "error", "New password must be at least 8 characters long")
			return
		case newPassword != confirm:
			a.flashSimple(w, r, "change_password", "error", "New passwords do not match")
			return
		case newPassword == current:
			a.flashSimple(w, r, "change_password", "error", "New password must be different from current password")
			return
		}

		hash, err := secret.GeneratePasswordHash(newPassword)
		if err != nil {
			a.serverError(w, r, err)
			return
		}
		if err := a.store.SetUserPassword(user.ID, hash, false); err != nil {
			a.serverError(w, r, err)
			return
		}
		// Keep this session valid under the new password version; every other
		// session of the user is now invalid.
		sess := requestSession(r)
		sess.login(user.ID, a.now().Unix(), a.passwordVersion(hash))
		sess.flash("success", "Password changed successfully!")
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	a.renderPage(w, "change_password", http.StatusOK, simplePage{a.baseData(r)})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	requestSession(r).logout()
	http.Redirect(w, r, "/login", http.StatusFound)
}

// ---- render helpers ------------------------------------------------------

func (a *App) flashSimple(w http.ResponseWriter, r *http.Request, page, category, message string) {
	requestSession(r).flash(category, message)
	a.renderPage(w, page, http.StatusOK, simplePage{a.baseData(r)})
}

func (a *App) renderEdit(w http.ResponseWriter, r *http.Request, s *model.Server) {
	a.renderPage(w, "edit_server", http.StatusOK, editData{
		baseData: a.baseData(r),
		Server: editServerRow{
			ID: s.ID, Name: s.Name, IPAddress: s.IPAddress, BMCType: s.BMCType,
			RedfishUser: s.RedfishUser, IPMIUser: s.IPMIUser, MACAddress: s.MACAddress, Notes: s.Notes,
			SOLInstance:    s.SOLInstanceOrDefault(),
			HasRedfishUser: s.RedfishUser != "", HasIPMIUser: s.IPMIUser != "",
		},
	})
}

func (a *App) editError(w http.ResponseWriter, r *http.Request, s *model.Server, message string) {
	requestSession(r).flash("error", message)
	a.renderEdit(w, r, s)
}
