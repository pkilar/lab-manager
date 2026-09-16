package bmcproxy

import (
	"bytes"
	"context"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkilar/lab-manager/internal/model"
)

// proxyCookieName is the opaque session cookie the browser holds on the proxy
// subdomain. It maps to server-side state (the injected iDRAC cookie).
const proxyCookieName = "bmcproxy"

// ServerLookup fetches a server by id; *store.Store satisfies it.
type ServerLookup interface {
	GetServer(id int64) (*model.Server, error)
}

// Manager serves the iDRAC reverse proxy for idrac-<id>.<domain> hosts.
type Manager struct {
	lookup   ServerLookup
	secret   []byte
	domain   string // e.g. "pi.home.kilar.net"; empty disables the feature
	sessions *sessionStore
}

// NewManager builds a proxy Manager and starts its session GC. A blank domain
// yields a disabled manager (Enabled() == false).
func NewManager(lookup ServerLookup, secret []byte, domain string) *Manager {
	m := &Manager{lookup: lookup, secret: secret, domain: domain, sessions: newSessionStore()}
	if m.Enabled() {
		go m.sessionGC()
	}
	return m
}

func (m *Manager) sessionGC() {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for range t.C {
		for _, sess := range m.sessions.gc() {
			m.logoutIDRAC(sess.ip, sess.idracCookie)
		}
	}
}

// logoutIDRAC releases an iDRAC web session (-http-session-) so repeated KVM
// launches don't exhaust the iDRAC's small web-session table. Best-effort: runs
// on its own background deadline so it completes even when the originating
// request is gone.
func (m *Manager) logoutIDRAC(ip, idracCookie string) {
	if ip == "" || idracCookie == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ip+"/data/logout", nil)
	if err != nil {
		return
	}
	req.Header.Set("Cookie", idracCookie)
	resp, err := loginClient.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// Enabled reports whether the proxy feature is configured.
func (m *Manager) Enabled() bool { return m != nil && m.domain != "" }

var hostIDPattern = regexp.MustCompile(`^idrac-(\d+)\.(.+)$`)

// HostServerID returns the iDRAC server id when host is a proxy host for this
// manager's domain.
func (m *Manager) HostServerID(host string) (int64, bool) {
	if !m.Enabled() {
		return 0, false
	}
	host = stripPort(host)
	mt := hostIDPattern.FindStringSubmatch(host)
	if mt == nil || mt[2] != m.domain {
		return 0, false
	}
	id, err := strconv.ParseInt(mt[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// MintToken signs a handshake token for the initiator on the main host.
func (m *Manager) MintToken(serverID int64) string { return mintToken(m.secret, serverID) }

// AuthURL is where the initiator redirects the browser to start the handshake.
// scheme and hostPort come from the request that hit the initiator, so the
// handshake stays on the scheme (and port) the browser is already using. Under
// the HTTPS Swarm deploy that is unchanged; it additionally makes the flow
// reachable over plain HTTP in development, where the whole path was previously
// impossible to exercise.
func (m *Manager) AuthURL(scheme, hostPort string, serverID int64, token string) string {
	host := fmt.Sprintf("idrac-%d.%s", serverID, m.domain)
	return fmt.Sprintf("%s://%s/__labmgr/auth?token=%s", scheme, withPortOf(hostPort, host), token)
}

// appBaseURL is the main app's external URL (used to bounce expired sessions
// back through the login-gated initiator). The app is deployed at lab.<domain>.
func (m *Manager) appBaseURL(r *http.Request) string {
	return proxyScheme(r) + "://" + withPortOf(r.Host, "lab."+m.domain)
}

// withPortOf appends src's port to host, so a non-default port in development
// (":5000") survives while the production HTTPS hosts stay bare.
func withPortOf(src, host string) string {
	if _, port, err := net.SplitHostPort(src); err == nil && port != "" {
		return net.JoinHostPort(host, port)
	}
	return host
}

// bmcConsolePort is the separate TLS listener the iDRAC serves its HTML5
// virtual console from. The console SPA builds its URL from
// window.location.host, so it arrives here as idrac-<id>.<domain>:5900 rather
// than pointing at the BMC directly — which means it can be proxied, but only
// if the request is forwarded to the BMC's 5900 instead of 443.
const bmcConsolePort = "5900"

// upstreamHost picks the BMC address to forward to, honouring the virtual
// console's separate port. Only bmcConsolePort is passed through: any other
// inbound port is the app's own listener (":5000" in development) and must not
// be forwarded to the BMC.
func upstreamHost(ip, inboundHost string) string {
	if _, port, err := net.SplitHostPort(inboundHost); err == nil && port == bmcConsolePort {
		return net.JoinHostPort(stripPort(ip), bmcConsolePort)
	}
	return ip
}

// relay proxies an authenticated request to the iDRAC, injecting the
// server-side session cookie. A single ReverseProxy handles both plain HTTP and
// the KVM WebSocket (it natively tunnels Upgrade requests).
func (m *Manager) relay(w http.ResponseWriter, r *http.Request, id int64) {
	sess, sid, ok := m.sessionFor(r)
	if !ok || sess.serverID != id {
		http.Redirect(w, r, m.appBaseURL(r)+"/server/"+strconv.FormatInt(id, 10)+"/kvm", http.StatusFound)
		return
	}
	s, err := m.lookup.GetServer(id)
	if err != nil {
		http.Error(w, "server not found", http.StatusNotFound)
		return
	}
	m.serveHTTP(w, r, sid, upstreamHost(s.IPAddress, r.Host), sess.idracCookie)
}

func (m *Manager) sessionFor(r *http.Request) (proxySession, string, bool) {
	c, err := r.Cookie(proxyCookieName)
	if err != nil {
		return proxySession{}, "", false
	}
	sess, ok := m.sessions.get(c.Value)
	if !ok {
		return proxySession{}, "", false
	}
	return sess, c.Value, true
}

func (m *Manager) serveHTTP(w http.ResponseWriter, r *http.Request, sid, ip, idracCookie string) {
	rp := &httputil.ReverseProxy{
		Transport: proxyTransport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = ip
			pr.Out.Host = ip
			// Rewrite drops query parameters it cannot parse; the KVM applet
			// relies on its own encoding, so forward the raw string verbatim.
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			pr.Out.Header.Set("Origin", "https://"+ip)
			pr.Out.Header.Set("Referer", "https://"+ip+"/")
			// Rebuild Cookie: drop our proxy cookie and any client-supplied
			// session, then inject the server-held iDRAC session.
			var keep []string
			for _, c := range pr.Out.Cookies() {
				if c.Name == proxyCookieName || c.Name == idracSessionCookie {
					continue
				}
				keep = append(keep, c.Name+"="+c.Value)
			}
			keep = append(keep, idracCookie)
			pr.Out.Header.Set("Cookie", strings.Join(keep, "; "))
			// Don't leak the browser's IP to the BMC: deliberately no
			// pr.SetXForwarded(). Rewrite already stripped the inbound
			// X-Forwarded-*/Forwarded headers, but Traefik's X-Real-Ip
			// is not one of them, so drop it explicitly.
			pr.Out.Header.Del("X-Real-Ip")
			// Ask the BMC for identity encoding so ModifyResponse can inject the
			// auto-launch script into the dashboard HTML without gzip surgery.
			// This is a low-traffic admin proxy on a LAN; the lost compression
			// is negligible, and the KVM stream is a WebSocket, unaffected.
			pr.Out.Header.Del("Accept-Encoding")
		},
		ModifyResponse: func(resp *http.Response) error {
			rewriteLocation(resp, ip, r.Host, proxyScheme(r))
			m.rewriteSetCookies(resp, sid)
			return m.maybeInjectAutoLaunch(resp, sid)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			slog.Error("bmcproxy upstream", "ip", ip, "err", err)
			http.Error(w, "iDRAC unreachable", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

// autoLaunchScript is injected once into the iDRAC dashboard after login so the
// operator lands on a KVM that opens itself instead of a page they must hunt a
// launch button on. It cannot be done by URL: the HTML5 viewer is a popup child
// of this SPA (it reads window.opener), so only the SPA's own QuickLaunch can
// open it correctly — this waits for that function and calls it.
//
// The one unavoidable seam is the pop-up blocker: QuickLaunch opens a window,
// and a script-driven open with no user gesture is often blocked. When that
// happens the script drops a single fixed button, so a blocked launch costs one
// click (still fewer than finding the console tab) instead of failing silently.
const autoLaunchScript = `<script>(function(){
  if (window.__labmgrKVM) return; window.__labmgrKVM = 1;
  function quick(){
    if (typeof window.QuickLaunch !== 'function') return null;
    var win = null, open = window.open;
    try {
      window.open = function(){ win = open.apply(window, arguments); return win; };
      window.QuickLaunch('viewer');
    } catch (e) {} finally { window.open = open; }
    return win; // null => QuickLaunch's window.open was blocked (no gesture)
  }
  function button(){
    if (document.getElementById('labmgr-kvm')) return;
    var b = document.createElement('button');
    b.id = 'labmgr-kvm';
    b.textContent = '▶︎  Launch Virtual Console';
    b.style.cssText = 'position:fixed;z-index:2147483647;top:14px;right:14px;padding:12px 18px;'
      + 'font:600 14px system-ui,-apple-system,sans-serif;color:#fff;background:#2563eb;border:0;'
      + 'border-radius:8px;cursor:pointer;box-shadow:0 6px 18px rgba(0,0,0,.4)';
    b.onclick = function(){ quick(); b.remove(); }; // a real gesture: never blocked
    (document.body || document.documentElement).appendChild(b);
  }
  var tries = 0;
  (function attempt(){
    if (typeof window.QuickLaunch !== 'function'){
      if (++tries > 100){ button(); return; } // SPA never finished loading
      setTimeout(attempt, 200);
      return;
    }
    if (quick() === null) button(); // auto-launch blocked -> offer one click
  })();
})();</script>`

// maybeInjectAutoLaunch injects autoLaunchScript into the first dashboard
// document of a freshly authenticated session, then clears the one-shot flag so
// later navigation is untouched. Only text/html documents qualify; assets and
// XHR/JSON responses pass through. Accept-Encoding was stripped upstream, so the
// body is identity and needs no gzip handling.
func (m *Manager) maybeInjectAutoLaunch(resp *http.Response, sid string) error {
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		return nil
	}
	// Refuse to touch a compressed body: injecting into gzip bytes corrupts the
	// document. Accept-Encoding was stripped upstream so the Transport hands us
	// identity here, but if that ever fails we skip (leaving the flag for a later
	// identity load) rather than mangle the page. Checked before consuming the
	// one-shot flag so a stray compressed response doesn't waste it.
	if resp.Header.Get("Content-Encoding") != "" {
		return nil
	}
	if !m.sessions.takeAutoLaunch(sid) {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	body = injectBeforeBodyClose(body, autoLaunchScript)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return nil
}

// injectBeforeBodyClose inserts script just before the last </body> (or </html>,
// or appends) so it runs after the SPA's own scripts are in the document.
func injectBeforeBodyClose(htmlDoc []byte, script string) []byte {
	lower := bytes.ToLower(htmlDoc)
	at := bytes.LastIndex(lower, []byte("</body>"))
	if at < 0 {
		at = bytes.LastIndex(lower, []byte("</html>"))
	}
	if at < 0 {
		return append(htmlDoc, script...)
	}
	out := make([]byte, 0, len(htmlDoc)+len(script))
	out = append(out, htmlDoc[:at]...)
	out = append(out, script...)
	out = append(out, htmlDoc[at:]...)
	return out
}

// proxyScheme returns the scheme the browser used to reach the proxy, honoring
// the X-Forwarded-Proto set by Traefik (which may be a comma list). Mirrors the
// web package's requestScheme.
func proxyScheme(r *http.Request) string {
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		first, _, _ := strings.Cut(proto, ",")
		return strings.ToLower(strings.TrimSpace(first))
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// rewriteLocation rewrites a redirect that points at the iDRAC host so it points
// at the proxy host instead; relative and other-host Locations are left alone.
func rewriteLocation(resp *http.Response, ip, proxyHost, scheme string) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	u, err := url.Parse(loc)
	if err != nil {
		return
	}
	// Compare on hostname so a redirect to https://<ip>:443/... (common from
	// iDRAC) is matched even though ip may itself carry a port (in tests).
	if u.Hostname() == stripPort(ip) {
		u.Scheme = scheme
		u.Host = proxyHost
		resp.Header.Set("Location", u.String())
	}
}

// rewriteSetCookies captures the iDRAC session cookie into server-side state
// (and strips it from the browser-facing response); other cookies are
// host-scoped to the subdomain by dropping their Domain attribute.
func (m *Manager) rewriteSetCookies(resp *http.Response, sid string) {
	lines := resp.Header.Values("Set-Cookie")
	if len(lines) == 0 {
		return
	}
	var out []string
	for _, line := range lines {
		c, err := http.ParseSetCookie(line)
		if err != nil {
			out = append(out, line)
			continue
		}
		if c.Name == idracSessionCookie {
			m.sessions.updateCookie(sid, c.Name+"="+c.Value)
			continue
		}
		c.Domain = ""
		out = append(out, c.String())
	}
	resp.Header.Del("Set-Cookie")
	for _, line := range out {
		resp.Header.Add("Set-Cookie", line)
	}
}

// Handler serves one request on a proxy host: the auth handshake, or a relay.
func (m *Manager) Handler(w http.ResponseWriter, r *http.Request) {
	id, ok := m.HostServerID(r.Host)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/__labmgr/auth" {
		m.handleAuth(w, r, id)
		return
	}
	m.relay(w, r, id)
}

// handleAuth verifies the handshake token, logs into the iDRAC server-side,
// stores the session, sets the opaque proxy cookie, and redirects the browser
// to the SPA forward URL.
func (m *Manager) handleAuth(w http.ResponseWriter, r *http.Request, id int64) {
	if !verifyToken(m.secret, r.URL.Query().Get("token"), id) {
		// Bounce through the login-gated initiator to re-mint.
		http.Redirect(w, r, m.appBaseURL(r)+"/server/"+strconv.FormatInt(id, 10)+"/kvm", http.StatusFound)
		return
	}
	s, err := m.lookup.GetServer(id)
	if err != nil || s.BMCType != model.BMCIDRAC {
		http.NotFound(w, r)
		return
	}
	user, pass := s.RedfishUser, s.RedfishPassword
	if user == "" {
		user, pass = s.IPMIUser, s.IPMIPassword
	}
	if user == "" {
		m.errorPage(w, r, id, "No credentials configured for this server")
		return
	}
	cookie, forwardURL, err := idracLogin(r.Context(), s.IPAddress, user, pass)
	if err != nil {
		slog.Error("bmcproxy iDRAC login", "server_id", id, "err", err)
		m.errorPage(w, r, id, err.Error())
		return
	}
	sid, displaced, err := m.sessions.create(id, s.IPAddress, cookie)
	if err != nil {
		slog.Error("bmcproxy session create", "server_id", id, "err", err)
		m.errorPage(w, r, id, "internal error")
		return
	}
	// Log out any prior iDRAC session for this server so repeated launches
	// don't pile up on the iDRAC's small web-session table.
	for _, d := range displaced {
		go m.logoutIDRAC(d.ip, d.idracCookie)
	}
	// Flag this session so the dashboard we're about to land on gets the
	// auto-launch script injected — it clicks the console open for the operator.
	m.sessions.setAutoLaunch(sid)
	http.SetCookie(w, &http.Cookie{
		Name:     proxyCookieName,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		// Secure only over HTTPS: a Secure cookie is dropped by the browser on
		// a plain-HTTP origin, which would silently break the dev flow. Mirrors
		// the session cookie in internal/web/session.go.
		Secure:   proxyScheme(r) == "https",
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, safeForwardPath(forwardURL), http.StatusFound)
}

// safeForwardPath keeps only the path+query of the iDRAC-supplied forward URL,
// dropping any scheme/host so a malicious or compromised iDRAC cannot
// open-redirect the browser off-site (e.g. "//evil.com/x").
func safeForwardPath(forwardURL string) string {
	u, err := url.Parse(forwardURL)
	if err != nil {
		return "/"
	}
	dest := u.EscapedPath()
	if u.RawQuery != "" {
		dest += "?" + u.RawQuery
	}
	if !strings.HasPrefix(dest, "/") {
		dest = "/" + dest
	}
	return dest
}

// errorPage renders a proxy failure. serverID > 0 adds a link to that server's
// credentials page: auto-login is now the primary Console action, so a failure
// here would otherwise dead-end with no way to reach the manual fallback.
func (m *Manager) errorPage(w http.ResponseWriter, r *http.Request, serverID int64, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	base := m.appBaseURL(r)
	fmt.Fprintf(w,
		`<!doctype html><meta charset="utf-8"><title>iDRAC proxy</title>`+
			`<body style="font-family:sans-serif;background:#1a1a2e;color:#fff;padding:40px">`+
			`<h2 style="color:#ef4444">Could not open iDRAC</h2><p>%s</p>`,
		html.EscapeString(msg))
	if serverID > 0 {
		fmt.Fprintf(w,
			`<p><a style="color:#60a5fa" href="%s/server/%d/console/manual">`+
				`Open the credentials page for manual login &rarr;</a></p>`,
			html.EscapeString(base), serverID)
	}
	fmt.Fprintf(w, `<p><a style="color:#60a5fa" href="%s/">&larr; Back to lab-manager</a></p>`,
		html.EscapeString(base))
}
