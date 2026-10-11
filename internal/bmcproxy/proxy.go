package bmcproxy

import (
	"bytes"
	"fmt"
	"html"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkilar/lab-manager/internal/model"
)

// proxyCookieName is the opaque session cookie the browser holds on the proxy
// subdomain. It maps to server-side state (the injected BMC cookie).
const proxyCookieName = "bmcproxy"

// ServerLookup fetches a server by id; *store.Store satisfies it.
type ServerLookup interface {
	GetServer(id int64) (*model.Server, error)
}

// Manager serves the BMC reverse proxy for <vendor>-<id>.<domain> hosts
// (iDRAC and PiKVM today).
type Manager struct {
	lookup   ServerLookup
	secret   []byte
	domain   string // e.g. "pi.home.kilar.net"; empty disables the feature
	sessions *sessionStore

	done      chan struct{} // closed by Close to stop sessionGC
	closeOnce sync.Once
}

// NewManager builds a proxy Manager and starts its session GC. A blank domain
// yields a disabled manager (Enabled() == false).
func NewManager(lookup ServerLookup, secret []byte, domain string) *Manager {
	m := &Manager{lookup: lookup, secret: secret, domain: domain, sessions: newSessionStore(), done: make(chan struct{})}
	if m.Enabled() {
		go m.sessionGC()
	}
	return m
}

func (m *Manager) sessionGC() {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
		}
		for _, sess := range m.sessions.gc() {
			sess.vendor.logout(sess.ip, sess.bmcCookie)
		}
	}
}

// Close stops the session GC and logs every live proxy session out of its
// BMC (via the vendor each was created with), returning once all logouts finish
// (each is bounded by the vendor logout's own 10s timeout). It is meant for process shutdown: without it the sessions would
// sit in the BMCs' small web-session tables until the BMC times them out.
// Idempotent and nil-safe.
func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() {
		close(m.done)
		var wg sync.WaitGroup
		for _, sess := range m.sessions.drain() {
			wg.Go(func() { sess.vendor.logout(sess.ip, sess.bmcCookie) })
		}
		wg.Wait()
	})
}

// Enabled reports whether the proxy feature is configured.
func (m *Manager) Enabled() bool { return m != nil && m.domain != "" }

// resolveHost returns the server id and vendor when host is a proxy host for
// this manager's domain.
func (m *Manager) resolveHost(host string) (int64, *vendor, bool) {
	if !m.Enabled() {
		return 0, nil, false
	}
	mt := hostIDPattern.FindStringSubmatch(stripPort(host))
	if mt == nil || mt[3] != m.domain {
		return 0, nil, false
	}
	id, err := strconv.ParseInt(mt[2], 10, 64)
	if err != nil {
		return 0, nil, false
	}
	for _, v := range vendors {
		if v.hostPrefix == mt[1] {
			return id, v, true
		}
	}
	return 0, nil, false
}

// HostServerID returns the server id when host is a proxy host (any known
// vendor prefix) for this manager's domain.
func (m *Manager) HostServerID(host string) (int64, bool) {
	id, _, ok := m.resolveHost(host)
	return id, ok
}

// Supports reports whether the proxy is enabled and has a vendor for bmcType.
func (m *Manager) Supports(bmcType string) bool {
	return m.Enabled() && vendorFor(bmcType) != nil
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
//
// bmcType picks the host prefix; an unknown type falls back to the iDRAC prefix
// (callers should gate on Supports). target, when non-empty, is appended as the
// url-escaped `to` parameter selecting a vendor landing page (e.g.
// TargetTerminal); with "" the URL is byte-identical to the pre-PiKVM output.
func (m *Manager) AuthURL(scheme, hostPort, bmcType string, serverID int64, token, target string) string {
	v := vendorFor(bmcType)
	if v == nil {
		v = idracVendor
	}
	host := fmt.Sprintf("%s-%d.%s", v.hostPrefix, serverID, m.domain)
	u := fmt.Sprintf("%s://%s/__labmgr/auth?token=%s", scheme, withPortOf(hostPort, host), token)
	if target != "" {
		u += "&to=" + url.QueryEscape(target)
	}
	return u
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
// virtual console from (vendor.consolePort). The console SPA builds its URL from
// window.location.host, so it arrives here as idrac-<id>.<domain>:5900 rather
// than pointing at the BMC directly — which means it can be proxied, but only
// if the request is forwarded to the BMC's 5900 instead of 443.
const bmcConsolePort = "5900"

// upstreamHost picks the BMC address to forward to, honouring the vendor's
// separate console port (if any). Only v.consolePort is passed through: any
// other inbound port is the app's own listener (":5000" in development) and
// must not be forwarded to the BMC.
func upstreamHost(v *vendor, ip, inboundHost string) string {
	if v.consolePort == "" {
		return ip
	}
	if _, port, err := net.SplitHostPort(inboundHost); err == nil && port == v.consolePort {
		return net.JoinHostPort(stripPort(ip), v.consolePort)
	}
	return ip
}

// relay proxies an authenticated request to the BMC, injecting the
// server-side session cookie. A single ReverseProxy handles both plain HTTP and
// the KVM WebSocket (it natively tunnels Upgrade requests).
func (m *Manager) relay(w http.ResponseWriter, r *http.Request, id int64, v *vendor) {
	if crossSiteWrite(r) {
		http.Error(w, "cross-site request refused", http.StatusForbidden)
		return
	}
	sess, sid, ok := m.sessionFor(r)
	if !ok || sess.serverID != id {
		m.bounceToInitiator(w, r, id, v)
		return
	}
	s, err := m.lookup.GetServer(id)
	if err != nil {
		http.Error(w, "server not found", http.StatusNotFound)
		return
	}
	if s.IPAddress != sess.ip || sess.vendor != v || s.BMCType != v.bmcType {
		// The server's address (or BMC type) changed since login: the session
		// cookie belongs to the old BMC and must not be replayed to whatever is
		// at the new address, nor across vendors. Release it where it was
		// issued and force a fresh handshake.
		if removed, ok := m.sessions.remove(sid); ok {
			go removed.vendor.logout(removed.ip, removed.bmcCookie)
		}
		m.bounceToInitiator(w, r, id, v)
		return
	}
	m.serveHTTP(w, r, v, sid, upstreamHost(v, s.IPAddress, r.Host), sess.bmcCookie)
}

// bounceToInitiator sends the browser back through the login-gated initiator.
// For a vendor with landing targets, a request under a non-default target's
// path (e.g. the PiKVM terminal) carries ?to=<name> so the fresh handshake
// returns to the same page.
func (m *Manager) bounceToInitiator(w http.ResponseWriter, r *http.Request, id int64, v *vendor) {
	dest := m.appBaseURL(r) + "/server/" + strconv.FormatInt(id, 10) + "/kvm"
	if name := v.targetName(r.URL.Path); name != "" {
		dest += "?to=" + url.QueryEscape(name)
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// crossSiteWrite reports whether r is a state-changing request or a WebSocket
// upgrade carrying an Origin from a different host. The proxy cookie is
// SameSite=Lax and Rewrite overwrites Origin with the BMC's, so a page on a
// sibling *.<domain> host (same-site) could otherwise drive the iDRAC with the
// operator's session. Ports are ignored on purpose: the console WebSocket on
// :5900 is opened by the :443 page of the same host. A missing Origin is
// allowed (browsers always send one on these requests; non-browser clients
// can't carry the victim's cookie); "null" yields an empty hostname and fails.
func crossSiteWrite(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		if !isWebSocketUpgrade(r) {
			return false
		}
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return true
	}
	return !strings.EqualFold(u.Hostname(), stripPort(r.Host))
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.Contains(strings.ToLower(strings.Join(r.Header.Values("Connection"), ",")), "upgrade") &&
		strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket")
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

func (m *Manager) serveHTTP(w http.ResponseWriter, r *http.Request, v *vendor, sid, ip, bmcCookie string) {
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
			// session, then inject the server-held BMC session (if any).
			var keep []string
			for _, c := range pr.Out.Cookies() {
				if c.Name == proxyCookieName || c.Name == v.sessionCookie {
					continue
				}
				keep = append(keep, c.Name+"="+c.Value)
			}
			if bmcCookie != "" {
				keep = append(keep, bmcCookie)
			}
			if len(keep) > 0 {
				pr.Out.Header.Set("Cookie", strings.Join(keep, "; "))
			} else {
				pr.Out.Header.Del("Cookie")
			}
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
			m.rewriteSetCookies(resp, sid, v)
			if !v.autoLaunch {
				return nil
			}
			return m.maybeInjectAutoLaunch(resp, sid)
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			slog.Error("bmcproxy upstream", "vendor", v.name, "ip", ip, "err", err)
			http.Error(w, v.name+" unreachable", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

// autoLaunchScript is injected once into the iDRAC dashboard after login so the
// operator is one click from the KVM instead of hunting for the console tab. It
// cannot be done by URL: the HTML5 viewer is a popup child of this SPA (it reads
// window.opener), so only the SPA's own QuickLaunch can open it correctly.
//
// It deliberately does NOT auto-invoke QuickLaunch. A script-driven window.open
// with no user gesture is blocked by the browser, and QuickLaunch called while
// blocked fires a malformed inter-frame message the dashboard reports as
// "Unknown viewer request: 0". So instead the script drops a single fixed button
// and calls QuickLaunch only from the click — a real gesture, never blocked and
// never triggering that alert. The dashboard is a frameset and QuickLaunch lives
// in a nested child frame, so the script walks every same-origin frame to find
// the one that defines it.
const autoLaunchScript = `<script>(function(){
  var T; try { T = window.top; } catch (e) { return; }
  if (T.__labmgrKVM) return; T.__labmgrKVM = 1;
  function find(w){
    try { if (typeof w.QuickLaunch === 'function') return w; } catch (e) { return null; }
    var n = 0; try { n = w.frames.length; } catch (e) { return null; }
    for (var i = 0; i < n; i++){ var f = find(w.frames[i]); if (f) return f; }
    return null;
  }
  function button(w){
    var d; try { d = w.document; } catch (e) { return; }
    if (!d || d.getElementById('labmgr-kvm')) return;
    var b = d.createElement('button');
    b.id = 'labmgr-kvm';
    b.textContent = '▶︎  Launch Virtual Console';
    b.style.cssText = 'position:fixed;z-index:2147483647;top:14px;right:14px;padding:12px 18px;'
      + 'font:600 14px system-ui,-apple-system,sans-serif;color:#fff;background:#2563eb;border:0;'
      + 'border-radius:8px;cursor:pointer;box-shadow:0 6px 18px rgba(0,0,0,.4)';
    b.onclick = function(){ try { w.QuickLaunch('viewer'); } catch (e) {} b.remove(); };
    (d.body || d.documentElement).appendChild(b);
  }
  var tries = 0;
  (function attempt(){
    var w = find(T);
    if (!w){ if (++tries > 150) return; setTimeout(attempt, 200); return; } // wait for frames to load
    button(w);
  })();
})();</script>`

// maxInjectBody caps how much of a response maybeInjectAutoLaunch will buffer.
// The dashboard shell is a few KiB; anything larger is not it.
const maxInjectBody = 4 << 20

// maybeInjectAutoLaunch injects autoLaunchScript into the first dashboard
// document of a freshly authenticated session, then clears the one-shot flag so
// later navigation is untouched. Only a 200 GET answered with exactly text/html
// qualifies; redirects, errors, HEADs, assets and XHR/JSON pass through without
// touching the flag. Accept-Encoding was stripped upstream, so the body is
// identity and needs no gzip handling.
func (m *Manager) maybeInjectAutoLaunch(resp *http.Response, sid string) error {
	if resp.Request == nil || resp.Request.Method != http.MethodGet || resp.StatusCode != http.StatusOK {
		return nil
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != "text/html" {
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
	if !m.sessions.pendingAutoLaunch(sid) {
		return nil
	}
	orig := resp.Body
	body, err := io.ReadAll(io.LimitReader(orig, maxInjectBody+1))
	if err != nil {
		_ = orig.Close()
		return err
	}
	if len(body) > maxInjectBody {
		// Not a dashboard shell: hand the body on untouched, flag preserved.
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(body), orig), orig}
		return nil
	}
	_ = orig.Close()
	if !m.sessions.takeAutoLaunch(sid) {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return nil
	}
	body = injectScript(body, autoLaunchScript)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return nil
}

// injectScript inserts script so it executes on load. It prefers just before
// </head>, because the iDRAC dashboard is a frameset document and a frameset
// only runs scripts in its head — a script placed after </frameset> (i.e. near
// </body>/</html>) is inert. Injecting in the head runs the script before the
// frames exist, which is fine: it polls for the frame that defines QuickLaunch.
// Falls back to </body>, then </html>, then appends.
func injectScript(htmlDoc []byte, script string) []byte {
	lower := bytes.ToLower(htmlDoc)
	for _, anchor := range []string{"</head>", "</body>", "</html>"} {
		if at := bytes.LastIndex(lower, []byte(anchor)); at >= 0 {
			out := make([]byte, 0, len(htmlDoc)+len(script))
			out = append(out, htmlDoc[:at]...)
			out = append(out, script...)
			out = append(out, htmlDoc[at:]...)
			return out
		}
	}
	return append(htmlDoc, script...)
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

// rewriteSetCookies captures the vendor's BMC session cookie into server-side
// state (and strips it from the browser-facing response); other cookies are
// host-scoped to the subdomain by dropping their Domain attribute.
func (m *Manager) rewriteSetCookies(resp *http.Response, sid string, v *vendor) {
	lines := resp.Header.Values("Set-Cookie")
	if len(lines) == 0 {
		return
	}
	var out []string
	for _, line := range lines {
		c, err := http.ParseSetCookie(line)
		if err != nil {
			// Fail closed for the session cookie only: an unparseable line
			// named like the session cookie would otherwise hand the real token
			// to the browser (and never reach the store). Other unparseable
			// cookies keep passing through verbatim -- the BMC UI cookies
			// that work today must not start vanishing.
			name, _, _ := strings.Cut(line, "=")
			if strings.TrimSpace(name) == v.sessionCookie {
				slog.Warn("bmcproxy dropped unparseable BMC session Set-Cookie", "vendor", v.name, "cookie", v.sessionCookie, "err", err)
				continue
			}
			out = append(out, line)
			continue
		}
		if c.Name == v.sessionCookie {
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
	id, v, ok := m.resolveHost(r.Host)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/__labmgr/auth" {
		m.handleAuth(w, r, id, v)
		return
	}
	m.relay(w, r, id, v)
}

// handleAuth verifies the handshake token, logs into the BMC server-side,
// stores the session, sets the opaque proxy cookie, and redirects the browser
// to the vendor's landing page. A vendor with reuseSession skips the login when
// the browser already holds a valid session for the same server.
func (m *Manager) handleAuth(w http.ResponseWriter, r *http.Request, id int64, v *vendor) {
	q := r.URL.Query()
	if !verifyToken(m.secret, q.Get("token"), id) {
		// Bounce through the login-gated initiator to re-mint, keeping a valid
		// landing target so an expired terminal handshake returns to it.
		dest := m.appBaseURL(r) + "/server/" + strconv.FormatInt(id, 10) + "/kvm"
		if to := q.Get("to"); to != "" {
			if _, ok := v.targets[to]; ok {
				dest += "?to=" + url.QueryEscape(to)
			}
		}
		http.Redirect(w, r, dest, http.StatusFound)
		return
	}
	s, err := m.lookup.GetServer(id)
	if err != nil || s.BMCType != v.bmcType {
		http.NotFound(w, r)
		return
	}
	if v.sessionValid != nil {
		// A second tab (KVM vs terminal) on the same host: a fresh login would
		// log out the session the first tab is using and the BMC would drop it.
		// A session the BMC no longer honours falls through to a fresh login,
		// which displaces (and logs out) the dead one.
		if sess, _, ok := m.sessionFor(r); ok && sess.serverID == id && sess.ip == s.IPAddress && sess.vendor == v &&
			v.sessionValid(r.Context(), s.IPAddress, sess.bmcCookie) {
			http.Redirect(w, r, v.targetPath(q.Get("to")), http.StatusFound)
			return
		}
	}
	user, pass := s.RedfishUser, s.RedfishPassword
	if user == "" {
		user, pass = s.IPMIUser, s.IPMIPassword
	}
	if user == "" {
		m.errorPage(w, r, id, v, "No credentials configured for this server")
		return
	}
	cookie, forwardURL, err := v.login(r.Context(), s.IPAddress, user, pass)
	if err != nil {
		slog.Error("bmcproxy login", "vendor", v.name, "server_id", id, "err", err)
		m.errorPage(w, r, id, v, err.Error())
		return
	}
	sid, displaced, err := m.sessions.create(v, id, s.IPAddress, cookie)
	if err != nil {
		slog.Error("bmcproxy session create", "server_id", id, "err", err)
		m.errorPage(w, r, id, v, "internal error")
		return
	}
	// Log out any prior BMC session for this server (via its own vendor) so
	// repeated launches don't pile up on the BMC's small web-session table.
	for _, d := range displaced {
		go d.vendor.logout(d.ip, d.bmcCookie)
	}
	if v.autoLaunch {
		// Flag this session so the dashboard we're about to land on gets the
		// auto-launch script injected — it clicks the console open for the operator.
		m.sessions.setAutoLaunch(sid)
	}
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
	dest := safeForwardPath(forwardURL)
	if v.targets != nil {
		dest = v.targetPath(q.Get("to"))
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// safeForwardPath keeps only the path+query of the BMC-supplied forward URL,
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
func (m *Manager) errorPage(w http.ResponseWriter, r *http.Request, serverID int64, v *vendor, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	base := m.appBaseURL(r)
	fmt.Fprintf(w,
		`<!doctype html><meta charset="utf-8"><title>%s proxy</title>`+
			`<body style="font-family:sans-serif;background:#1a1a2e;color:#fff;padding:40px">`+
			`<h2 style="color:#ef4444">Could not open %s</h2><p>%s</p>`,
		html.EscapeString(v.name), html.EscapeString(v.name), html.EscapeString(msg))
	if serverID > 0 {
		fmt.Fprintf(w,
			`<p><a style="color:#60a5fa" href="%s/server/%d/console/manual">`+
				`Open the credentials page for manual login &rarr;</a></p>`,
			html.EscapeString(base), serverID)
	}
	fmt.Fprintf(w, `<p><a style="color:#60a5fa" href="%s/">&larr; Back to lab-manager</a></p>`,
		html.EscapeString(base))
}
