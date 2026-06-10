package bmcproxy

import (
	"fmt"
	"log"
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
		m.sessions.gc()
	}
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
func (m *Manager) AuthURL(serverID int64, token string) string {
	return fmt.Sprintf("https://idrac-%d.%s/__labmgr/auth?token=%s", serverID, m.domain, token)
}

// appBaseURL is the main app's external URL (used to bounce expired sessions
// back through the login-gated initiator). The app is deployed at lab.<domain>.
func (m *Manager) appBaseURL() string { return "https://lab." + m.domain }

// relay proxies an authenticated request to the iDRAC, injecting the
// server-side session cookie. A single ReverseProxy handles both plain HTTP and
// the KVM WebSocket (it natively tunnels Upgrade requests).
func (m *Manager) relay(w http.ResponseWriter, r *http.Request, id int64) {
	sess, sid := m.sessionFor(r)
	if sess == nil || sess.serverID != id {
		http.Redirect(w, r, m.appBaseURL()+"/server/"+strconv.FormatInt(id, 10)+"/kvm", http.StatusFound)
		return
	}
	s, err := m.lookup.GetServer(id)
	if err != nil {
		http.Error(w, "server not found", http.StatusNotFound)
		return
	}
	m.serveHTTP(w, r, sid, s.IPAddress, sess.idracCookie)
}

func (m *Manager) sessionFor(r *http.Request) (*proxySession, string) {
	c, err := r.Cookie(proxyCookieName)
	if err != nil {
		return nil, ""
	}
	sess, ok := m.sessions.get(c.Value)
	if !ok {
		return nil, ""
	}
	return sess, c.Value
}

func (m *Manager) serveHTTP(w http.ResponseWriter, r *http.Request, sid, ip, idracCookie string) {
	rp := &httputil.ReverseProxy{
		Transport: proxyTransport,
		Director: func(req *http.Request) {
			req.URL.Scheme = "https"
			req.URL.Host = ip
			req.Host = ip
			req.Header.Set("Origin", "https://"+ip)
			req.Header.Set("Referer", "https://"+ip+"/")
			// Rebuild Cookie: drop our proxy cookie and any client-supplied
			// session, then inject the server-held iDRAC session.
			var keep []string
			for _, c := range req.Cookies() {
				if c.Name == proxyCookieName || c.Name == idracSessionCookie {
					continue
				}
				keep = append(keep, c.Name+"="+c.Value)
			}
			keep = append(keep, idracCookie)
			req.Header.Set("Cookie", strings.Join(keep, "; "))
		},
		ModifyResponse: func(resp *http.Response) error {
			rewriteLocation(resp, ip, r.Host, proxyScheme(r))
			m.rewriteSetCookies(resp, sid)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Printf("ERROR: bmcproxy upstream %s: %v", ip, err)
			http.Error(w, "iDRAC unreachable", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
}

// proxyScheme returns the scheme the browser used to reach the proxy.
func proxyScheme(r *http.Request) string {
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
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
	if u.Host == ip {
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
