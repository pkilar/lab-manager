package bmcproxy

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
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
