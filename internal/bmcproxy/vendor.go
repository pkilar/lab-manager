package bmcproxy

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/pkilar/lab-manager/internal/model"
)

// TargetTerminal names the PiKVM web-terminal landing page (see vendor.targets).
const TargetTerminal = "terminal"

// vendor captures everything that differs between the BMC families the proxy
// fronts. A proxy host is <hostPrefix>-<server id>.<domain>; the handshake,
// relay and session cleanup are otherwise vendor-neutral.
type vendor struct {
	bmcType    string // model.BMC* value a server must have to be served here
	hostPrefix string // subdomain prefix, e.g. "idrac" -> idrac-<id>.<domain>
	name       string // human name for logs and error pages

	// sessionCookie is the upstream cookie that carries the BMC login. It is
	// captured from upstream Set-Cookie into server state, stripped from any
	// client-supplied Cookie header, and never shown to the browser.
	sessionCookie string

	// login authenticates server-side. cookie is the full "name=value" to
	// inject upstream (empty when the BMC needs none); forwardURL is the
	// vendor-supplied landing path (empty when the vendor uses targets).
	login func(ctx context.Context, ip, user, pass string) (cookie, forwardURL string, err error)
	// logout releases a BMC session. Best-effort, own background deadline,
	// no-op on empty ip/cookie, never logs the cookie.
	logout func(ip, cookie string)

	// targets maps the handshake's `to` enum to a landing path; "" is the
	// default. nil means land on safeForwardPath(forwardURL).
	targets map[string]string

	autoLaunch bool // inject the one-shot console launcher into the first dashboard
	// consolePort is a separate BMC listener whose inbound port is passed
	// through to the BMC (iDRAC virtual console on 5900); "" always uses 443.
	consolePort string
	// sessionValid, when set, lets a handshake carrying a valid proxy cookie for
	// the same server skip the login — logging in again would displace the
	// session an already-open tab depends on — provided the BMC still accepts
	// the held cookie. Asking the BMC matters: the proxy's record outlives the
	// BMC's (a PiKVM reboot drops every token; a Logout click inside the UI
	// revokes it), and reusing a dead cookie would land every later launch on
	// the BMC's login page until the proxy session expired. nil: never reuse.
	sessionValid func(ctx context.Context, ip, cookie string) bool
}

var idracVendor = &vendor{
	bmcType:       model.BMCIDRAC,
	hostPrefix:    "idrac",
	name:          "iDRAC",
	sessionCookie: idracSessionCookie,
	login:         idracLogin,
	logout:        idracLogout,
	autoLaunch:    true,
	consolePort:   bmcConsolePort,
}

var pikvmVendor = &vendor{
	bmcType:       model.BMCPiKVM,
	hostPrefix:    "pikvm",
	name:          "PiKVM",
	sessionCookie: pikvmSessionCookie,
	login:         pikvmLogin,
	logout:        pikvmLogout,
	targets: map[string]string{
		"":             "/kvm/",
		TargetTerminal: "/extras/webterm/ttyd/",
	},
	sessionValid: pikvmSessionValid,
}

var vendors = []*vendor{idracVendor, pikvmVendor}

// vendorFor returns the vendor serving a BMC type, or nil.
func vendorFor(bmcType string) *vendor {
	for _, v := range vendors {
		if v.bmcType == bmcType {
			return v
		}
	}
	return nil
}

// hostIDPattern matches <prefix>-<id>.<rest> for every known vendor prefix.
var hostIDPattern = func() *regexp.Regexp {
	var prefixes []string
	for _, v := range vendors {
		prefixes = append(prefixes, regexp.QuoteMeta(v.hostPrefix))
	}
	return regexp.MustCompile(`^(` + strings.Join(prefixes, "|") + `)-(\d+)\.(.+)$`)
}()

// targetPath resolves the handshake's `to` value. Unknown values fall back to
// the default: it is an enum, never a client-supplied path.
func (v *vendor) targetPath(to string) string {
	if p, ok := v.targets[to]; ok {
		return p
	}
	return v.targets[""]
}

// targetName returns the non-default target whose path prefixes urlPath, or "".
func (v *vendor) targetName(urlPath string) string {
	for name, p := range v.targets {
		if name != "" && strings.HasPrefix(urlPath, p) {
			return name
		}
	}
	return ""
}

// idracLogout releases an iDRAC web session (-http-session-) so repeated KVM
// launches don't exhaust the iDRAC's small web-session table.
func idracLogout(ip, cookie string) {
	bmcLogout(http.MethodGet, ip, "/data/logout", cookie)
}

// pikvmLogout releases a PiKVM auth_token session.
func pikvmLogout(ip, cookie string) {
	bmcLogout(http.MethodPost, ip, "/api/auth/logout", cookie)
}

// bmcLogout is the shared best-effort logout: its own 10s background deadline
// so it completes even when the originating request is gone.
func bmcLogout(method, ip, path, cookie string) {
	if ip == "" || cookie == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "https://"+ip+path, nil)
	if err != nil {
		return
	}
	req.Header.Set("Cookie", cookie)
	resp, err := loginClient.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}
