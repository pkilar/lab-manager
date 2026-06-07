// Package console implements the token-gated BMC console launch subsystem:
// short-lived access tokens, per-vendor login configuration, and the iDRAC
// server-side credential pre-flight.
package console

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkilar/lab-manager/internal/model"
)

// TokenValiditySeconds bounds how long a console launch token is usable.
const TokenValiditySeconds = 30

// Manager issues and verifies console access tokens and runs the iDRAC
// credential pre-flight.
type Manager struct {
	secretKey []byte
}

// NewManager builds a console Manager keyed by the application secret.
func NewManager(secretKey []byte) *Manager {
	return &Manager{secretKey: secretKey}
}

// insecureClient returns an HTTP client that skips TLS verification — BMCs use
// self-signed certificates, so certificate validation is disabled throughout.
func insecureClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // BMCs use self-signed certs
		},
	}
}

// CredsFor returns the (username, password) the console/protocol code should
// use: Redfish credentials take precedence over IPMI.
func CredsFor(s *model.Server) (string, string) {
	if s.RedfishUser != "" {
		return s.RedfishUser, s.RedfishPassword
	}
	if s.IPMIUser != "" {
		return s.IPMIUser, s.IPMIPassword
	}
	return "", ""
}

// ---- console access tokens ----------------------------------------------

func (m *Manager) GenerateToken(serverID, userID int64) string {
	ts := time.Now().Unix()
	sig := hmacHex(m.secretKey, fmt.Sprintf("%d:%d:%d", serverID, userID, ts))
	return base64.URLEncoding.EncodeToString(fmt.Appendf(nil, "%d:%s", ts, sig))
}

func (m *Manager) VerifyToken(token string, serverID, userID int64) bool {
	raw, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return false
	}
	tsStr, sig, ok := strings.Cut(string(raw), ":")
	if !ok {
		return false
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	if time.Now().Unix()-ts > TokenValiditySeconds {
		return false
	}
	expected := hmacHex(m.secretKey, fmt.Sprintf("%d:%d:%d", serverID, userID, ts))
	return subtle.ConstantTimeCompare([]byte(sig), []byte(expected)) == 1
}

func hmacHex(key []byte, message string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// ---- BMC login configuration --------------------------------------------

type BMCLoginConfig struct {
	LoginURL          string
	ConsoleURL        string
	SupportsAutoLogin bool
}

// LoginConfigFor returns per-vendor login/console URLs, or nil when the server
// has no credentials configured.
func LoginConfigFor(s *model.Server) *BMCLoginConfig {
	if s.RedfishUser == "" && s.IPMIUser == "" {
		return nil
	}
	ip := s.IPAddress
	switch s.BMCType {
	case model.BMCIDRAC:
		return &BMCLoginConfig{
			LoginURL:          "https://" + ip + "/data/login",
			ConsoleURL:        "https://" + ip + "/console",
			SupportsAutoLogin: true,
		}
	case model.BMCSupermicro:
		return &BMCLoginConfig{
			LoginURL:          "https://" + ip + "/cgi/login.cgi",
			ConsoleURL:        "https://" + ip + "/cgi/url_redirect.cgi?url_name=man_ikvm_html5_bootstrap",
			SupportsAutoLogin: true,
		}
	case model.BMCILO:
		return &BMCLoginConfig{
			LoginURL:          "https://" + ip + "/json/login_session",
			ConsoleURL:        "https://" + ip + "/html5/html5client.html",
			SupportsAutoLogin: false,
		}
	default: // generic / unknown
		return &BMCLoginConfig{
			LoginURL:          "",
			ConsoleURL:        "https://" + ip + "/",
			SupportsAutoLogin: false,
		}
	}
}

// ---- iDRAC server-side credential pre-flight -----------------------------

type IDRACAuthResult struct {
	Success      bool
	Method       string
	IDRACVersion string
	ConsoleURL   string
	Error        string
}

// PreAuthenticateIDRAC validates iDRAC credentials without leaking a session.
// Any Redfish session opened during validation is deleted before returning, so
// console launches can't exhaust the iDRAC session table.
func (m *Manager) PreAuthenticateIDRAC(s *model.Server) IDRACAuthResult {
	ip := s.IPAddress
	res := IDRACAuthResult{ConsoleURL: "https://" + ip + "/console"}

	user, pass := CredsFor(s)
	if user == "" {
		res.Error = "No credentials configured"
		return res
	}

	if idracRedfishPreAuth(ip, user, pass, &res) {
		idracLegacyPreAuth(ip, user, pass, &res)
	}
	return res
}

// idracRedfishPreAuth tries the Redfish SessionService (iDRAC 8/9). It returns
// true when the caller should fall through to the legacy method.
func idracRedfishPreAuth(ip, user, pass string, res *IDRACAuthResult) (tryLegacy bool) {
	client := insecureClient(30 * time.Second)

	var sessionToken, sessionLocation string
	defer func() {
		// Always drop any session we created, on every return path.
		if sessionToken != "" && sessionLocation != "" {
			idracCleanupSession(ip, sessionToken, sessionLocation)
		}
	}()

	body, _ := json.Marshal(map[string]string{"UserName": user, "Password": pass})
	req, err := http.NewRequest(http.MethodPost, "https://"+ip+"/redfish/v1/SessionService/Sessions", bytes.NewReader(body))
	if err != nil {
		res.Error = err.Error()
		return true
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			res.Error = "Connection timeout"
			return true // a timeout may still let the legacy path through
		}
		res.Error = "Connection failed - iDRAC may be unreachable"
		return false // unreachable: no point trying the legacy endpoint
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		sessionToken = resp.Header.Get("X-Auth-Token")
		sessionLocation = resp.Header.Get("Location")
		res.Success = true
		res.Method = "redfish"
		if sessionToken != "" {
			res.IDRACVersion = idracFirmwareVersion(ip, sessionToken)
		}
		return false
	case http.StatusUnauthorized:
		res.Error = "Invalid credentials"
		return true
	default:
		res.Error = fmt.Sprintf("Redfish auth failed with status %d", resp.StatusCode)
		return true
	}
}

func idracFirmwareVersion(ip, token string) string {
	client := insecureClient(10 * time.Second)
	req, err := http.NewRequest(http.MethodGet, "https://"+ip+"/redfish/v1/Managers/iDRAC.Embedded.1", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("X-Auth-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var data map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data); err != nil {
		// A JSON-parse failure leaves the version unset (treated the same as
		// no version reported).
		return ""
	}
	if v, ok := data["FirmwareVersion"].(string); ok {
		return v
	}
	// 200 OK with valid JSON but no FirmwareVersion key: fall back to
	// "Unknown".
	return "Unknown"
}

func idracCleanupSession(ip, token, location string) {
	if token == "" || location == "" {
		return
	}
	deleteURL := location
	if strings.HasPrefix(location, "/") {
		deleteURL = "https://" + ip + location
	}
	req, err := http.NewRequest(http.MethodDelete, deleteURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Auth-Token", token)
	resp, err := insecureClient(10 * time.Second).Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close() // best effort
}

var authResultPattern = regexp.MustCompile(`<authResult>(\d+)</authResult>`)

// idracLegacyPreAuth tries the legacy /data/login endpoint (iDRAC 6/7/8). Any
// cookies it returns are intentionally discarded — they can't be shared
// cross-origin with the browser.
func idracLegacyPreAuth(ip, user, pass string, res *IDRACAuthResult) {
	client := insecureClient(30 * time.Second)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.PostForm("https://"+ip+"/data/login", url.Values{"user": {user}, "password": {pass}})
	if err != nil {
		if res.Error == "" {
			res.Error = err.Error()
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	m := authResultPattern.FindSubmatch(body)
	switch {
	case m == nil:
		res.Error = "Could not parse authentication response"
	case string(m[1]) == "0":
		res.Success = true
		res.Method = "legacy"
		res.Error = ""
	default:
		res.Error = "Invalid credentials"
	}
}

// NOTE: there is intentionally no server-side Supermicro pre-authentication
// routine. A server-side SID-extraction step would be dead code, since a
// cross-origin SID can't be reused by the browser. Supermicro auto-login is
// driven entirely client-side by console_launch_supermicro.html.
