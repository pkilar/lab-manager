// Package power implements server power control over Redfish, IPMI,
// Wake-on-LAN, and PiKVM ATX (kvmd HTTP API), and live power-status checks.
package power

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gorilla/websocket"
	"github.com/pkilar/lab-manager/internal/model"
	"github.com/pkilar/lab-manager/internal/store"
)

// bmcTimeout bounds a single BMC request (Redfish HTTP call or ipmitool run).
const bmcTimeout = 30 * time.Second

// bmcHTTPClient is shared across all BMC calls so its Transport can pool
// connections. Per-call deadlines come from the request context, not the
// client, so one client serves every caller. TLS verification is disabled
// because BMCs present self-signed certificates.
var bmcHTTPClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // BMCs use self-signed certs
	},
	// A BMC API call never legitimately redirects; following one would replay credentials elsewhere.
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// bmcHost returns the URL host for a server's BMC. A var so tests can point it
// at an httptest listener (whose address carries a port).
var bmcHost = (*model.Server).BMCHost

// errBadAddress is returned when the stored address is not an IP, so no URL is
// built from it and nothing is dialed.
const errBadAddress = "Server address is not a valid IP address"

// errCredsUnreadable is returned instead of contacting a BMC with credentials
// that could not be decrypted: sending ciphertext as a password only racks up
// failed logins and can lock the BMC account.
const errCredsUnreadable = "Stored BMC credentials can't be decrypted (the encryption key changed). Re-enter the password on the edit page." //nolint:gosec // G101: a message, not a credential

// maxBMCText caps BMC-supplied text copied into messages.
const maxBMCText = 200

// bmcText makes text from a BMC safe to show: control characters are dropped
// and the result is cut to maxBMCText bytes on a rune boundary.
func bmcText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.ToValidUTF8(strings.TrimSpace(s), "")
	if len(s) <= maxBMCText {
		return s
	}
	cut := maxBMCText
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// maxOutputBytes caps how much of ipmitool's stdout or stderr is kept.
const maxOutputBytes = 64 << 10

// cappedBuffer keeps the first maxOutputBytes written and silently discards the
// rest while reporting full success, so ipmitool never sees a short write.
type cappedBuffer struct{ buf bytes.Buffer }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := maxOutputBytes - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (b *cappedBuffer) String() string { return b.buf.String() }

// Controller sends power commands and persists the resulting status.
type Controller struct {
	store      *store.Store
	wolEnabled bool
	// sendWoL transmits one magic packet; a field so tests can avoid real UDP.
	sendWoL func(packet []byte, ip string, port int) error
}

// NewController builds a power controller. wolEnabled gates Wake-on-LAN.
func NewController(st *store.Store, wolEnabled bool) *Controller {
	return &Controller{store: st, wolEnabled: wolEnabled, sendWoL: sendMagicPacket}
}

// Protocol is the single power-control path used for a server. Send and
// CheckStatus both act on exactly the Protocol that ProtocolFor reports, so
// anything that wants to say how a server is controlled should ask ProtocolFor
// instead of re-deriving it from the credential fields.
type Protocol string

const (
	// ProtocolPiKVM is the PiKVM ATX board, over the kvmd HTTP API.
	ProtocolPiKVM Protocol = "pikvm"
	// ProtocolRedfish is a Dell-style Redfish ComputerSystem.Reset action.
	ProtocolRedfish Protocol = "redfish"
	// ProtocolIPMI is ipmitool over LAN.
	ProtocolIPMI Protocol = "ipmi"
	// ProtocolWoL is a Wake-on-LAN magic packet. It can only power a host on and
	// cannot report its state.
	ProtocolWoL Protocol = "wake-on-lan"
	// ProtocolNone means no power control is configured.
	ProtocolNone Protocol = "none"
)

// ProtocolFor selects exactly one protocol by credential availability — not a
// fallback chain: PiKVM when the BMC type says so, else Redfish when a Redfish
// user is set, else IPMI when an IPMI user is set, else Wake-on-LAN when a MAC
// address is set, else ProtocolNone. A PiKVM never falls through to the others,
// even with no credentials. A MAC-only server reports ProtocolWoL whether or not
// WOL_ENABLED is set: the flag is enforced when a packet is sent (wolCommand),
// so a "wake-on-lan" server can still refuse to power on.
func ProtocolFor(s *model.Server) Protocol {
	switch {
	// PiKVM speaks neither Redfish nor IPMI, so it must be routed first.
	case s.BMCType == model.BMCPiKVM:
		return ProtocolPiKVM
	case s.RedfishUser != "":
		return ProtocolRedfish
	case s.IPMIUser != "":
		return ProtocolIPMI
	case s.MACAddress != "":
		return ProtocolWoL
	default:
		return ProtocolNone
	}
}

// Send runs command through the one protocol ProtocolFor selects for s. The
// context bounds the underlying network/exec call.
func (c *Controller) Send(ctx context.Context, s *model.Server, command string) (bool, string) {
	proto := ProtocolFor(s)
	if s.CredentialsUnreadable && proto != ProtocolWoL && proto != ProtocolNone {
		return false, errCredsUnreadable
	}
	switch proto {
	case ProtocolPiKVM:
		return c.pikvmCommand(ctx, s, command)
	case ProtocolRedfish:
		return c.redfishCommand(ctx, s, command)
	case ProtocolIPMI:
		var ipmi string
		switch command {
		case "power on":
			ipmi = "power on"
		case "power off":
			ipmi = "power off"
		case "reset":
			ipmi = "power reset"
		case "power cycle":
			ipmi = "power cycle"
		default:
			return false, "Invalid command"
		}
		return c.ipmiCommand(ctx, s, ipmi)
	case ProtocolWoL:
		if command == "power on" {
			return c.wolCommand(s)
		}
	}
	// Reached when nothing is configured, or when only a MAC address is and the
	// command is anything but power on (all Wake-on-LAN can do).
	if command == "power on" {
		return false, "No authentication credentials or MAC address configured"
	}
	return false, "No authentication credentials configured (Wake-on-LAN only supports power on)"
}

// redfishCommand sends a Dell-style Redfish ComputerSystem.Reset action.
func (c *Controller) redfishCommand(ctx context.Context, s *model.Server, command string) (bool, string) {
	var resetType, okStatus, okMessage string
	switch command {
	case "power on":
		resetType, okStatus, okMessage = "On", "On", "Power on command sent"
	case "power off":
		resetType, okStatus, okMessage = "GracefulShutdown", "Off", "Power off command sent"
	case "power cycle":
		resetType, okStatus, okMessage = "ForceRestart", "On", "Restart command sent"
	default:
		return false, "Command not implemented"
	}

	host, ok := bmcHost(s)
	if !ok {
		return false, errBadAddress
	}
	resetURL := "https://" + host + "/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset"

	reqCtx, cancel := context.WithTimeout(ctx, bmcTimeout)
	defer cancel()

	payload, _ := json.Marshal(map[string]string{"ResetType": resetType})
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, resetURL, bytes.NewReader(payload))
	if err != nil {
		return false, err.Error()
	}
	req.SetBasicAuth(s.RedfishUser, s.RedfishPassword)
	req.Header.Set("Content-Type", "application/json")

	resp, err := bmcHTTPClient.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		c.touchStatus(s, okStatus)
		return true, okMessage
	}
	// Non-OK. "power off"/"power cycle" report the HTTP status; "power on"
	// falls through to the generic message.
	switch command {
	case "power off":
		return false, fmt.Sprintf("Power off failed: HTTP %d", resp.StatusCode)
	case "power cycle":
		return false, fmt.Sprintf("Restart failed: HTTP %d", resp.StatusCode)
	default:
		return false, "Command not implemented"
	}
}

// pikvmCreds returns the PiKVM login: Redfish credentials win over IPMI ones
// (the same precedence as the console package).
func pikvmCreds(s *model.Server) (user, pass string) {
	if s.RedfishUser != "" {
		return s.RedfishUser, s.RedfishPassword
	}
	return s.IPMIUser, s.IPMIPassword
}

// pikvmRequest builds a kvmd API request authenticated statelessly with the
// X-KVMD-User/X-KVMD-Passwd headers (no session is created).
func pikvmRequest(ctx context.Context, s *model.Server, method, path string) (*http.Request, error) {
	host, ok := bmcHost(s)
	if !ok {
		return nil, errors.New(errBadAddress) //nolint:staticcheck // ST1005: user-facing message, shown verbatim
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+host+path, nil)
	if err != nil {
		return nil, err
	}
	user, pass := pikvmCreds(s)
	req.Header.Set("X-KVMD-User", user)
	req.Header.Set("X-KVMD-Passwd", pass)
	return req, nil
}

// pikvmCommand drives the PiKVM ATX board via POST /api/atx/power. A PiKVM row
// with no credentials fails outright; it never falls through to Wake-on-LAN
// (the PiKVM is the BMC, not the host, so a magic packet would be wrong here).
func (c *Controller) pikvmCommand(ctx context.Context, s *model.Server, command string) (bool, string) {
	var action, okStatus, okMessage, failPrefix string
	switch command {
	case "power on":
		action, okStatus, okMessage, failPrefix = "on", "On", "Power on command sent", "Power on failed"
	case "power off":
		action, okStatus, okMessage, failPrefix = "off", "Off", "Power off command sent", "Power off failed"
	case "power cycle", "reset":
		action, okStatus, okMessage, failPrefix = "reset_hard", "On", "Restart command sent", "Restart failed"
	default:
		return false, "Command not implemented"
	}
	if user, _ := pikvmCreds(s); user == "" {
		return false, "No authentication credentials configured"
	}

	reqCtx, cancel := context.WithTimeout(ctx, bmcTimeout)
	defer cancel()
	req, err := pikvmRequest(reqCtx, s, http.MethodPost, "/api/atx/power?action="+action)
	if err != nil {
		return false, err.Error()
	}
	resp, err := bmcHTTPClient.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusOK {
		c.touchStatus(s, okStatus)
		return true, okMessage
	}
	var e struct {
		Result struct {
			Error    string `json:"error"`
			ErrorMsg string `json:"error_msg"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &e) == nil && (e.Result.Error != "" || e.Result.ErrorMsg != "") {
		detail := e.Result.Error
		if e.Result.ErrorMsg != "" {
			if detail != "" {
				detail += ": "
			}
			detail += e.Result.ErrorMsg
		}
		return false, fmt.Sprintf("%s: %s (HTTP %d)", failPrefix, bmcText(detail), resp.StatusCode)
	}
	return false, fmt.Sprintf("%s: HTTP %d", failPrefix, resp.StatusCode)
}

// pikvmVideoWindow is how long pikvmVideoSignal listens for an online video
// signal before concluding there is none. A var so tests can shrink it.
var pikvmVideoWindow = 5 * time.Second

// checkStatusPiKVM decides the power state of the host behind a PiKVM. The ATX
// power LED (GET /api/atx) is trusted only when it reads on: an LED sense input
// that is not wired (common on DIY boards) reads off forever, so a running host
// would show Off. When the LED is off, or the ATX board is disabled, the HDMI
// capture is consulted instead (pikvmVideoSignal): a live signal means On; a
// capture that ran for the whole window without one means Off. Known false-Off
// case: a host that cuts its HDMI output when the display sleeps (DPMS) reads
// Off. Any failure, missing credentials, or an undetermined video state yields
// the cached status.
func (c *Controller) checkStatusPiKVM(ctx context.Context, s *model.Server) string {
	if user, _ := pikvmCreds(s); user == "" || s.CredentialsUnreadable {
		return s.Status
	}
	reqCtx, cancel := context.WithTimeout(ctx, bmcTimeout)
	defer cancel()
	req, err := pikvmRequest(reqCtx, s, http.MethodGet, "/api/atx")
	if err != nil {
		return s.Status
	}
	resp, err := bmcHTTPClient.Do(req)
	if err != nil {
		return s.Status
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return s.Status
	}
	var data struct {
		OK     bool `json:"ok"`
		Result struct {
			Enabled bool `json:"enabled"`
			LEDs    struct {
				Power bool `json:"power"`
			} `json:"leds"`
		} `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data); err != nil || !data.OK {
		return s.Status
	}
	if data.Result.Enabled && data.Result.LEDs.Power {
		c.touchStatus(s, "On")
		return "On"
	}
	online, known := pikvmVideoSignal(ctx, s)
	switch {
	case online:
		c.touchStatus(s, "On")
		return "On"
	case known:
		c.touchStatus(s, "Off")
		return "Off"
	}
	return s.Status
}

// pikvmVideoSignal listens on the kvmd event WebSocket (/api/ws?stream=1, same
// stateless header auth as the HTTP calls) for the HDMI capture state. kvmd
// sends JSON {"event_type", "event"} messages; only "streamer" (legacy
// "streamer_state") events matter, and later ones are partial, so each is
// scanned for event.streamer.source, which is null while the capture process is
// not running and otherwise carries "online". online is true as soon as a
// source reports online. known means a source was reported at all, so the
// capture ran: with online false that is a definitive no-signal after the full
// window (a cold start can report a transient offline first, so the first
// false is never final). Dial, auth, or read failures return known=false
// unless a source was already seen.
func pikvmVideoSignal(ctx context.Context, s *model.Server) (online, known bool) {
	user, pass := pikvmCreds(s)
	hdr := http.Header{}
	hdr.Set("X-KVMD-User", user)
	hdr.Set("X-KVMD-Passwd", pass)
	host, ok := bmcHost(s)
	if !ok {
		return false, false
	}
	d := websocket.Dialer{
		// BMCs ship self-signed certs, as with bmcHTTPClient.
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // self-signed BMC certificate
		HandshakeTimeout: 10 * time.Second,
	}
	conn, resp, err := d.DialContext(ctx, "wss://"+host+"/api/ws?stream=1", hdr)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return false, false
	}
	// Close politely so kvmd drops the client and stops the capture after its
	// own delay.
	defer func() {
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
		_ = conn.Close()
	}()
	conn.SetReadLimit(1 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(pikvmVideoWindow))
	for {
		typ, msg, err := conn.ReadMessage()
		if err != nil {
			return false, known
		}
		if typ != websocket.TextMessage {
			continue
		}
		var ev struct {
			Type  string `json:"event_type"`
			Event struct {
				Streamer struct {
					Source *struct {
						Online bool `json:"online"`
					} `json:"source"`
				} `json:"streamer"`
			} `json:"event"`
		}
		if json.Unmarshal(msg, &ev) != nil || (ev.Type != "streamer" && ev.Type != "streamer_state") {
			continue
		}
		if src := ev.Event.Streamer.Source; src != nil {
			known = true
			if src.Online {
				return true, true
			}
		}
	}
}

// ipmiArgs builds the ipmitool argv. The password is deliberately absent: -E
// makes ipmitool read it from the IPMI_PASSWORD environment variable (see
// ipmiEnv), keeping it out of `ps` and /proc/<pid>/cmdline.
func ipmiArgs(s *model.Server, cmd ...string) []string {
	return append([]string{"-I", "lan", "-H", s.IPAddress, "-U", s.IPMIUser, "-E"}, cmd...)
}

// ipmiEnv is the child environment carrying the IPMI password for -E. The
// app's own LAB_MANAGER_* settings (session secret etc.) and any inherited
// IPMI_PASSWORD are stripped so ipmitool never sees them.
func ipmiEnv(s *model.Server) []string {
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "LAB_MANAGER_") || strings.HasPrefix(kv, "IPMI_PASSWORD=")
	})
	return append(env, "IPMI_PASSWORD="+s.IPMIPassword)
}

// ipmiCommand runs `ipmitool ... <command>` over LAN.
func (c *Controller) ipmiCommand(ctx context.Context, s *model.Server, command string) (bool, string) {
	if !s.ValidIP() {
		return false, errBadAddress
	}
	cmdCtx, cancel := context.WithTimeout(ctx, bmcTimeout)
	defer cancel()

	var stdout, stderr cappedBuffer
	cmd := exec.CommandContext(cmdCtx, "ipmitool", ipmiArgs(s, strings.Fields(command)...)...)
	cmd.Env = ipmiEnv(s)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// A non-zero process exit surfaces stderr (which may itself be empty).
		// The Go error text is reserved for the case where the process never
		// ran (binary missing / timeout).
		if _, ok := errors.AsType[*exec.ExitError](err); ok {
			return false, bmcText(stderr.String())
		}
		return false, bmcText(err.Error())
	}

	// Update the cached status from the command keyword ("on" is checked first).
	switch {
	case strings.Contains(command, "on"):
		c.touchStatus(s, "On")
	case strings.Contains(command, "off"):
		c.touchStatus(s, "Off")
	case strings.Contains(command, "cycle"), strings.Contains(command, "reset"):
		c.touchStatus(s, "On")
	default:
		c.touchStatus(s, s.Status)
	}
	return true, bmcText(stdout.String())
}

// wolCommand sends Wake-on-LAN magic packets. Gated behind WOL_ENABLED. The
// packets are fire-and-forget local UDP writes, so there is no request to
// cancel.
func (c *Controller) wolCommand(s *model.Server) (bool, string) {
	if !c.wolEnabled {
		return false, "Wake-on-LAN is disabled. Set WOL_ENABLED=true to enable it (see README)."
	}
	if s.MACAddress == "" {
		return false, "No MAC address configured for Wake-on-LAN"
	}

	mac := strings.TrimSpace(s.MACAddress)
	slog.Info("sending Wake-on-LAN packet", "mac", mac, "server", s.Name)
	packet, err := buildMagicPacket(mac)
	if err != nil {
		slog.Error("Wake-on-LAN invalid MAC", "mac", mac, "err", err)
		return false, "Wake-on-LAN failed: " + err.Error()
	}

	// Count successes: every send failing (e.g. no usable network interface)
	// must not be reported as a wake.
	var sent int
	var lastErr error
	send := func(ip string, port int) bool {
		if err := c.sendWoL(packet, ip, port); err != nil {
			lastErr = err
			slog.Warn("Wake-on-LAN send failed", "ip", ip, "port", port, "err", err)
			return false
		}
		sent++
		slog.Info("Wake-on-LAN packet sent", "ip", ip, "port", port, "mac", mac)
		return true
	}

	// 255.255.255.255 on the standard port 9 and the alternate port 7.
	for _, port := range []int{9, 7} {
		send("255.255.255.255", port)
	}
	// Plus the server's /24 subnet-directed broadcast on port 9.
	if parts := strings.Split(s.IPAddress, "."); len(parts) == 4 {
		send(parts[0]+"."+parts[1]+"."+parts[2]+".255", 9)
	}
	if sent == 0 {
		return false, "Wake-on-LAN failed: " + lastErr.Error()
	}

	// Optimistically mark the server On; the real state is confirmed on the
	// next status check.
	c.touchStatus(s, "On")
	return true, fmt.Sprintf("Wake-on-LAN packets sent to %s on ports 7 and 9 (check logs for details)", mac)
}

// macCleaner strips the separators from a MAC address in a single pass.
var macCleaner = strings.NewReplacer(":", "", "-", "")

func buildMagicPacket(mac string) ([]byte, error) {
	hw, err := hex.DecodeString(macCleaner.Replace(strings.TrimSpace(mac)))
	if err != nil || len(hw) != 6 {
		return nil, fmt.Errorf("invalid MAC address %q", mac)
	}
	packet := make([]byte, 6, 6+16*6)
	for i := range packet {
		packet[i] = 0xFF
	}
	for range 16 {
		packet = append(packet, hw...)
	}
	return packet, nil
}

// sendMagicPacket sends one UDP datagram to a broadcast address. SO_BROADCAST is
// required for the OS to permit sending to a broadcast destination.
func sendMagicPacket(packet []byte, ip string, port int) error {
	dst := net.ParseIP(ip)
	if dst == nil {
		return fmt.Errorf("invalid broadcast address %q", ip)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if raw, err := conn.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		})
	}
	_, err = conn.WriteToUDP(packet, &net.UDPAddr{IP: dst, Port: port})
	return err
}

// CheckStatus queries the live power state, persists it, and returns it. On any
// error it returns the last-known cached status.
func (c *Controller) CheckStatus(ctx context.Context, s *model.Server) string {
	proto := ProtocolFor(s)
	if s.CredentialsUnreadable && proto != ProtocolWoL && proto != ProtocolNone {
		// Cached, and LastUpdated untouched: callers infer "live" from it.
		return s.Status
	}
	switch proto {
	case ProtocolPiKVM:
		return c.checkStatusPiKVM(ctx, s)
	case ProtocolRedfish:
		return c.checkStatusRedfish(ctx, s)
	case ProtocolIPMI:
		return c.checkStatusIPMI(ctx, s)
	default:
		// Wake-on-LAN (or nothing at all) has no way to read the power state.
		return s.Status
	}
}

// checkAllConcurrency bounds the parallel BMC status checks of CheckAll.
const checkAllConcurrency = 8

// CheckAll runs CheckStatus for every server, at most checkAllConcurrency at a
// time, and returns once all are done. As with CheckStatus, a successful live
// check updates the server's Status and LastUpdated in place. The servers must
// be distinct pointers, since the checks run concurrently.
func (c *Controller) CheckAll(ctx context.Context, servers []*model.Server) {
	// Each check can block for the full BMC timeout on an unreachable host, so
	// run them concurrently (bounded) rather than holding the caller N x timeout.
	sem := make(chan struct{}, checkAllConcurrency)
	var wg sync.WaitGroup
	for _, s := range servers {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			c.CheckStatus(ctx, s)
		})
	}
	wg.Wait()
}

func (c *Controller) checkStatusRedfish(ctx context.Context, s *model.Server) string {
	host, ok := bmcHost(s)
	if !ok {
		return s.Status
	}
	reqCtx, cancel := context.WithTimeout(ctx, bmcTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://"+host+"/redfish/v1/Systems/System.Embedded.1/", nil)
	if err != nil {
		return s.Status
	}
	req.SetBasicAuth(s.RedfishUser, s.RedfishPassword)
	resp, err := bmcHTTPClient.Do(req)
	if err != nil {
		return s.Status
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return s.Status
	}
	var data map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data); err != nil {
		return s.Status
	}
	// The BMC's string is stored and shown verbatim, so only known values pass.
	state, _ := data["PowerState"].(string)
	switch state {
	case "On", "Off", "PoweringOn", "PoweringOff", "Paused":
	default:
		state = "Unknown"
	}
	c.touchStatus(s, state)
	return state
}

func (c *Controller) checkStatusIPMI(ctx context.Context, s *model.Server) string {
	if !s.ValidIP() {
		return s.Status
	}
	cmdCtx, cancel := context.WithTimeout(ctx, bmcTimeout)
	defer cancel()

	var stdout cappedBuffer
	cmd := exec.CommandContext(cmdCtx, "ipmitool", ipmiArgs(s, "power", "status")...)
	cmd.Env = ipmiEnv(s)
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return s.Status
	}
	status, ok := parseIPMIPowerStatus(stdout.String())
	if !ok {
		return s.Status
	}
	c.touchStatus(s, status)
	return status
}

// parseIPMIPowerStatus maps `ipmitool power status` output ("Chassis Power is
// on|off") to "On"/"Off". It anchors on that phrase: a bare substring test for
// "on" also matches words like "session" in an ipmitool error message.
func parseIPMIPowerStatus(out string) (string, bool) {
	_, rest, ok := strings.Cut(strings.ToLower(out), "chassis power is ")
	if !ok {
		return "", false
	}
	state, _, _ := strings.Cut(strings.TrimSpace(rest), "\n")
	switch strings.TrimSpace(state) {
	case "on":
		return "On", true
	case "off":
		return "Off", true
	default:
		return "", false
	}
}

// touchStatus updates the in-memory status and timestamp and persists them.
func (c *Controller) touchStatus(s *model.Server, status string) {
	now := time.Now().UTC()
	s.Status = status
	s.LastUpdated = now
	if err := c.store.TouchStatus(s.ID, status, now); err != nil {
		slog.Error("persist server status", "server_id", s.ID, "server", s.Name, "err", err)
	}
}
