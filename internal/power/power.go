// Package power implements server power control over Redfish, IPMI, and
// Wake-on-LAN, and live power-status checks.
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
	"os/exec"
	"strings"
	"syscall"
	"time"

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
}

// Controller sends power commands and persists the resulting status.
type Controller struct {
	store      *store.Store
	wolEnabled bool
}

// NewController builds a power controller. wolEnabled gates Wake-on-LAN.
func NewController(st *store.Store, wolEnabled bool) *Controller {
	return &Controller{store: st, wolEnabled: wolEnabled}
}

// Send selects exactly one protocol by credential availability — not a fallback
// chain. The context bounds the underlying network/exec call.
func (c *Controller) Send(ctx context.Context, s *model.Server, command string) (bool, string) {
	switch {
	case s.RedfishUser != "":
		return c.redfishCommand(ctx, s, command)
	case s.IPMIUser != "":
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
	case s.MACAddress != "" && command == "power on":
		return c.wolCommand(s)
	default:
		if command == "power on" {
			return false, "No authentication credentials or MAC address configured"
		}
		return false, "No authentication credentials configured (Wake-on-LAN only supports power on)"
	}
}

// redfishCommand sends a Dell-style Redfish ComputerSystem.Reset action.
func (c *Controller) redfishCommand(ctx context.Context, s *model.Server, command string) (bool, string) {
	resetURL := "https://" + s.IPAddress + "/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset"

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

// ipmiCommand runs `ipmitool ... <command>` over LAN.
func (c *Controller) ipmiCommand(ctx context.Context, s *model.Server, command string) (bool, string) {
	cmdCtx, cancel := context.WithTimeout(ctx, bmcTimeout)
	defer cancel()

	args := append([]string{"-I", "lan", "-H", s.IPAddress, "-U", s.IPMIUser, "-P", s.IPMIPassword}, strings.Fields(command)...)
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(cmdCtx, "ipmitool", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// A non-zero process exit surfaces stderr (which may itself be empty).
		// The Go error text is reserved for the case where the process never
		// ran (binary missing / timeout).
		if _, ok := errors.AsType[*exec.ExitError](err); ok {
			return false, stderr.String()
		}
		return false, err.Error()
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
	return true, stdout.String()
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

	// 255.255.255.255 on the standard port 9 and the alternate port 7.
	for _, port := range []int{9, 7} {
		if err := sendMagicPacket(packet, "255.255.255.255", port); err != nil {
			slog.Warn("Wake-on-LAN broadcast failed", "port", port, "err", err)
		} else {
			slog.Info("Wake-on-LAN packet sent", "port", port, "mac", mac)
		}
	}
	// Plus the server's /24 subnet-directed broadcast on port 9.
	if parts := strings.Split(s.IPAddress, "."); len(parts) == 4 {
		subnet := parts[0] + "." + parts[1] + "." + parts[2] + ".255"
		if err := sendMagicPacket(packet, subnet, 9); err != nil {
			slog.Warn("Wake-on-LAN subnet broadcast failed", "subnet", subnet, "err", err)
		} else {
			slog.Info("Wake-on-LAN packet sent to subnet broadcast", "subnet", subnet)
		}
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
	switch {
	case s.RedfishUser != "":
		return c.checkStatusRedfish(ctx, s)
	case s.IPMIUser != "":
		return c.checkStatusIPMI(ctx, s)
	default:
		return s.Status
	}
}

func (c *Controller) checkStatusRedfish(ctx context.Context, s *model.Server) string {
	reqCtx, cancel := context.WithTimeout(ctx, bmcTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://"+s.IPAddress+"/redfish/v1/Systems/System.Embedded.1/", nil)
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
	state, _ := data["PowerState"].(string)
	if state == "" {
		state = "Unknown"
	}
	c.touchStatus(s, state)
	return state
}

func (c *Controller) checkStatusIPMI(ctx context.Context, s *model.Server) string {
	cmdCtx, cancel := context.WithTimeout(ctx, bmcTimeout)
	defer cancel()

	args := []string{"-I", "lan", "-H", s.IPAddress, "-U", s.IPMIUser, "-P", s.IPMIPassword, "power", "status"}
	var stdout bytes.Buffer
	cmd := exec.CommandContext(cmdCtx, "ipmitool", args...)
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return s.Status
	}
	low := strings.ToLower(stdout.String())
	switch {
	case strings.Contains(low, "on"):
		c.touchStatus(s, "On")
		return "On"
	case strings.Contains(low, "off"):
		c.touchStatus(s, "Off")
		return "Off"
	default:
		return s.Status
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
