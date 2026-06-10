// Package sol streams a server's IPMI Serial-over-LAN console. ipmitool runs
// server-side; the web layer bridges a Session's I/O to a browser terminal so
// credentials never reach the client.
package sol

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/pkilar/lab-manager/internal/model"
)

// Creds picks the credentials ipmitool should use: IPMI first, Redfish as a
// fallback (the same root/calvin works for iDRAC IPMI). ok is false when the
// server has neither.
func Creds(s *model.Server) (user, pass string, ok bool) {
	if s.IPMIUser != "" {
		return s.IPMIUser, s.IPMIPassword, true
	}
	if s.RedfishUser != "" {
		return s.RedfishUser, s.RedfishPassword, true
	}
	return "", "", false
}

// activateArgs / deactivateArgs build the ipmitool argv. The password is NOT an
// argv element — it is passed via the IPMI_PASSWORD env var and the -E flag, so
// it never appears in `ps`.
func activateArgs(ip, user string) []string   { return solArgs(ip, user, "activate") }
func deactivateArgs(ip, user string) []string { return solArgs(ip, user, "deactivate") }

func solArgs(ip, user, verb string) []string {
	return []string{"-I", "lanplus", "-H", ip, "-U", user, "-E", "sol", verb}
}

// ErrNoCreds is returned by Start when the server has no usable credentials.
var ErrNoCreds = errors.New("no IPMI or Redfish credentials configured")

// runner abstracts process execution so the bridge logic is testable without a
// real ipmitool/BMC. stdin may be nil (no input); stdout receives merged
// stdout+stderr.
type runner interface {
	Run(ctx context.Context, args, env []string, stdin io.Reader, stdout io.Writer) error
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, args, env []string, stdin io.Reader, stdout io.Writer) error {
	cmd := exec.CommandContext(ctx, "ipmitool", args...)
	cmd.Env = env
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stdout // surface ipmitool errors inline in the terminal
	return cmd.Run()
}

// Manager runs SOL sessions. Construct once with NewManager and share it.
type Manager struct {
	run runner
}

func NewManager() *Manager { return &Manager{run: execRunner{}} }

// Session is one live SOL connection. The web layer writes browser keystrokes
// to Stdin and copies BMC bytes from Output to the WebSocket.
type Session struct {
	Stdin  io.Writer // browser keystrokes in
	Output io.Reader // BMC bytes out (EOF when the session ends)

	cancel    context.CancelFunc
	stdinW    *io.PipeWriter
	closeOnce sync.Once
	done      chan struct{}
	err       error
}

// Start clears any stale BMC payload, then runs `sol activate`. The returned
// Session streams until Close is called, the browser disconnects, or ipmitool
// exits. The caller MUST Close the Session to release the BMC payload.
func (m *Manager) Start(ctx context.Context, s *model.Server) (*Session, error) {
	user, pass, ok := Creds(s)
	if !ok {
		return nil, ErrNoCreds
	}
	ctx, cancel := context.WithCancel(ctx)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	env := append(os.Environ(), "IPMI_PASSWORD="+pass)

	sess := &Session{
		Stdin: inW, Output: outR,
		cancel: cancel, stdinW: inW, done: make(chan struct{}),
	}

	go func() {
		// Clear a possibly-leaked prior payload (single-session per BMC).
		_ = m.run.Run(ctx, deactivateArgs(s.IPAddress, user), env, nil, io.Discard)
		// Run the console until ctx is cancelled or ipmitool exits.
		runErr := m.run.Run(ctx, activateArgs(s.IPAddress, user), env, inR, outW)
		// Release the BMC payload even though ctx is now (usually) cancelled.
		cleanupCtx, ccancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		_ = m.run.Run(cleanupCtx, deactivateArgs(s.IPAddress, user), env, nil, io.Discard)
		ccancel()
		_ = outW.CloseWithError(io.EOF) // EOF to Output reader
		_ = inW.Close()
		sess.err = runErr
		close(sess.done)
	}()

	return sess, nil
}

// Close cancels the session, releases the BMC payload, and waits for cleanup.
// Safe to call multiple times and from multiple goroutines.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		_ = s.stdinW.Close() // EOF to the runner's stdin (kills the echo/copy)
	})
	<-s.done
	return nil
}
