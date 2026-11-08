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
	"strconv"
	"strings"
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
func activateArgs(ip, user string, instance int) []string {
	return solArgs(ip, user, "activate", instance)
}
func deactivateArgs(ip, user string, instance int) []string {
	return solArgs(ip, user, "deactivate", instance)
}

// solArgs appends `instance=<n>` only for non-default instances. ipmitool
// already defaults to instance 1, so omitting it keeps the argv for the common
// case byte-identical to what shipped before this option existed — no BMC that
// works today can be broken by firmware that mishandles the explicit form.
//
// The instance must be passed to `deactivate` as well: without it a teardown
// would release payload 1 and leave the session the user actually opened
// pinned on the BMC, which allows only one at a time.
func solArgs(ip, user, verb string, instance int) []string {
	args := []string{"-I", "lanplus", "-H", ip, "-U", user, "-E", "sol", verb}
	if instance > model.DefaultSOLInstance {
		args = append(args, "instance="+strconv.Itoa(instance))
	}
	return args
}

// ErrNoCreds is returned by Start when the server has no usable credentials.
var ErrNoCreds = errors.New("no IPMI or Redfish credentials configured")

// ErrCredsUnreadable is returned by Start when the stored password could not be
// decrypted (the encryption key changed); ciphertext must not be sent to a BMC
// as a password.
var ErrCredsUnreadable = errors.New("stored BMC credentials can't be decrypted (the encryption key changed); re-enter the password on the edit page")

// ErrBadAddress is returned by Start when the stored address is not an IP.
var ErrBadAddress = errors.New("server address is not a valid IP address")

// ErrTooManySessions is returned by Start at the session cap.
var ErrTooManySessions = errors.New("too many serial console sessions open")

// maxSessions caps live sessions, each of which holds an ipmitool process.
const maxSessions = 16

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
	cmd.Stdout = stdout
	cmd.Stderr = stdout // surface ipmitool errors inline in the terminal
	if stdin == nil {
		return cmd.Run()
	}
	// Feed stdin from our own goroutine rather than cmd.Stdin: for a reader that
	// isn't an *os.File, Wait also waits for os/exec's copy goroutine, which sits
	// in stdin.Read until the next keystroke. An ipmitool that exited on its own
	// (BMC dropped the session, `~.`) would then go unnoticed until the user
	// typed. This goroutine ends when the caller closes stdin.
	w, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		_, _ = io.Copy(w, stdin)
		_ = w.Close()
	}()
	return cmd.Wait()
}

// Manager runs SOL sessions. Construct once with NewManager and share it.
type Manager struct {
	run runner

	mu   sync.Mutex
	live map[*Session]struct{} // lazily created so a bare &Manager{run: r} works
}

func NewManager() *Manager { return &Manager{run: execRunner{}} }

// Session is one live SOL connection. The web layer writes browser keystrokes
// to Stdin and copies BMC bytes from Output to the WebSocket.
type Session struct {
	Stdin  io.Writer // browser keystrokes in
	Output io.Reader // BMC bytes out (EOF when the session ends)

	cancel    context.CancelFunc
	stdinW    *io.PipeWriter
	outR      *io.PipeReader
	closeOnce sync.Once
	done      chan struct{}
}

// Start clears any stale BMC payload, then runs `sol activate`. The returned
// Session streams until Close is called, the browser disconnects, or ipmitool
// exits. The caller MUST Close the Session to release the BMC payload.
func (m *Manager) Start(ctx context.Context, s *model.Server) (*Session, error) {
	user, pass, ok := Creds(s)
	if !ok {
		return nil, ErrNoCreds
	}
	if s.CredentialsUnreadable {
		return nil, ErrCredsUnreadable
	}
	if !s.ValidIP() {
		return nil, ErrBadAddress
	}
	instance := s.SOLInstanceOrDefault()
	ctx, cancel := context.WithCancel(ctx)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	env := childEnv(pass)

	sess := &Session{
		Stdin: inW, Output: outR,
		cancel: cancel, stdinW: inW, outR: outR, done: make(chan struct{}),
	}

	if !m.track(sess) {
		cancel()
		return nil, ErrTooManySessions
	}
	go func() {
		// Clear a possibly-leaked prior payload (single-session per BMC).
		_ = m.run.Run(ctx, deactivateArgs(s.IPAddress, user, instance), env, nil, io.Discard)
		// Run the console until ctx is cancelled or ipmitool exits. The exit
		// error is intentionally discarded: a normal disconnect kills ipmitool
		// (signal: killed), which is not a failure, and stderr is already
		// streamed to the terminal.
		_ = m.run.Run(ctx, activateArgs(s.IPAddress, user, instance), env, inR, outW)
		// Release the BMC payload even though ctx is now (usually) cancelled.
		cleanupCtx, ccancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		_ = m.run.Run(cleanupCtx, deactivateArgs(s.IPAddress, user, instance), env, nil, io.Discard)
		ccancel()
		_ = outW.CloseWithError(io.EOF) // EOF to the Output reader
		// Also close stdin: if ipmitool exited on its own (no Close() yet), this
		// makes a pending browser write fail instead of blocking forever.
		_ = inW.Close()
		// Free the slot before signalling done, so it is released exactly once
		// and a returned Close implies it is free.
		m.untrack(sess)
		close(sess.done)
	}()

	return sess, nil
}

// childEnv is the environment handed to ipmitool: the app's own, minus its
// secrets (LAB_MANAGER_SECRET_KEY / _ENCRYPTION_KEY, ...) and any inherited
// IPMI_PASSWORD, plus the one password this session needs.
func childEnv(pass string) []string {
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "LAB_MANAGER_") || strings.HasPrefix(kv, "IPMI_PASSWORD=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "IPMI_PASSWORD="+pass)
}

// track registers s, or reports false when maxSessions are already live.
func (m *Manager) track(s *Session) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.live) >= maxSessions {
		return false
	}
	if m.live == nil {
		m.live = make(map[*Session]struct{})
	}
	m.live[s] = struct{}{}
	return true
}

func (m *Manager) untrack(s *Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.live, s)
}

// CloseAll closes every live session concurrently and returns once all have
// finished their cleanup deactivate (each bounded by its 10s timeout). It is
// meant for process shutdown so every BMC SOL payload is released rather than
// left pinned until the BMC times it out.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.live))
	for s := range m.live {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, s := range sessions {
		wg.Go(func() { _ = s.Close() })
	}
	wg.Wait()
}

// Close cancels the session, releases the BMC payload, and waits for cleanup.
// Safe to call multiple times and from multiple goroutines.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		_ = s.stdinW.Close() // EOF to the runner's stdin (kills the echo/copy)
		// Fail any write still pending on the output pipe. Without this, a
		// caller that stopped reading Output (its WebSocket write failed) leaves
		// os/exec's stdout copy blocked, so Wait never returns, the cleanup
		// deactivate never runs, and this Close blocks forever.
		_ = s.outR.CloseWithError(io.ErrClosedPipe)
	})
	<-s.done
	return nil
}
