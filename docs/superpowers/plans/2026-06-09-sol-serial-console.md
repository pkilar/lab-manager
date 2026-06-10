# SOL Serial Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a browser serial console that streams a server's IPMI Serial-over-LAN session to an xterm.js terminal, with `ipmitool` running server-side and credentials never reaching the browser.

**Architecture:** A new pure-ish `internal/sol` package resolves credentials and runs `ipmitool sol activate` through an injectable `runner` (real = `exec`, fake = test echo), exposing a `Session` with an `io.Reader` (BMC output) and an `io.Writer` (keystrokes). The `internal/web` layer owns the gorilla/websocket dependency: it upgrades `GET /server/{id}/sol`, checks Origin, and bridges the socket to the session with a single-writer write pump + a read-pump goroutine. xterm.js is vendored and embedded; the launch page is a standalone template.

**Tech Stack:** Go 1.26 stdlib `net/http` + `os/exec`, `github.com/gorilla/websocket` (pure-Go, zero transitive deps), xterm.js 5.3.0 + addon-fit 0.8.0 (vendored, `//go:embed`), `ipmitool` (already in the runtime image). Tests use the stdlib `testing` package (this repo does not use testify).

**Spec:** `docs/superpowers/specs/2026-06-09-sol-serial-console-design.md`

---

## File Structure

| File | Responsibility |
|------|----------------|
| `internal/sol/sol.go` (new) | `Creds`, arg builders, `runner` + `execRunner`, `Manager`, `Session` lifecycle/bridge plumbing. Depends only on `model` + stdlib. |
| `internal/sol/sol_test.go` (new) | Cred resolution, arg construction (password not in argv), bridge round-trip + deactivate-on-close via fake runner. |
| `internal/web/sol.go` (new) | `handleSOLLaunch`, `handleSOLSocket`, the `websocket.Upgrader` + Origin check, WS↔Session pumps. Owns the gorilla dep. |
| `internal/web/sol_test.go` (new) | WS upgrade requires a session; foreign Origin rejected; `/static/` serves an asset. |
| `internal/web/static/xterm/*` (new) | Vendored `xterm.js`, `xterm.css`, `addon-fit.js`. |
| `internal/web/static.go` (new) | `//go:embed static` FS + `staticHandler()`. |
| `internal/web/templates/console_sol.html` (new) | xterm.js launch page (standalone). |
| `internal/web/render.go` (modify) | Register `console_sol` template; add `consoleSOLData`. |
| `internal/web/routes.go` (modify) | Register `/server/{id}/sol/launch`, `/server/{id}/sol`, `/static/`. |
| `internal/web/app.go` (modify) | Add + wire `*sol.Manager`. |
| `internal/web/templates/index.html` (modify) | Add the "📟 Serial" button. |
| `go.mod` / `go.sum` (modify) | Add gorilla/websocket. |
| `CLAUDE.md` (modify) | Document `internal/sol`, the `static/` dir, and the SOL routes. |

---

## Task 1: Add the gorilla/websocket dependency

**Files:**
- Modify: `go.mod`, `go.sum`

- [ ] **Step 1: Add the dependency**

Run:
```bash
cd /home/pkilar/Devel/lab_manager
go get github.com/gorilla/websocket@v1.5.3
```
Expected: `go.mod` gains `github.com/gorilla/websocket v1.5.3` in the `require` block; `go.sum` updated.

- [ ] **Step 2: Verify it's a direct, zero-transitive-dep require**

Run: `go mod tidy && grep websocket go.mod`
Expected: a single line `github.com/gorilla/websocket v1.5.3` (NOT marked `// indirect`), no new indirect deps added.

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "build: add gorilla/websocket for the serial console"
```

---

## Task 2: `internal/sol` — credential resolution + arg builders (pure functions)

**Files:**
- Create: `internal/sol/sol.go`
- Test: `internal/sol/sol_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/sol/sol_test.go`:
```go
package sol

import (
	"slices"
	"testing"

	"github.com/pkilar/lab-manager/internal/model"
)

func TestCredsPrefersIPMIThenRedfish(t *testing.T) {
	cases := []struct {
		name             string
		srv              model.Server
		wantUser, wantPw string
		wantOK           bool
	}{
		{"ipmi preferred", model.Server{IPMIUser: "ipmi", IPMIPassword: "ip", RedfishUser: "rf", RedfishPassword: "rp"}, "ipmi", "ip", true},
		{"redfish fallback", model.Server{RedfishUser: "rf", RedfishPassword: "rp"}, "rf", "rp", true},
		{"none", model.Server{}, "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			user, pw, ok := Creds(&c.srv)
			if user != c.wantUser || pw != c.wantPw || ok != c.wantOK {
				t.Fatalf("Creds = (%q,%q,%v), want (%q,%q,%v)", user, pw, ok, c.wantUser, c.wantPw, c.wantOK)
			}
		})
	}
}

func TestActivateArgsCarryNoPassword(t *testing.T) {
	args := activateArgs("10.0.0.5", "root")
	want := []string{"-I", "lanplus", "-H", "10.0.0.5", "-U", "root", "-E", "sol", "activate"}
	if !slices.Equal(args, want) {
		t.Fatalf("activateArgs = %v, want %v", args, want)
	}
	for _, a := range args {
		if a == "calvin" || a == "secret" {
			t.Fatalf("password leaked into argv: %v", args)
		}
	}
}

func TestDeactivateArgs(t *testing.T) {
	args := deactivateArgs("10.0.0.5", "root")
	want := []string{"-I", "lanplus", "-H", "10.0.0.5", "-U", "root", "-E", "sol", "deactivate"}
	if !slices.Equal(args, want) {
		t.Fatalf("deactivateArgs = %v, want %v", args, want)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/sol/ -run 'TestCreds|TestActivateArgs|TestDeactivateArgs' -v`
Expected: FAIL — `undefined: Creds`, `undefined: activateArgs`, `undefined: deactivateArgs`.

- [ ] **Step 3: Write the minimal implementation**

Create `internal/sol/sol.go`:
```go
// Package sol streams a server's IPMI Serial-over-LAN console. ipmitool runs
// server-side; the web layer bridges a Session's I/O to a browser terminal so
// credentials never reach the client.
package sol

import "github.com/pkilar/lab-manager/internal/model"

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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sol/ -run 'TestCreds|TestActivateArgs|TestDeactivateArgs' -v`
Expected: PASS (all three).

- [ ] **Step 5: Commit**

```bash
git add internal/sol/sol.go internal/sol/sol_test.go
git commit -m "feat(sol): credential resolution and ipmitool arg builders"
```

---

## Task 3: `internal/sol` — runner, Manager, Session bridge

**Files:**
- Modify: `internal/sol/sol.go`
- Test: `internal/sol/sol_test.go`

- [ ] **Step 1: Write the failing bridge test**

First, replace the import block at the top of `internal/sol/sol_test.go` with the full set it needs after this task:
```go
import (
	"context"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pkilar/lab-manager/internal/model"
)
```

Then append the bridge tests:
```go

// fakeRunner echoes stdin→stdout for `sol activate` (so the test can round-trip
// bytes) and counts `sol deactivate` calls. It records the env it was given.
type fakeRunner struct {
	deactivations atomic.Int32
	mu            sync.Mutex
	lastEnv       []string
	lastArgs      []string
}

func (f *fakeRunner) Run(ctx context.Context, args, env []string, stdin io.Reader, stdout io.Writer) error {
	f.mu.Lock()
	f.lastEnv, f.lastArgs = env, args
	f.mu.Unlock()
	if len(args) > 0 && args[len(args)-1] == "deactivate" {
		f.deactivations.Add(1)
		return nil
	}
	if stdin != nil { // activate: echo until stdin closes (Session.Close) or ctx done
		_, _ = io.Copy(stdout, stdin)
	}
	return nil
}

func envHas(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}

func TestSessionBridgesIOAndDeactivatesOnClose(t *testing.T) {
	fr := &fakeRunner{}
	m := &Manager{run: fr}
	srv := &model.Server{IPAddress: "10.0.0.5", RedfishUser: "root", RedfishPassword: "calvin"}

	sess, err := m.Start(t.Context(), srv)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if _, err := io.WriteString(sess.Stdin, "uname -a\n"); err != nil {
		t.Fatalf("write keystrokes: %v", err)
	}
	got := make([]byte, len("uname -a\n"))
	if _, err := io.ReadFull(sess.Output, got); err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(got) != "uname -a\n" {
		t.Fatalf("bridge round-trip = %q, want %q", got, "uname -a\n")
	}

	// A `sol deactivate` must run specifically on Close (releasing the BMC
	// payload), beyond the best-effort pre-activate clear.
	before := fr.deactivations.Load()
	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if sess.Close() != nil { // idempotent
		t.Fatal("second Close should be a no-op")
	}
	if fr.deactivations.Load() <= before {
		t.Fatal("expected sol deactivate to run on Close")
	}

	fr.mu.Lock()
	defer fr.mu.Unlock()
	if !envHas(fr.lastEnv, "IPMI_PASSWORD=calvin") {
		t.Fatal("IPMI_PASSWORD not passed in env")
	}
	if strings.Contains(strings.Join(fr.lastArgs, " "), "calvin") {
		t.Fatalf("password leaked into argv: %v", fr.lastArgs)
	}
}

func TestStartFailsWithoutCreds(t *testing.T) {
	m := &Manager{run: &fakeRunner{}}
	if _, err := m.Start(t.Context(), &model.Server{IPAddress: "10.0.0.5"}); err == nil {
		t.Fatal("expected error when no credentials are configured")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/sol/ -run 'TestSessionBridges|TestStartFails' -v`
Expected: FAIL — `undefined: Manager`, `undefined: (*Manager).Start`, `Session`, field `run`.

- [ ] **Step 3: Implement runner, Manager, Session**

Append to `internal/sol/sol.go`:
```go
import (
	// extend the import block to:
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

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
```

Then change `NewManager`'s sibling note: the package-level `Manager{run: ...}` is constructed by tests directly. Keep `NewManager()` for production wiring.

> Note: `runErr` is captured in `sess.err` but `Close` returns nil — a normal ipmitool exit (or ctx-kill) is not a Close failure. The web layer treats Output EOF as "session over". `sess.err` is retained for future logging.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/sol/ -v`
Expected: PASS (all tests, including Task 2's).

- [ ] **Step 5: Vet + format**

Run: `go vet ./internal/sol/ && gofmt -l internal/sol/`
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add internal/sol/sol.go internal/sol/sol_test.go
git commit -m "feat(sol): Manager/Session with injectable runner and lifecycle cleanup"
```

---

## Task 4: Vendor xterm.js and serve it from an embedded FS

**Files:**
- Create: `internal/web/static/xterm/xterm.js`, `xterm.css`, `addon-fit.js`
- Create: `internal/web/static.go`
- Test: `internal/web/sol_test.go` (created here, extended in Task 7)

- [ ] **Step 1: Download the vendored assets**

Run:
```bash
cd /home/pkilar/Devel/lab_manager
mkdir -p internal/web/static/xterm
curl -fsSL https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js                 -o internal/web/static/xterm/xterm.js
curl -fsSL https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css                -o internal/web/static/xterm/xterm.css
curl -fsSL https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js -o internal/web/static/xterm/addon-fit.js
```
Expected: three non-empty files. Verify: `wc -c internal/web/static/xterm/*` (xterm.js ≈ 280 KB, xterm.css ≈ 10 KB, addon-fit.js ≈ 3 KB). The UMD globals are `window.Terminal` and `window.FitAddon.FitAddon`.

- [ ] **Step 2: Write the failing test**

Create `internal/web/sol_test.go`:
```go
package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStaticServesXtermAsset(t *testing.T) {
	h := staticHandler()
	req := httptest.NewRequest(http.MethodGet, "/static/xterm/xterm.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /static/xterm/xterm.js = %d, want 200", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("xterm.js body is empty")
	}
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `go test ./internal/web/ -run TestStaticServesXtermAsset -v`
Expected: FAIL — `undefined: staticHandler`.

- [ ] **Step 4: Implement the embed + handler**

Create `internal/web/static.go`:
```go
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var staticFS embed.FS

// staticHandler serves the embedded read-only asset tree at /static/ (xterm.js
// and friends). Being an embedded FS, it cannot traverse to the host disk.
func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // embed path is a compile-time constant; this never fails
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `go test ./internal/web/ -run TestStaticServesXtermAsset -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/web/static.go internal/web/static/ internal/web/sol_test.go
git commit -m "feat(web): embed and serve vendored xterm.js assets"
```

---

## Task 5: SOL launch page template + view model

**Files:**
- Create: `internal/web/templates/console_sol.html`
- Modify: `internal/web/render.go`

- [ ] **Step 1: Create the template**

Create `internal/web/templates/console_sol.html`:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Serial Console - {{.ServerName}}</title>
    <link rel="stylesheet" href="/static/xterm/xterm.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        html, body { height: 100%; background: #000; }
        .bar {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            color: #cbd5e1; background: #16213e; padding: 8px 12px;
            display: flex; align-items: center; gap: 12px; font-size: 0.9rem;
        }
        .bar .name { color: #60a5fa; font-weight: 600; }
        .bar .state { margin-left: auto; font-size: 0.8rem; color: #94a3b8; }
        .bar a { color: #60a5fa; text-decoration: none; }
        #term { height: calc(100vh - 37px); width: 100%; padding: 4px; }
    </style>
</head>
<body>
    <div class="bar">
        <span>📟 Serial Console</span>
        <span class="name">{{.ServerName}}</span>
        <span class="state" id="state">connecting…</span>
        <a href="/">← Back</a>
    </div>
    <div id="term"></div>

    <script src="/static/xterm/xterm.js"></script>
    <script src="/static/xterm/addon-fit.js"></script>
    <script>
        const ID = {{.ServerID}};
        const term = new Terminal({ cursorBlink: true, fontSize: 14, convertEol: false });
        const fit = new FitAddon.FitAddon();
        term.loadAddon(fit);
        term.open(document.getElementById('term'));
        fit.fit();
        window.addEventListener('resize', () => fit.fit());

        const state = document.getElementById('state');
        const proto = location.protocol === 'https:' ? 'wss' : 'ws';
        const ws = new WebSocket(proto + '://' + location.host + '/server/' + ID + '/sol');
        ws.binaryType = 'arraybuffer';

        ws.onopen = () => {
            state.textContent = 'connected';
            term.writeln('\x1b[90mConnected. If the screen stays blank, ensure the host has BIOS serial console redirection enabled. Press Enter.\x1b[0m');
            term.focus();
        };
        ws.onmessage = (ev) => {
            const data = typeof ev.data === 'string' ? ev.data : new Uint8Array(ev.data);
            term.write(data);
        };
        ws.onclose = () => { state.textContent = 'disconnected'; term.writeln('\r\n\x1b[91m[ session closed ]\x1b[0m'); };
        ws.onerror = () => { state.textContent = 'error'; };

        term.onData((d) => { if (ws.readyState === WebSocket.OPEN) ws.send(d); });
    </script>
</body>
</html>
```

- [ ] **Step 2: Register the template and add the view model**

In `internal/web/render.go`, add `console_sol` to the console template set. Change:
```go
	for _, name := range []string{"console_launch", "console_launch_idrac", "console_launch_supermicro"} {
```
to:
```go
	for _, name := range []string{"console_launch", "console_launch_idrac", "console_launch_supermicro", "console_sol"} {
```

Then add the view model after the existing `consoleIdracData` struct (end of the `// ---- console pages ----` section):
```go
type consoleSOLData struct {
	ServerID   int64
	ServerName string
}
```

- [ ] **Step 3: Verify templates still parse**

Run: `go test ./internal/web/ -run TestStaticServesXtermAsset -v`
(The web tests construct `App` via `parseTemplates`; a parse error in `console_sol.html` fails app construction in later tasks. For now confirm the package builds.)
Run: `go build ./internal/web/`
Expected: build OK.

- [ ] **Step 4: Commit**

```bash
git add internal/web/templates/console_sol.html internal/web/render.go
git commit -m "feat(web): SOL launch page (xterm.js) template and view model"
```

---

## Task 6: SOL web handlers, Upgrader, and wiring

**Files:**
- Create: `internal/web/sol.go`
- Modify: `internal/web/app.go`, `internal/web/routes.go`

- [ ] **Step 1: Wire `*sol.Manager` into `App`**

In `internal/web/app.go`, add the import `"github.com/pkilar/lab-manager/internal/sol"`, add the field, and construct it. Result:
```go
type App struct {
	store      *store.Store
	power      *power.Controller
	console    *console.Manager
	sol        *sol.Manager
	tmpl       *Templates
	secretKey  []byte
	wolEnabled bool
}
```
and inside `New(...)`'s returned struct literal add:
```go
		sol:        sol.NewManager(),
```

- [ ] **Step 2: Create the handlers + Upgrader**

Create `internal/web/sol.go`:
```go
package web

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/websocket"
)

// solUpgrader upgrades the SOL WebSocket. CheckOrigin enforces a same-host
// Origin: the WS handshake is a GET and bypasses the form-based CSRF middleware,
// so this is the cross-site-WebSocket-hijacking guard.
var solUpgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return false // browsers always send Origin on WS upgrades
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Host, r.Host)
	},
}

// handleSOLLaunch renders the xterm.js page. Creds stay server-side; the page
// only needs the id + name.
func (a *App) handleSOLLaunch(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s, err := a.store.GetServer(id)
	if err != nil {
		a.notFoundOrError(w, r, err)
		return
	}
	a.renderConsole(w, "console_sol", consoleSOLData{ServerID: s.ID, ServerName: s.Name})
}

// handleSOLSocket upgrades to a WebSocket and bridges it to an SOL session:
// a write pump (BMC output → socket) on this goroutine and a read pump
// (keystrokes → ipmitool stdin) on a second goroutine. Only the write pump
// writes to the socket (gorilla requires a single writer).
func (a *App) handleSOLSocket(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s, err := a.store.GetServer(id)
	if err != nil {
		a.notFoundOrError(w, r, err)
		return
	}
	conn, err := solUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade already wrote the HTTP error (e.g. 403 on bad Origin)
	}
	defer func() { _ = conn.Close() }()

	sess, err := a.sol.Start(r.Context(), s)
	if err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, []byte("\r\n"+err.Error()+"\r\n"))
		return
	}
	defer func() { _ = sess.Close() }()

	// Read pump: browser keystrokes → ipmitool stdin. Closing the session on
	// exit unblocks the write pump.
	go func() {
		defer func() { _ = sess.Close() }()
		for {
			_, data, rerr := conn.ReadMessage()
			if rerr != nil {
				return
			}
			if _, werr := sess.Stdin.Write(data); werr != nil {
				return
			}
		}
	}()

	// Write pump: ipmitool output → browser. Returns on EOF / socket error.
	buf := make([]byte, 4096)
	for {
		n, rerr := sess.Output.Read(buf)
		if n > 0 {
			if werr := conn.WriteMessage(websocket.TextMessage, buf[:n]); werr != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}
```
> Note: `sol.go` does NOT import the `sol` package — it only accesses the
> `a.sol` field (typed in `app.go`) and the returned `error`. The `*sol.Manager`
> type and `sol` import live in `app.go` (Task 6 Step 1).

- [ ] **Step 3: Register the routes**

In `internal/web/routes.go`, after the `// Console.` block add:
```go
	// Serial-over-LAN console.
	mux.HandleFunc("GET /server/{id}/sol/launch", a.requireLogin(true, a.handleSOLLaunch))
	mux.HandleFunc("GET /server/{id}/sol", a.requireLogin(true, a.handleSOLSocket))

	// Static assets (vendored xterm.js); not sensitive, no auth needed.
	mux.Handle("GET /static/", staticHandler())
```

- [ ] **Step 4: Build**

Run: `go build ./... && go vet ./internal/web/ && gofmt -l internal/web/`
Expected: build OK, no vet/gofmt output. (Delete the `var _ = sol.ErrNoCreds` line if vet complains; `a.sol.Start` already uses the package.)

- [ ] **Step 5: Commit**

```bash
git add internal/web/sol.go internal/web/app.go internal/web/routes.go
git commit -m "feat(web): SOL launch + WebSocket bridge handlers"
```

---

## Task 7: WebSocket auth + Origin tests

**Files:**
- Create: `internal/web/sol_ws_test.go`

These tests reuse the shared integration-test helpers already in
`internal/web/integration_test.go` (same `package web`): `testServer(t)` (returns
`(*httptest.Server, *http.Client, *store.Store)` with a cookie jar), `get`,
`postForm`, `csrfFrom`, `mustRedirect`. The default admin has a forced
password-change gate that `requireLogin(true, …)` enforces, so the
authenticated test must clear it (login → change password → add a server),
exactly as `TestFullAuthFlow` does.

- [ ] **Step 1: Write the failing tests**

Create `internal/web/sol_ws_test.go`:
```go
package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

// authenticateAndSeed logs the default admin in, clears the forced-password
// gate, and adds one server (id 1, Redfish creds) so /server/1/sol exists.
func authenticateAndSeed(t *testing.T, base string, c *http.Client) {
	t.Helper()
	_, body := get(t, c, base+"/login")
	resp := postForm(t, c, base+"/login", url.Values{
		"username": {"admin"}, "password": {"admin"}, "csrf_token": {csrfFrom(t, body)},
	})
	mustRedirect(t, resp, "/change-password")
	_, cp := get(t, c, base+"/change-password")
	resp = postForm(t, c, base+"/change-password", url.Values{
		"current_password": {"admin"}, "new_password": {"labpass123"},
		"confirm_password": {"labpass123"}, "csrf_token": {csrfFrom(t, cp)},
	})
	mustRedirect(t, resp, "/")
	_, nb := get(t, c, base+"/server/new")
	resp = postForm(t, c, base+"/server/new", url.Values{
		"name": {"r630"}, "ip_address": {"10.22.40.50"}, "bmc_type": {"idrac"},
		"redfish_user": {"root"}, "redfish_password": {"calvin"},
		"csrf_token": {csrfFrom(t, nb)},
	})
	mustRedirect(t, resp, "/")
}

func wsURL(base string, id int64) string {
	return strings.Replace(base, "http", "ws", 1) + "/server/" + strconv.FormatInt(id, 10) + "/sol"
}

func cookieHeader(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	var parts []string
	for _, ck := range c.Jar.Cookies(u) {
		parts = append(parts, ck.Name+"="+ck.Value)
	}
	return strings.Join(parts, "; ")
}

func TestSOLSocketRequiresLogin(t *testing.T) {
	srv, _, _ := testServer(t)
	// Same-origin header so we get past CheckOrigin and prove auth is what blocks.
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL(srv.URL, 1), http.Header{"Origin": {srv.URL}})
	if err == nil {
		_ = conn.Close()
		t.Fatal("unauthenticated SOL upgrade should fail")
	}
	if resp == nil || resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatalf("expected a non-101 response for unauthenticated upgrade, got %v", resp)
	}
}

func TestSOLSocketRejectsForeignOrigin(t *testing.T) {
	srv, c, _ := testServer(t)
	authenticateAndSeed(t, srv.URL, c)
	h := http.Header{
		"Cookie": {cookieHeader(t, c, srv.URL)},
		"Origin": {"https://evil.example.com"},
	}
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL(srv.URL, 1), h)
	if err == nil {
		_ = conn.Close()
		t.Fatal("foreign-Origin upgrade should be rejected")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 on foreign Origin, got %v", resp)
	}
}
```

> Why no positive end-to-end WS test: a successful upgrade would spawn real
> `ipmitool` against an unreachable BMC, making the test depend on the binary +
> network + timing. The bridge logic is already covered hermetically in
> `internal/sol` (Task 3, fake runner); these web tests cover only the auth +
> Origin gates, which is where the web layer's responsibility lies.

- [ ] **Step 2: Run to verify they pass**

Run: `go test ./internal/web/ -run 'TestSOLSocket' -v`
Expected: both PASS. `TestSOLSocketRequiresLogin` fails the handshake with a
redirect (unauthenticated `requireLogin`); `TestSOLSocketRejectsForeignOrigin`
gets `403` from `CheckOrigin`. If either fails, fix the harness usage — the
Task 6 handler already enforces both gates.

- [ ] **Step 3: Run the whole web suite**

Run: `go test ./internal/web/ -v`
Expected: all PASS (existing integration tests + the new SOL tests).

- [ ] **Step 4: Commit**

```bash
git add internal/web/sol_ws_test.go
git commit -m "test(web): SOL WebSocket requires login and rejects foreign Origin"
```

---

## Task 8: Index "Serial" button

**Files:**
- Modify: `internal/web/templates/index.html`

- [ ] **Step 1: Add the button**

In `internal/web/templates/index.html`, inside `<div class="action-buttons">`, immediately after the `Console` button's closing `</button>`, add:
```html
                        {{if .HasCreds}}
                        <a href="/server/{{.ID}}/sol/launch" target="_blank" rel="noopener"
                            class="btn btn-info btn-sm" title="IPMI Serial-over-LAN console">📟 Serial</a>
                        {{end}}
```

- [ ] **Step 2: Verify it renders**

Run: `go test ./internal/web/ -run TestIntegration -v` (or the existing index-render test)
Expected: PASS — the index template still renders for both creds/no-creds rows.

- [ ] **Step 3: Manual smoke (optional, local)**

Run: `go run ./cmd/lab-manager` then browse to `/`, confirm a "📟 Serial" button appears on rows with credentials and opens `/server/<id>/sol/launch` showing the xterm terminal (it will report disconnected if no BMC is reachable from your dev box — that's expected).

- [ ] **Step 4: Commit**

```bash
git add internal/web/templates/index.html
git commit -m "feat(web): add Serial console button to the server list"
```

---

## Task 9: Docs + full verification

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update CLAUDE.md**

Make three edits in `CLAUDE.md`:

1. In the architecture intro, the line "There is no `static/` directory or JS build; HTML is embedded." → replace with:
   ```
   HTML is embedded; the only static assets are the vendored xterm.js files under
   `internal/web/static/` (embedded via `//go:embed`, served at `/static/`).
   ```

2. In the packages list and the dependency-graph line `model ← secret ← store ← power/console ← web ← cmd`, add `sol` beside `power`/`console`:
   ```
   `model` ← `secret` ← `store` ← `power`/`console`/`sol` ← `web` ← `cmd`
   ```
   and add a bullet:
   ```
   - **`internal/sol`** — IPMI Serial-over-LAN session manager: resolves creds
     (IPMI, else Redfish), runs `ipmitool ... sol activate` via an injectable
     runner, and exposes a `Session` the web layer bridges to a browser terminal.
   ```

3. In the Routes section, under Console, add:
   ```
   - **Serial console**: `/server/<id>/sol/launch` (xterm.js page),
     `/server/<id>/sol` (WebSocket; same-origin session auth + Origin check)
   - **Static**: `/static/...` (embedded vendored xterm.js)
   ```

- [ ] **Step 2: Full verification suite**

Run:
```bash
gofmt -l internal cmd
go vet ./...
go build ./...
go test ./...
```
Expected: `gofmt` prints nothing; `vet` clean; build OK; all tests pass.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document the SOL serial console package, routes, and static dir"
```

---

## Self-Review notes (addressed)

- **Spec coverage:** cred resolution (T2), `-E` env not argv (T2/T3), single-session deactivate-first + cleanup (T3), WS bridge single-writer (T6), Origin check (T6/T7), same-origin session auth (T6 via `requireLogin` + T7), xterm vendored/embedded (T4), launch page (T5), index button gated on `HasCreds` (T8), any-IPMI-server scope (T2 `Creds` works for Supermicro too), deploy note + blank-screen hint (T5 greeting line), docs (T9). KVM/Phase-2 intentionally absent.
- **Type consistency:** `Manager.run` (field) / `runner` interface / `execRunner` / `Session{Stdin io.Writer, Output io.Reader, Close() error}` / `Creds` / `activateArgs` / `deactivateArgs` / `consoleSOLData{ServerID,ServerName}` / `staticHandler()` / `solUpgrader` are used identically across tasks.
- **Harness caveat:** Task 7 Step 1 deliberately discovers the real test-server/login helper instead of hard-coding a name, because the existing `integration_test.go` owns that setup; the test bodies are concrete once the helper name is substituted.
```
