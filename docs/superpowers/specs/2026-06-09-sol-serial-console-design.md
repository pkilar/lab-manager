# SOL Serial Console — Design (Phase 1)

Status: approved-pending-review
Date: 2026-06-09
Author: Paul Kilar (with Claude)

## Context

`lab_manager` can power-control servers and launch BMC KVM consoles, but the
iDRAC KVM auto-login cannot work cross-origin (the iDRAC SPA's session is an
HttpOnly cookie paired with per-login ST tokens the SPA reads from the login
response body — unreadable/uninjectable from lab-manager's origin). The agreed
direction is a two-phase feature:

- **Phase 1 (this spec):** a browser-based **Serial-over-LAN (SOL) console** —
  reliable, self-contained, no infrastructure changes. Useful on its own (gives
  Supermicro a real text console too) and the dependable fallback for Phase 2.
- **Phase 2 (separate spec, later):** a per-iDRAC **subdomain reverse proxy**
  that makes the iDRAC web console same-origin and enables true KVM auto-login.

This document covers **Phase 1 only**. Phase 2 is out of scope here; see
"Forward note: Phase 2" at the end.

## Goals

- Stream a server's IPMI SOL console to an in-browser terminal (xterm.js).
- Credentials never reach the browser; `ipmitool` runs server-side.
- Available for **any** server with usable IPMI **or** Redfish credentials
  (iDRAC and Supermicro), gated by the existing `serverRow.HasCreds`.
- Works in both the Swarm-overlay and docker-compose deploys (egress IPMI only).
- No silent failures: BMC/auth/ipmitool problems surface in the terminal.

## Non-goals

- KVM (graphical) console — that is Phase 2.
- Recording/log persistence of console sessions.
- Multi-user shared viewing of one SOL session (IPMI SOL is single-session per
  BMC; we manage exactly one active session per server).
- Configuring BIOS serial redirection on the target host (operator's job; if the
  host has no serial console configured, SOL connects but shows nothing — we
  document this, we don't fix it).

## Architecture

```
Browser (xterm.js)  ──WS/WSS /server/{id}/sol──►  lab-manager (web)
   ▲  terminal output (server→client text frames)      │
   │  keystrokes (client→server text frames)           ▼
   └───────────────────────────────────────────  internal/sol.Manager
                                                        │  exec.CommandContext
                                                        ▼
                                   ipmitool -I lanplus -H <ip> -U <u> -E sol activate
                                                        │  UDP 623 (RMCP+)
                                                        ▼
                                                     BMC (iDRAC / Supermicro)
```

The browser only ever talks to lab-manager (same origin → existing session
cookie authenticates the WebSocket). lab-manager owns the `ipmitool` child
process and bridges its stdio to the WebSocket.

### New package: `internal/sol`

Sits beside `power`/`console` in the dependency graph
(`model ← … ← power/console/sol ← web ← cmd`); depends only on `model` and the
standard library. Single responsibility: resolve credentials, run an SOL
session, bridge its I/O, and clean up.

Public surface (sketch — final names settled in the plan):

```go
package sol

// Manager runs SOL sessions. Constructed once and shared.
type Manager struct {
    // runner abstracts process execution so the bridge/lifecycle logic is
    // testable without a real ipmitool/BMC.
    run runner
}

func NewManager() *Manager

// Creds picks the credentials ipmitool should use: IPMI first, Redfish as a
// fallback (root/calvin works for iDRAC IPMI). Returns ok=false if neither set.
func Creds(s *model.Server) (user, pass string, ok bool)

// Session is one live SOL connection. Stdin accepts browser keystrokes; Output
// delivers BMC bytes; Close deactivates the BMC payload and reaps the process.
type Session struct { /* … */ }

// Start clears any stale payload (sol deactivate), then sol activate. The
// returned Session streams until ctx is cancelled or the process exits.
func (m *Manager) Start(ctx context.Context, s *model.Server) (*Session, error)
```

- **Credential resolution:** `IPMIUser/IPMIPassword` if set, else
  `RedfishUser/RedfishPassword`. The password is passed to `ipmitool` via the
  `-E` flag (reads `IPMI_PASSWORD` from the environment), **not** as an argv
  element — so it does not appear in `ps`. (Small hardening over the existing
  IPMI power path, which passes `-P <pass>`; that path is out of scope to change
  here but noted.)
- **Command:** `ipmitool -I lanplus -H <ip> -U <user> -E sol activate`, with
  `IPMI_PASSWORD` in the child env. stdin/stdout/stderr are pipes (no PTY — the
  browser is the terminal; ipmitool streams fine over pipes).
- **Lifecycle / single-session:** IPMI SOL allows one payload per BMC. `Start`
  runs `ipmitool … sol deactivate` first (idempotent; clears a leaked prior
  payload), then `sol activate`. `Close`/ctx-cancel kills the process **and**
  runs `sol deactivate` so the BMC payload is released even if the operator just
  closed the tab. A leaked payload otherwise blocks the next launch.
- **The injectable `runner`** lets tests feed a scripted stdout (e.g. an echo or
  canned boot log) and assert the bridge forwards bytes both ways, without
  spawning `ipmitool`.

### Web layer

Two routes, both `requireLogin(true, …)` (same pattern as the console routes):

- `GET /server/{id}/sol/launch` → renders `console_sol.html`, the xterm.js page.
  No credentials and no token in the page (creds stay server-side; the WS is
  same-origin so the session cookie authenticates it).
- `GET /server/{id}/sol` → **WebSocket upgrade** (gorilla/websocket). On upgrade:
  1. `requireLogin` has already authenticated the session.
  2. **Origin check:** reject the upgrade unless the `Origin` header host matches
     the request host (defense against cross-site WebSocket hijacking — the WS
     handshake is a GET and bypasses the form-based CSRF middleware).
  3. Resolve server + creds; if none, write an error frame and close.
  4. `sol.Manager.Start`; run a read pump (WS→stdin) and write pump
     (stdout→WS). All WS writes happen from the single write-pump goroutine
     (gorilla requires single-writer). Close tears down the session.

`App` gains a `*sol.Manager` field, wired in `App.New` alongside the existing
services.

### Frontend assets

- Vendor **xterm.js**, **@xterm/addon-fit**, and **xterm.css** into a new
  `internal/web/static/xterm/` directory, embedded via `//go:embed` and served
  from a new `GET /static/...` route (file server over the embedded FS).
  - Rationale for embedding vs CDN: preserves the single-static-binary / no-CDN
    property and works on the plain-HTTP LAN deploy without external fetches.
  - Rationale for xterm.js vs a `<pre>`: the BIOS/POST/boot/login stream emits
    ANSI/VT100 escape sequences (colors, cursor moves, clears) that only a real
    terminal emulator renders correctly.
- `console_sol.html`: a standalone full-page document (like the console
  launchers) that mounts xterm.js, opens `wss?://<host>/server/{id}/sol`, wires
  the fit addon + window resize, and forwards terminal input to the socket.

### Index UI

Add a **"📟 Serial Console"** button to each server row, shown under the existing
`{{if .HasCreds}}` block next to the **Console** button; it opens
`/server/{id}/sol/launch` in a new tab. No new view-model field needed
(`HasCreds` already means "has Redfish or IPMI user").

## Error handling

| Condition | Behavior |
|-----------|----------|
| No usable creds | WS opens, writes `No IPMI/Redfish credentials configured`, closes. |
| `ipmitool` missing | Error frame `ipmitool not found`, close. (Present in the image; matters for local `go run`.) |
| BMC unreachable / auth fail / SOL disabled | ipmitool's stderr is forwarded to the terminal, then the session closes with a status line. |
| `sol activate` reports "payload already active" | `Start` already ran `sol deactivate` first; if it still fails, surface the message and close — operator can retry. |
| Browser disconnects | Write pump errors → ctx cancel → process kill + `sol deactivate`. |

All paths converge on `Session.Close` (process reap + `sol deactivate`); no
fire-and-forget goroutines outlive the request.

## Security

- Auth: existing `requireLogin` session for both routes; **Origin check** on the
  WS upgrade.
- Credentials: never sent to the browser; password via `IPMI_PASSWORD` env, not
  argv.
- The `/static/` file server serves only the embedded xterm assets (read-only
  embedded FS — no path traversal to disk).

## Deploy

- Needs outbound UDP 623 (IPMI RMCP+) to the BMC. Egress-only, so it works in
  the Swarm overlay **and** compose deploys — proven by the existing IPMI power
  feature reaching the same BMCs. No host networking required (unlike WoL).
- `ipmitool` and `ca-certificates` already in the runtime image; no Dockerfile
  changes expected for Phase 1.

## Files changed

- `internal/sol/sol.go` (new) — Manager, Creds, Session, lifecycle, bridge.
- `internal/sol/sol_test.go` (new) — cred-resolution + command-construction +
  bridge tests (via injected runner).
- `internal/web/sol.go` (new) — `handleSOLLaunch`, `handleSOLSocket`, Origin
  check, WS pumps.
- `internal/web/routes.go` — register `/server/{id}/sol/launch`,
  `/server/{id}/sol`, and `/static/`.
- `internal/web/app.go` — add/wire `*sol.Manager`.
- `internal/web/render.go` — `consoleSOLData` view model + `handleSOLLaunch`
  render path; `/static/` embed FS.
- `internal/web/templates/console_sol.html` (new) — xterm.js page.
- `internal/web/templates/index.html` — Serial Console button.
- `internal/web/static/xterm/...` (new) — vendored xterm.js + addon-fit + css.
- `go.mod` / `go.sum` — add `github.com/gorilla/websocket`.
- `CLAUDE.md` — note the new `internal/web/static/` dir + `internal/sol` package
  + the SOL routes/feature (the "no static/ directory" line becomes stale).

## Testing

- **Unit (`internal/sol`):**
  - `Creds`: IPMI preferred; Redfish fallback; neither → ok=false.
  - Command construction: argv is `ipmitool -I lanplus -H <ip> -U <user> -E sol
    activate`; env carries `IPMI_PASSWORD`; password absent from argv.
  - Bridge: injected runner emits a canned stream → asserted delivered to
    `Output`; bytes written to `Stdin` reach the runner; `Close` triggers
    `sol deactivate`.
- **Web:**
  - WS upgrade requires a session (unauthenticated → 401/redirect, no upgrade).
  - WS upgrade rejects a foreign `Origin`.
  - `/static/xterm/xterm.js` serves 200 from the embedded FS.
- Existing suites stay green (`go vet`, `gofmt -l`, `go test ./...`).

## Risks / open questions

- **Host serial redirection not configured** → SOL connects but is blank. Mitigate
  with a one-line hint in the terminal on connect ("If blank, enable BIOS serial
  console redirection on the host"). Documented, not solved.
- **iDRAC IPMI-over-LAN disabled** → `sol activate` fails; surfaced as an error.
- **gorilla/websocket** is the first non-sqlite runtime dep; it is pure-Go with
  zero transitive deps, preserving the CGO-free single static binary. (Chosen
  over coder/websocket and a hand-rolled RFC6455 server.)

## Forward note: Phase 2 (out of scope)

Phase 2 adds a per-iDRAC subdomain reverse proxy
(`idrac-<id>.<base-domain>` → transparent relay to the iDRAC, HTTP + WebSocket,
Set-Cookie domain + Origin rewriting, a signed-token → proxy-cookie handshake to
carry lab-manager auth across the subdomain origin). It reuses this phase's
auth/token patterns and the SOL console as its fallback. It will get its own
spec and plan, and it depends on wildcard DNS + a Traefik rule, so it is
deliberately not bundled here.
