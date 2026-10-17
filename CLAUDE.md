# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Home Lab Server Manager - A Go web application for managing physical servers via IPMI, Redfish, and Wake-on-LAN protocols. Provides a web interface to control server power states (on/off/restart/cycle), monitor status, and launch BMC consoles with credential auto-fill. An opt-in MCP endpoint (`/mcp`) gives AI agents the same status and power control.

The routes, on-disk SQLite schema, Fernet-encrypted credentials, and scrypt password hashes are stable, so an existing `instance/servers.db` keeps working unchanged. The server uses only the standard library's `net/http` (Go 1.22+ `ServeMux` routing — no third-party router), with templates and the timezone DB embedded into a single static binary.

## Development Commands

```bash
# Build / run / test (Go 1.27.2+)
go build -o lab-manager ./cmd/lab-manager   # Build the binary
go run ./cmd/lab-manager                     # Run locally (listens on :5000)
go test ./...                                # Run the test suite
go vet ./... && gofmt -l .                   # Static checks + format lint

# Docker via helper script (handles compose v1/v2, instance dir, SECRET_KEY)
./start.sh                              # Build and start in background
./start.sh --logs                       # Build, start, tail logs
./start.sh --foreground                 # Build and run in foreground
./start.sh --restart                    # Rebuild and restart
./start.sh --stop                       # Stop the container

# Docker Compose directly
docker-compose up -d                    # Start application
docker-compose up -d --build            # Rebuild after code changes
docker-compose logs -f                  # View logs
docker-compose exec lab-manager sh      # Shell access

# Database access
sqlite3 instance/servers.db
```

The test suite (`*_test.go`) covers crypto interoperability against the documented on-disk formats (Fernet tokens and scrypt+pbkdf2:sha256 hashes), template rendering, validation, and a full in-process HTTP integration flow (login → CSRF → password-change gate → CRUD → encryption-at-rest). There is no separate linter config beyond `go vet`/`gofmt`.

## Environment Variables

The app reads the variable names shown below, which match the long-standing names in existing `.env` files, `docker-compose.yml`, and `docker-stack.yml`, so those work unchanged.

```bash
# Recommended for any non-throwaway deployment (sessions persist across restarts).
# Optional: if unset, the app logs a warning and generates a random key per boot.
# start.sh generates one on first run and persists it to .env.
LAB_MANAGER_SECRET_KEY="$(openssl rand -hex 32)"

# Leave UNSET. A Fernet key is generated on first start and saved to
# instance/.encryption_key (chmod 600); that file is the key's real home.
# docker-stack.yml deliberately does NOT pass this variable: a malformed value is
# rejected and silently falls back to the file (one ERROR line per start), and a
# well-formed but different value makes every stored credential unreadable.
# See README "Backing up the encryption key". (A valid key is any urlsafe-base64
# encoding of 32 random bytes, i.e. 44 chars -- relevant when RESTORING a backup,
# which is done by writing the file, not by setting this.)
LAB_MANAGER_ENCRYPTION_KEY=

# Wake-on-LAN feature flag — OFF by default (true/1/yes/on or false/0/no/off; any
# other value is a startup error, as for LAB_MANAGER_STRICT_CONFIG). Requires host
# networking to actually wake hosts; see "Wake-on-LAN" below and the README.
WOL_ENABLED=false

# BMC KVM reverse-proxy base domain — UNSET by default (feature off). When set
# (e.g. "pi.home.kilar.net") the app also answers idrac-<id>.<domain> and
# pikvm-<id>.<domain>, and the Console (and PiKVM Terminal) buttons on those rows
# auto-log into the BMC web UI. Swarm/Traefik only: needs the (idrac|pikvm)-*
# Traefik router (docker-stack.yml) + wildcard DNS + the *.pi cert. Does nothing
# in the host-networked docker-compose deploy.
LAB_MANAGER_BMC_PROXY_DOMAIN=""

# MCP endpoint bearer token — UNSET by default (feature off; /mcp 404s). When set,
# /mcp serves the Model Context Protocol to AI agents (Authorization: Bearer
# <token>). Validated on EVERY start, strict or not: shorter than 32 chars or
# anything outside RFC 6750 b64token syntax (e.g. a pasted trailing newline) is a
# startup error (checkMCPToken). Works in both deploys (plain path on the main host).
LAB_MANAGER_MCP_TOKEN=""
```

## Architecture

A standard `cmd/` + `internal/` Go layout. The entry point is `cmd/lab-manager/main.go`; everything else lives in `internal/` packages with an acyclic dependency graph (`model` ← `secret` ← `store` ← `power`/`console`/`sol`/`bmcproxy` ← `mcpserver` ← `web` ← `cmd`; `mcpserver` itself uses only `model`, `store` and `power`). HTML is embedded; the only static assets are the vendored xterm.js files under `internal/web/static/` (embedded via `//go:embed`, served at `/static/`).

Packages:
- **`cmd/lab-manager`** (`package main`) — config loading, wiring (cipher → store+migrations+seed → `web.New`), and the `http.Server` (`:5000`).
- **`internal/model`** — the `Server` and `User` structs and the BMC vendor constants/`ValidBMCType`. No internal dependencies.
- **`internal/secret`** — a from-scratch Fernet implementation (AES-128-CBC + HMAC-SHA256, urlsafe-base64) matching the Fernet token spec on the wire, encryption-key loading, and password hashing in the documented `method$salt$hash` string format (`GeneratePasswordHash`/`CheckPasswordHash`: scrypt + pbkdf2:sha256).
- **`internal/store`** — SQLite access (`modernc.org/sqlite`, pure-Go/CGO-free), schema creation + additive migrations, server/user CRUD, default-admin seeding, and the transparent credential encrypt-on-write / decrypt-on-read.
- **`internal/power`** — `Controller` for Redfish / IPMI / Wake-on-LAN / PiKVM ATX power control and live status checks (persists status via the store). `ProtocolFor(server)` is the protocol selection (see "Power control" below) and its single source of truth; `CheckAll` runs `CheckStatus` over many servers, at most 8 at once, for `/check-all-servers` and the MCP `check_all_power_status` tool.
- **`internal/console`** — `Manager` for console access tokens, plus per-vendor BMC login config and the iDRAC server-side credential pre-flight.
- **`internal/sol`** — IPMI Serial-over-LAN session manager: resolves creds (IPMI, else Redfish), runs `ipmitool ... sol activate` via an injectable runner (password via `IPMI_PASSWORD` env, never argv), and exposes a `Session` (`Stdin`/`Output`) the web layer bridges to a browser xterm.js terminal. `Start` deactivates first to clear a stale single-session payload; `Close` cancels and deactivates so the BMC payload is always released. Two lifecycle invariants keep that cleanup reachable (both have stub-`ipmitool` regression tests): `execRunner` feeds stdin from its own goroutine via `StdinPipe` (with `cmd.Stdin` set to a pipe, `Wait` also waits on os/exec's copy goroutine, which sits in `Read` until the next keystroke, so a self-exited ipmitool went unnoticed), and `Close` fails the output pipe (otherwise a caller that stopped reading `Output` leaves os/exec's stdout copy blocked and `Close` hangs forever; `WaitDelay` does not help, since `Wait` still awaits the copy goroutines). The web bridge sends output as **binary** WebSocket frames: serial bytes aren't valid UTF-8, and browsers fail the connection on an invalid text frame. The socket pings every 25s and drops a client silent for 60s (`App.solTimings`), sets a 10s write deadline, and accepts frames up to 64 KiB (a paste is one frame). ipmitool's env is the app's minus every `LAB_MANAGER_*` secret (power's `ipmiEnv` does the same). `Manager.CloseAll` ends every live session at shutdown. The per-server **SOL payload instance** (`server.sol_instance`, 1–15, default 1) selects which serial port the BMC redirects — `solArgs` appends `instance=<n>` to **both** `activate` and `deactivate` (a teardown on the wrong instance would strand the session on the BMC, which allows only one). Instance 1 is left implicit so the default argv is unchanged from before the option existed.
- **`internal/bmcproxy`** — KVM auto-login reverse proxy for **iDRAC and PiKVM**. A `vendor` table (`vendor.go`) holds everything that differs per BMC: host prefix (`idrac-<id>.<domain>` / `pikvm-<id>.<domain>`), the upstream session cookie (`-http-session-` / `auth_token`), login/logout funcs, landing targets, auto-launch injection (iDRAC only), the :5900 console-port passthrough (iDRAC only), and session revalidation (PiKVM only); each `proxySession` records its vendor so GC/drain/displace/IP-change logouts go to the right BMC. A handshake on a host whose vendor doesn't match the server's `bmc_type` 404s, and a relayed session whose vendor or BMC type no longer matches is logged out and re-handshaken (like an IP change). For iDRAC: a signed-token handshake does a server-side `/data/login`, holds the iDRAC `-http-session-` cookie in an in-memory session store keyed by an opaque `bmcproxy` cookie, and injects it upstream so the browser never sees it. A single `httputil.ReverseProxy` (TLS-skip transport) relays HTTP **and** the KVM WebSocket; `ModifyResponse` rewrites `Location` (port-aware), captures/strips iDRAC `Set-Cookie`, and (one-shot per handshake) injects `autoLaunchScript` into the first dashboard HTML so the console opens itself — the viewer is a popup child of the SPA and can only be started by its own `QuickLaunch('viewer')`. The dashboard is a **frameset** and `QuickLaunch` lives in a nested child frame, so the script is injected into `<head>` (a frameset ignores scripts after `</frameset>`) and walks every same-origin frame to find the one defining `QuickLaunch`, then drops a fixed button that calls it on click. It does **not** auto-invoke `QuickLaunch`: a gesture-less `window.open` is blocked by the browser, and `QuickLaunch` called while blocked fires a malformed message the dashboard reports as "Unknown viewer request: 0" — the click is a real gesture, so it is never blocked and never triggers that alert. Rewrite strips `Accept-Encoding` so the Transport hands `ModifyResponse` an identity body to inject into (no gzip surgery); injection is skipped for non-`text/html` or any still-compressed response. See [[project-idrac-console-auth]] for why URL-based deep-linking of the viewer is impossible. `forwardURL` is reduced to a same-origin path (open-redirect guard). Depends only on `model` (via a `ServerLookup` interface satisfied by the store). Guards: non-GET/HEAD/OPTIONS requests and WebSocket upgrades whose `Origin` hostname differs from the proxy host get **403** before any session lookup (the proxy cookie is SameSite=Lax and Rewrite forges a BMC `Origin`, so a sibling `*.<domain>` page could otherwise drive the iDRAC; ports are ignored because the console WS on :5900 comes from the :443 page); a session whose server IP changed since login is logged out of the *old* BMC and re-handshaken rather than replayed to the new address; auto-launch injection runs only on a GET 200 `text/html` response under 4 MiB, so a redirect/error page can't spend the one-shot flag. Expired sessions are left for the hourly GC (which logs them out) — `get()` must not delete them. `Manager.Close` (process shutdown) stops the GC and logs every session out. **PiKVM**: server-side `POST /api/auth/login` (`user`/`passwd` form; 200 with no cookie means kvmd auth is off, and nothing is injected), logout `POST /api/auth/logout`. It lands on a fixed target — `/kvm/`, or `/extras/webterm/ttyd/` for `?to=terminal` (an enum mapped by the vendor, never a client path; an expired terminal tab bounces back with `to=terminal`). A handshake that already holds a session for the same server/IP is **reused** instead of logging in again, because a fresh login displaces (logs out) the session the other open tab (KVM vs Terminal) is using. It is reused only after `GET /api/auth/check` confirms kvmd still honours the token: kvmd keeps tokens in memory, so after a PiKVM reboot or an in-UI Logout, reusing would land every later launch on the PiKVM login page until the 8h proxy TTL. Feature-flagged by `LAB_MANAGER_BMC_PROXY_DOMAIN`; Swarm/Traefik-only.
- **`internal/mcpserver`** — the `/mcp` Model Context Protocol endpoint for AI agents, on the official `github.com/modelcontextprotocol/go-sdk`, **pinned** at v1.8.0 (v1.7/v1.8 flipped defaults and the `MCPGODEBUG` opt-outs go away in 1.9, so read the changelog before bumping). One shared `mcp.Server` behind a **stateless**, JSON-response streamable-HTTP handler that serves both the 2026-07-28 (`server/discover`) protocol and the initialize-based 2025 ones; nothing outlives a request, so there is nothing to close at shutdown. Six tools: `list_servers` (DB only), `check_power_status` / `check_all_power_status` (live reads via `Power.CheckStatus` / `CheckAll`), and `power_on` / `power_off` / `power_cycle` (`Send`; off and cycle carry `destructiveHint`). `live` is inferred from whether the controller re-stamped `LastUpdated`, which every `CheckStatus` path does only on a decisive BMC read — keep it that way. Outputs never include credentials, the MAC or the SOL instance, and there is no CRUD. Wrapping, outermost first: `http.CrossOriginProtection` → `requireBearer` (SHA-256 digests compared in constant time; the SDK's `auth.RequireBearerToken` is unusable here because it demands a token expiry) → SDK handler; `New` panics on an empty token. SDK gotchas the code guards against: tool handlers run on SDK goroutines with no `recover()`, so the `recoverPanics` middleware is all that stops one bad call from killing the process; capabilities are pinned to tools-without-`listChanged` (and no logging) so a 2026-07-28 client can't park a `subscriptions/listen` stream that stalls graceful shutdown; a handler's returned error reaches the client verbatim as an `isError` result, so store errors are logged and replaced with a generic message. The SDK's localhost DNS-rebinding guard is left on: a request that arrives on a loopback address with a non-loopback `Host` gets **403** (a same-host reverse proxy to 127.0.0.1, or a hostname that resolves to 127.0.1.1); Traefik over the overlay and LAN clients are unaffected. Reaches `store`/`power` only through its `Store`/`Power` interfaces (plus `power.ProtocolFor`); tests use fakes and the SDK client over both protocol generations.
- **`internal/web`** — the HTTP layer: `App` (holds the store + `power.Controller` + `console.Manager` + `sol.Manager` + `bmcproxy.Manager` + templates), routing (`routes.go`), handlers (incl. `sol.go`: the SOL launch page + WebSocket bridge; `kvm.go`: the KVM proxy initiator), sessions/CSRF (`session.go`), validation (`validate.go`), template rendering + view models (`render.go`), and the embedded static assets (`static.go`). The embedded templates live in `internal/web/templates/`. `App.New` builds the services; `App.Handler` is a Host dispatch — `idrac-<id>.<domain>` and `pikvm-<id>.<domain>` hosts go straight to `bmcproxy.Manager` (no app middleware), everything else through the `securityHeaders → limitRequestBody → withSession → withCSRF → routes` chain, except the path `/mcp` (`mcpPath`), which gets only `securityHeaders → limitRequestBody → mcpserver`: MCP clients carry a bearer token, not the session cookie, and `withCSRF` would 400 every POST. `App.mcp` is a 404 handler when the token is unset (`mcpHandler`; tests enable it with the `withMCP` opt).

Cross-cutting behavior:

- **CSRF**: `withCSRF` validates a per-session synchronizer token (form field `csrf_token` or `X-CSRFToken` header) on every non-GET/HEAD/OPTIONS request, returning **400** on failure. Form templates embed `{{.CSRF}}`. The token is rotated on login and logout, and logout is `POST /logout` (a CSRF-protected form in the `base.html` header) so a cross-site link can't log anyone out.
- **Security headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` + `Content-Security-Policy: frame-ancestors 'none'`, and an explicit `Referrer-Policy: strict-origin-when-cross-origin` (cross-origin navigations from the `?token=` launch URL send only the origin). Deliberately not `no-referrer`: the Supermicro launcher auto-POSTs to the BMC and some BMC CGIs require a Referer.
- **Shutdown**: on SIGTERM, `srv.Shutdown` drains requests while `App.Close` concurrently ends SOL sessions and logs out KVM proxy sessions (Shutdown tracks neither: they're hijacked/in-memory), all within 8s to fit Docker's default 10s grace period; a timed-out drain force-closes and still exits 0.
- **Sessions**: a signed `session` cookie (HttpOnly, SameSite=Lax, `Secure` set only when the request arrived over HTTPS — directly or via `X-Forwarded-Proto`, so plain-HTTP LAN access still works). Survives restarts when `LAB_MANAGER_SECRET_KEY` is stable. Holds the user id, CSRF token, pending flashes, `iat` (login time) and `pv` (an HMAC marker of the user's password hash). `requireLogin` rejects a session older than `sessionMaxAge` (24h, server-side; the cookie itself stays a browser-session cookie), one without `iat` (pre-expiry cookies), or one whose `pv` no longer matches — so a password change revokes every other session, while `handleChangePassword` re-stamps the session that made the change.
- **Login throttling**: `loginlimit.go` throttles per normalized **username**, not client IP (behind Traefik every request has Traefik's RemoteAddr). Five free failures, then one attempt per cooldown (1s doubling, capped at 5m; the slot is reserved under the lock so concurrent guesses can't share a window), answered with **429** without running scrypt. Unknown usernames are tracked identically and verified against a lazily-generated dummy hash, so neither timing nor throttling reveals which accounts exist. State is in-memory (resets on restart); a known username can be deliberately locked for up to 5m — inherent to per-username throttling.
- **Input validation**: `validateIPAddress`, `validateMACAddress`, `sanitizeServerName`, `parseSOLInstance` gate the new/edit forms alongside `validBMCType`. `parseSOLInstance` rejects out-of-range values rather than clamping them — silently turning a typo into instance 1 would open the console on the wrong port and look like a BMC fault.
- **Timestamps**: `last_updated` is stored as a naive-UTC microsecond string (the existing on-disk column format) and rendered both as a server-side fallback string and an ISO `data-utc` attribute that the index JS converts to the browser's local time.
- **Password-change gate**: `requireLogin(enforcePasswordGate=true, …)` redirects any authenticated user with `password_change_required` to `/change-password`; the gate is disabled for the `change-password` and `logout` handlers so those stay reachable while the flag is set.
- **Feature flags**: `WOL_ENABLED` (env, default off) gates Wake-on-LAN. The flag is injected into templates (`{{.WolEnabled}}`) so the WoL button/📡 indicator hide when off; `wolCommand()` and the `/server/<id>/wol` route also refuse when off — defense in depth, so a direct POST is rejected even though the button is hidden. The MAC field stays visible (with a "disabled" note) so stored MACs survive edits.

**Database models** (`internal/model` + `internal/store`):
- `Server`: credentials are stored encrypted (Fernet) in the `redfish_password` / `ipmi_password` columns; the store decrypts them on read into the struct's plaintext fields and re-encrypts on write. A legacy-plaintext fallback returns the raw value when a column isn't a valid Fernet token (the shipped DB still holds some pre-encryption plaintext credentials); a value that is *shaped* like a Fernet token but fails to decrypt (lost/swapped key) is still returned raw but logged once per server+column, never with the value. Plus `bmc_type`, `mac_address`, `status`, `last_updated` (UTC), and `sol_instance` (serial console port; NULL on pre-migration rows, normalized by `Server.SOLInstanceOrDefault()`). `power.Controller.CheckStatus(server)` queries live state via Redfish/IPMI and persists it.
- `User`: password hashes stored in the `method$salt$hash` string format (scrypt + pbkdf2:sha256); `password_change_required` defaults to `true` (drives the gate above).

**Power control** — `power.Controller.Send(server, command)` selects exactly one protocol by credential availability (not a fallback chain across all three). The selection is `power.ProtocolFor(server)`, which `Send`, `CheckStatus` and the MCP `power_control` field all use — ask it rather than re-deriving the order from credential fields:
0. **PiKVM ATX** if `BMCType == pikvm`, checked first and never falling through (a PiKVM speaks neither Redfish nor IPMI, and WoL would target the PiKVM, not the host): `POST https://{ip}/api/atx/power?action=on|off|reset_hard` (`power cycle` → `reset_hard`; `off` is the short, graceful press). Auth is stateless via `X-KVMD-User`/`X-KVMD-Passwd` headers (Redfish creds, else IPMI), so no kvmd session is created. `CheckStatus` is a hybrid: the ATX power LED (`GET /api/atx` → `leds.power`) is trusted only when it reads **on**. An off or disabled LED falls back to the HDMI video signal: a short kvmd WebSocket session (`/api/ws?stream=1`, same headers) starts the capture and watches `streamer.source.online` for up to `pikvmVideoWindow` (5s). Signal ⇒ On; capture ran with no signal for the whole window ⇒ Off; capture never reported a source, or the dial/auth failed ⇒ cached status. Why: on a DIY PiKVM the LED sense input is often unwired and reads off forever (the user's v2 does). A lone `online:false` doesn't decide Off, because a cold capture start can report a transient 640x480 `online:false` before the real signal. Known false Off: a host that cuts HDMI when its display sleeps (DPMS).
1. **Redfish** if `RedfishUser` is set — `https://{ip}/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset` (Dell-specific path). Implements `power on`/`power off`/`power cycle`; anything else returns "Command not implemented".
2. **IPMI** else if `IPMIUser` is set — `ipmitool -I lan -H {ip} -U {user} -E power [on|off|reset|cycle]` (password via the `IPMI_PASSWORD` env var, never argv).
3. **Wake-on-LAN** else if `MACAddress` is set **and** command is `power on` — magic packets sent over UDP (with `SO_BROADCAST`). WoL is power-on only and is only reached when no Redfish/IPMI user exists. **Gated by `WOL_ENABLED` (default off)**: when disabled, `wolCommand()` returns a disabled message without sending.

### Console Auto-Login Subsystem

The most involved feature; understanding it requires reading several functions in `console.go`/`handlers.go` plus three templates. Two-step, token-gated flow so credentials never sit in a long-lived URL:

1. `GET /server/<id>/console` issues a short-lived (`console.TokenValiditySeconds = 30`) HMAC-SHA256 token (`console.Manager.GenerateToken`, keyed by `LAB_MANAGER_SECRET_KEY`, bound to server_id + user_id + timestamp) and returns JSON with the `auto_login_url` (built from the external scheme/host).
2. `GET /server/<id>/console/launch` verifies the token (`console.Manager.VerifyToken`, constant-time compare + expiry) and renders a BMC-specific launch page.

`console.LoginConfigFor(server)` returns per-vendor login/console URLs (or nil when no credentials). Template selection by `bmc_type`, plus the `manual=1` query flag:
- **Supermicro** → `console_launch_supermicro.html` (browser-side form auto-submit to `/cgi/login.cgi`). There is intentionally no server-side Supermicro pre-authentication step — the launch is purely browser-side. The page **does not display the credentials**: it auto-logs-in, so showing them made every launch a credential popup. The password is still in the document because the form POST needs it — that is inherent to the browser-side approach, so assert on the credential *UI* (not the string) when testing.
- **`manual=1`** (set by `/console/manual`, the 🔑 button) skips only the auto-login machinery, so Supermicro falls through to the generic credentials helper. iDRAC deliberately ignores the flag: its page does no auto-login of its own (the proxy does) and it reports whether the stored credentials still work — worth keeping on the copy/paste path.
- **iDRAC** → calls `console.Manager.PreAuthenticateIDRAC(server)` then renders `console_launch_idrac.html` with the auth result.
- **else** → `console_launch.html` (manual credential helper with copy-to-clipboard). This page is only reached via the 🔑 button now: `App.consoleTarget` sends the primary Console button of a vendor with `SupportsAutoLogin == false` (generic, iLO, PiKVM without the proxy) straight to `cfg.ConsoleURL` instead, because the launch page it would otherwise render is byte-for-byte the 🔑 page — so "Console" popped up a credential list rather than opening a console.

**PiKVM** has `SupportsAutoLogin == false` and no launch page: kvmd's `auth_token` cookie is `SameSite=Strict`, so a cookie set by a cross-site form POST (the Supermicro trick) is never sent on the navigation into `/kvm/` that follows — auto-login exists only through bmcproxy. Its `BMCLoginConfig.TerminalURL` (`/extras/webterm/ttyd/`, kvmd's ttyd) drives `App.terminalTarget`: a PiKVM row shows **📟 Terminal** in place of the IPMI **📟 Serial** button (a PiKVM serves no SOL), linking `/server/<id>/kvm?to=terminal` when the proxy fronts it, else the PiKVM URL directly.

`App.kvmTarget` (proxy path, gated by `bmcproxy.Manager.Supports(bmcType)`) is deliberately separate from `App.consoleTarget` (button href). `kvm.go` guards on **kvmTarget**: now that consoleTarget returns a BMC URL for non-iDRAC vendors, reusing it there would send a generic server into the iDRAC proxy handshake instead of degrading to the credentials page.

`PreAuthenticateIDRAC()` is a server-side credential **pre-flight only**: it tries Redfish SessionService (iDRAC 8/9) then legacy `/data/login` (iDRAC 6/7/8). Any Redfish session it opens is deleted in a deferred cleanup before returning — the browser cannot reuse a cross-origin session, and leaking sessions would exhaust the iDRAC session table. A connection failure skips the legacy fallback; a timeout still tries it.

### Routes

- **Web UI**: `/`, `/server/new`, `/server/<id>/edit`, `/server/<id>/delete`, `/server/<id>/power/<action>`, `/server/<id>/wol`, `/check-all-servers`
- **API (JSON)**: `/api/server/<id>/power/<action>`, `/api/server/<id>/power/check`
- **Console**: `/server/<id>/console` (JSON), `/server/<id>/console/launch`, `/server/<id>/console/manual` (the 🔑 button — mints a token and redirects to `launch?manual=1`; shown on every row with credentials, since no launch page displays them any more)
- **Serial console (SOL)**: `/server/<id>/sol/launch` (xterm.js page), `/server/<id>/sol` (WebSocket; same-origin session auth + `Origin` check, gorilla/websocket)
- **Static**: `/static/...` (embedded vendored xterm.js; no auth)
- **BMC KVM proxy** (when `LAB_MANAGER_BMC_PROXY_DOMAIN` set): `/server/<id>/kvm[?to=terminal]` (login-gated initiator on the main host → mints a token, 302 to the vendor subdomain; `to` is an enum, never a path) and, on `idrac-<id>.<domain>` / `pikvm-<id>.<domain>`, `/__labmgr/auth` (handshake) + transparent relay of everything else to the BMC
- **Auth**: `/login`, `POST /logout`, `/change-password`
- **MCP** (when `LAB_MANAGER_MCP_TOKEN` set): `POST /mcp` — streamable HTTP, stateless, JSON responses; bearer-token auth only (no session/CSRF); GET/DELETE answer 405. Dispatched in `App.Handler`, not `routes()`.

Routes are registered with Go 1.22+ method+wildcard patterns (e.g. `POST /server/{id}/power/{action}`, `GET /{$}` for the exact index). All routes except `/login` require authentication via the `requireLogin` wrapper (`/mcp` uses its bearer token instead); non-integer ids 404.

### Database

- SQLite at `instance/servers.db`, opened with the pure-Go `modernc.org/sqlite` driver (CGO-free), `SetMaxOpenConns(1)` since SQLite is single-writer.
- `(*Store).migrate()` runs on startup: `CREATE TABLE IF NOT EXISTS` for fresh databases, then an additive migrator (`PRAGMA table_info` + `ALTER TABLE … ADD COLUMN`) that backfills `user.password_change_required` and `server.bmc_type`. **Add new columns here** when extending models, or existing databases won't pick them up.
- Default admin user (`admin` / `admin`) is created on first startup with `password_change_required = true`.

### Templates (`internal/web/templates/`)

Go `html/template`, embedded from `internal/web/templates/` via `//go:embed`. The content pages compose with `base.html` via the `{{block "title"}}` / `{{block "content"}}` layout pattern; the three console launchers are standalone full-page documents. `base.html` (layout + inline CSS + flash messages) · `index.html` (server list + controls) · `new_server.html` / `edit_server.html` · `login.html` / `change_password.html` · console launchers: `console_launch.html` (generic), `console_launch_idrac.html`, `console_launch_supermicro.html`. Credentials embedded in inline JS are emitted through the `js` func (JSON-encoded for safe embedding in a `<script>` context); other interpolations rely on `html/template`'s context-aware escaping.

## Deployment Options

### Docker Compose
- Built from `Dockerfile` — a multi-stage build: `golang:1.27-alpine` compiles a static (`CGO_ENABLED=0`) binary, copied into a minimal `alpine:3.24` runtime that installs only `ipmitool`, `ca-certificates` and `su-exec`. Templates and the timezone DB are embedded, so nothing else is copied.
- **Runs unprivileged.** `docker-entrypoint.sh` starts as root only to `chown -R` + `chmod 0700` `/app/instance`, then `su-exec`s the app as `PUID:PGID` (default `10001:10001`; `PUID=0` and non-numeric values are refused). Re-owning on every start migrates volumes written by older root-run images (root-owned `servers.db` / 0600 `.encryption_key`) with no manual step. `docker-compose.yml` sets `PUID`/`PGID` to `1000` so the bind-mounted `./instance` stays usable from the host; the Swarm stack uses the default. Nothing the app does needs root (BMC calls and WoL broadcasts are ordinary sockets; it listens on 5000).
- Uses host networking for Wake-on-LAN broadcast packets.
- Bind-mounts `./instance` for the SQLite DB and `.encryption_key`.

### Docker Swarm (primary)

`docker-stack.yml` is the Swarm-native deploy file (`docker stack deploy -c docker-stack.yml --with-registry-auth lab-manager`). **This is how the app is actually deployed** (there are no Kubernetes manifests in this repo). Swarm **ignores** `build:`, `container_name:`, `network_mode:`, and `restart:`, so the stack: pulls the image from `registry.home.kilar.net` (never builds), joins the shared external `traefik-public` overlay so Traefik's swarm provider publishes it at `https://lab.pi.home.kilar.net` (via `deploy.labels`; default TLS cert is the cluster's LE wildcard `*.pi.home.kilar.net`), runs a single replica pinned to a labeled node with `update_config: order: stop-first` (SQLite is single-writer — the Recreate equivalent), and persists data in the `lab_manager_instance` named volume. **Trade-off**: because it's on an overlay rather than host networking, Wake-on-LAN does **not** work in the Swarm deploy (WoL needs host networking — that path stays available in `docker-compose.yml`). Conversely, the **BMC KVM reverse proxy (iDRAC + PiKVM auto-login) is Swarm-only** (the inverse of WoL): it needs Traefik + the `(idrac|pikvm)-*` router + `LAB_MANAGER_BMC_PROXY_DOMAIN`, so it does nothing in the host-networked compose deploy (PiKVM rows there link straight to the PiKVM and you log in by hand). The Traefik model lives in `~/Devel/pi-cluster-ansible` (swarm provider reads `deploy.labels` from services on `traefik-public`; `whoami` is the registration template).

## Protocol Implementation Notes

**Redfish**: TLS certificate verification disabled (BMCs ship self-signed certs), 30s timeout, redirects **not** followed (a 307/308 would replay the login JSON with the password to whatever host it names; a BMC API never legitimately redirects). The iDRAC session DELETE takes only the *path* of the `Location` header and always targets the BMC, so the `X-Auth-Token` can't be sent elsewhere; power actions map to `{"ResetType": "On|GracefulShutdown|ForceRestart"}`.

**IPMI**: requires the `ipmitool` binary (present in the Docker image). The password is passed via `-E` + the `IPMI_PASSWORD` env var (power, status, and SOL alike), so it never appears in `ps` / `/proc/<pid>/cmdline`.

**Wake-on-LAN**: **off by default — gated behind `WOL_ENABLED`** (see Feature flags above). When enabled, sends magic packets to `255.255.255.255` on ports 9 and 7, plus the server's `/24` subnet broadcast on port 9; optimistically sets status to `On` (real state confirmed on next status check). Requires host networking and BIOS WoL support; full requirements are in the README's "Wake-on-LAN (opt-in)" section.

## GBrain Search Guidance (configured by /sync-gbrain)
<!-- gstack-gbrain-search-guidance:start -->

GBrain is set up and synced on this machine. The agent should prefer gbrain
over Grep when the question is semantic or when you don't know the exact
identifier yet. Two indexed corpora available via the `gbrain` CLI:
- This repo's code (registered as `gstack-code-<repo>` source).
- `~/.gstack/` curated memory (registered as `gstack-brain-<user>` source via
  the existing federation pipeline).

Prefer gbrain when:
- "Where is X handled?" / semantic intent, no exact string yet:
    `gbrain search "<terms>"` or `gbrain query "<question>"`
- "Where is symbol Y defined?" / symbol-based code questions:
    `gbrain code-def <symbol>` or `gbrain code-refs <symbol>`
- "What calls Y?" / "What does Y depend on?":
    `gbrain code-callers <symbol>` / `gbrain code-callees <symbol>`
- "What did we decide last time?" / past plans, retros, learnings:
    `gbrain search "<terms>" --source gstack-brain-<user>`

Grep is still right for known exact strings, regex, multiline patterns, and
file globs. The brain auto-syncs incrementally on every gstack skill start.
Run `/sync-gbrain` to force-refresh, `/sync-gbrain --full` for full reindex.

<!-- gstack-gbrain-search-guidance:end -->
