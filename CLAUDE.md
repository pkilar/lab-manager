# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Home Lab Server Manager - A Go web application for managing physical servers via IPMI, Redfish, and Wake-on-LAN protocols. Provides a web interface to control server power states (on/off/restart/cycle), monitor status, and launch BMC consoles with credential auto-fill.

The routes, on-disk SQLite schema, Fernet-encrypted credentials, and scrypt password hashes are stable, so an existing `instance/servers.db` keeps working unchanged. The server uses only the standard library's `net/http` (Go 1.22+ `ServeMux` routing — no third-party router), with templates and the timezone DB embedded into a single static binary.

## Development Commands

```bash
# Build / run / test (Go 1.26+)
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

# Optional: if unset, a Fernet key is generated and saved to instance/.encryption_key (chmod 600).
# Changing it makes existing encrypted credentials unreadable. Any urlsafe-base64
# encoding of 32 random bytes is a valid Fernet key (e.g. `openssl rand 32 | basenc --base64url`).
LAB_MANAGER_ENCRYPTION_KEY="..."

# Wake-on-LAN feature flag — OFF by default (accepts true/1/yes/on). Requires host
# networking to actually wake hosts; see "Wake-on-LAN" below and the README.
WOL_ENABLED=false
```

## Architecture

A standard `cmd/` + `internal/` Go layout. The entry point is `cmd/lab-manager/main.go`; everything else lives in `internal/` packages with an acyclic dependency graph (`model` ← `secret` ← `store` ← `power`/`console` ← `web` ← `cmd`). There is no `static/` directory or JS build; HTML is embedded.

Packages:
- **`cmd/lab-manager`** (`package main`) — config loading, wiring (cipher → store+migrations+seed → `web.New`), and the `http.Server` (`:5000`).
- **`internal/model`** — the `Server` and `User` structs and the BMC vendor constants/`ValidBMCType`. No internal dependencies.
- **`internal/secret`** — a from-scratch Fernet implementation (AES-128-CBC + HMAC-SHA256, urlsafe-base64) matching the Fernet token spec on the wire, encryption-key loading, and password hashing in the documented `method$salt$hash` string format (`GeneratePasswordHash`/`CheckPasswordHash`: scrypt + pbkdf2:sha256).
- **`internal/store`** — SQLite access (`modernc.org/sqlite`, pure-Go/CGO-free), schema creation + additive migrations, server/user CRUD, default-admin seeding, and the transparent credential encrypt-on-write / decrypt-on-read.
- **`internal/power`** — `Controller` for Redfish / IPMI / Wake-on-LAN power control and live status checks (persists status via the store).
- **`internal/console`** — `Manager` for console access tokens, plus per-vendor BMC login config and the iDRAC server-side credential pre-flight.
- **`internal/web`** — the HTTP layer: `App` (holds the store + `power.Controller` + `console.Manager` + templates), routing (`routes.go`), handlers, sessions/CSRF (`session.go`), validation (`validate.go`), and template rendering + view models (`render.go`). The embedded templates live in `internal/web/templates/`. `App.New` builds the services; `App.Handler` is the `withSession → withCSRF → routes` chain.

Cross-cutting behavior:

- **CSRF**: `withCSRF` validates a per-session synchronizer token (form field `csrf_token` or `X-CSRFToken` header) on every non-GET/HEAD/OPTIONS request, returning **400** on failure. Form templates embed `{{.CSRF}}`.
- **Sessions**: a signed `session` cookie (HttpOnly, SameSite=Lax, `Secure` set only when the request arrived over HTTPS — directly or via `X-Forwarded-Proto`, so plain-HTTP LAN access still works). Survives restarts when `LAB_MANAGER_SECRET_KEY` is stable. Holds the user id, CSRF token, and pending flashes.
- **Input validation**: `validateIPAddress`, `validateMACAddress`, `sanitizeServerName` gate the new/edit forms alongside `validBMCType`.
- **Timestamps**: `last_updated` is stored as a naive-UTC microsecond string (the existing on-disk column format) and rendered both as a server-side fallback string and an ISO `data-utc` attribute that the index JS converts to the browser's local time.
- **Password-change gate**: `requireLogin(enforcePasswordGate=true, …)` redirects any authenticated user with `password_change_required` to `/change-password`; the gate is disabled for the `change-password` and `logout` handlers so those stay reachable while the flag is set.
- **Feature flags**: `WOL_ENABLED` (env, default off) gates Wake-on-LAN. The flag is injected into templates (`{{.WolEnabled}}`) so the WoL button/📡 indicator hide when off; `wolCommand()` and the `/server/<id>/wol` route also refuse when off — defense in depth, so a direct POST is rejected even though the button is hidden. The MAC field stays visible (with a "disabled" note) so stored MACs survive edits.

**Database models** (`internal/model` + `internal/store`):
- `Server`: credentials are stored encrypted (Fernet) in the `redfish_password` / `ipmi_password` columns; the store decrypts them on read into the struct's plaintext fields and re-encrypts on write. A legacy-plaintext fallback returns the raw value when a column isn't a valid Fernet token (the shipped DB still holds some pre-encryption plaintext credentials). Plus `bmc_type`, `mac_address`, `status`, `last_updated` (UTC). `power.Controller.CheckStatus(server)` queries live state via Redfish/IPMI and persists it.
- `User`: password hashes stored in the `method$salt$hash` string format (scrypt + pbkdf2:sha256); `password_change_required` defaults to `true` (drives the gate above).

**Power control** — `power.Controller.Send(server, command)` selects exactly one protocol by credential availability (not a fallback chain across all three):
1. **Redfish** if `RedfishUser` is set — `https://{ip}/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset` (Dell-specific path). Implements `power on`/`power off`/`power cycle`; anything else returns "Command not implemented".
2. **IPMI** else if `IPMIUser` is set — `ipmitool -I lan -H {ip} -U {user} -P {pass} power [on|off|reset|cycle]`.
3. **Wake-on-LAN** else if `MACAddress` is set **and** command is `power on` — magic packets sent over UDP (with `SO_BROADCAST`). WoL is power-on only and is only reached when no Redfish/IPMI user exists. **Gated by `WOL_ENABLED` (default off)**: when disabled, `wolCommand()` returns a disabled message without sending.

### Console Auto-Login Subsystem

The most involved feature; understanding it requires reading several functions in `console.go`/`handlers.go` plus three templates. Two-step, token-gated flow so credentials never sit in a long-lived URL:

1. `GET /server/<id>/console` issues a short-lived (`console.TokenValiditySeconds = 30`) HMAC-SHA256 token (`console.Manager.GenerateToken`, keyed by `LAB_MANAGER_SECRET_KEY`, bound to server_id + user_id + timestamp) and returns JSON with the `auto_login_url` (built from the external scheme/host).
2. `GET /server/<id>/console/launch` verifies the token (`console.Manager.VerifyToken`, constant-time compare + expiry) and renders a BMC-specific launch page.

`console.LoginConfigFor(server)` returns per-vendor login/console URLs (or nil when no credentials). Template selection by `bmc_type`:
- **Supermicro** → `console_launch_supermicro.html` (browser-side form auto-submit to `/cgi/login.cgi`). There is intentionally no server-side Supermicro pre-authentication step — the launch is purely browser-side.
- **iDRAC** → calls `console.Manager.PreAuthenticateIDRAC(server)` then renders `console_launch_idrac.html` with the auth result.
- **else** → `console_launch.html` (manual credential helper with copy-to-clipboard).

`PreAuthenticateIDRAC()` is a server-side credential **pre-flight only**: it tries Redfish SessionService (iDRAC 8/9) then legacy `/data/login` (iDRAC 6/7/8). Any Redfish session it opens is deleted in a deferred cleanup before returning — the browser cannot reuse a cross-origin session, and leaking sessions would exhaust the iDRAC session table. A connection failure skips the legacy fallback; a timeout still tries it.

### Routes

- **Web UI**: `/`, `/server/new`, `/server/<id>/edit`, `/server/<id>/delete`, `/server/<id>/power/<action>`, `/server/<id>/wol`, `/check-all-servers`
- **API (JSON)**: `/api/server/<id>/power/<action>`, `/api/server/<id>/power/check`
- **Console**: `/server/<id>/console`, `/server/<id>/console/launch`
- **Auth**: `/login`, `/logout`, `/change-password`

Routes are registered with Go 1.22+ method+wildcard patterns (e.g. `POST /server/{id}/power/{action}`, `GET /{$}` for the exact index). All routes except `/login` require authentication via the `requireLogin` wrapper; non-integer ids 404.

### Database

- SQLite at `instance/servers.db`, opened with the pure-Go `modernc.org/sqlite` driver (CGO-free), `SetMaxOpenConns(1)` since SQLite is single-writer.
- `(*Store).migrate()` runs on startup: `CREATE TABLE IF NOT EXISTS` for fresh databases, then an additive migrator (`PRAGMA table_info` + `ALTER TABLE … ADD COLUMN`) that backfills `user.password_change_required` and `server.bmc_type`. **Add new columns here** when extending models, or existing databases won't pick them up.
- Default admin user (`admin` / `admin`) is created on first startup with `password_change_required = true`.

### Templates (`internal/web/templates/`)

Go `html/template`, embedded from `internal/web/templates/` via `//go:embed`. The content pages compose with `base.html` via the `{{block "title"}}` / `{{block "content"}}` layout pattern; the three console launchers are standalone full-page documents. `base.html` (layout + inline CSS + flash messages) · `index.html` (server list + controls) · `new_server.html` / `edit_server.html` · `login.html` / `change_password.html` · console launchers: `console_launch.html` (generic), `console_launch_idrac.html`, `console_launch_supermicro.html`. Credentials embedded in inline JS are emitted through the `js` func (JSON-encoded for safe embedding in a `<script>` context); other interpolations rely on `html/template`'s context-aware escaping.

## Deployment Options

### Docker Compose
- Built from `Dockerfile` — a multi-stage build: `golang:1.26-alpine` compiles a static (`CGO_ENABLED=0`) binary, copied into a minimal `alpine` runtime that installs only `ipmitool` and `ca-certificates`. Templates and the timezone DB are embedded, so nothing else is copied.
- Uses host networking for Wake-on-LAN broadcast packets.
- Bind-mounts `./instance` for the SQLite DB and `.encryption_key`.

### Docker Swarm (primary)

`docker-stack.yml` is the Swarm-native deploy file (`docker stack deploy -c docker-stack.yml --with-registry-auth lab-manager`). **This is how the app is actually deployed** (there are no Kubernetes manifests in this repo). Swarm **ignores** `build:`, `container_name:`, `network_mode:`, and `restart:`, so the stack: pulls the image from `registry.home.kilar.net` (never builds), joins the shared external `traefik-public` overlay so Traefik's swarm provider publishes it at `https://lab.pi.home.kilar.net` (via `deploy.labels`; default TLS cert is the cluster's LE wildcard `*.pi.home.kilar.net`), runs a single replica pinned to a labeled node with `update_config: order: stop-first` (SQLite is single-writer — the Recreate equivalent), and persists data in the `lab_manager_instance` named volume. **Trade-off**: because it's on an overlay rather than host networking, Wake-on-LAN does **not** work in the Swarm deploy (WoL needs host networking — that path stays available in `docker-compose.yml`). The Traefik model lives in `~/Devel/pi-cluster-ansible` (swarm provider reads `deploy.labels` from services on `traefik-public`; `whoami` is the registration template).

## Protocol Implementation Notes

**Redfish**: TLS certificate verification disabled (BMCs ship self-signed certs), 30s timeout; power actions map to `{"ResetType": "On|GracefulShutdown|ForceRestart"}`.

**IPMI**: requires the `ipmitool` binary (present in the Docker image); passwords are passed as command-line arguments.

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
