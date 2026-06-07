# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Home Lab Server Manager - A Flask web application for managing physical servers via IPMI, Redfish, and Wake-on-LAN protocols. Provides a web interface to control server power states (on/off/restart/cycle), monitor status, and launch BMC consoles with credential auto-fill.

## Development Commands

```bash
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

# Local development
source .venv/bin/activate               # Activate virtualenv
pip install -r requirements.txt         # Install dependencies
python app.py                           # Run application (localhost:5000)
FLASK_DEBUG=true python app.py          # Run with debug mode

# Wake-on-LAN testing utility (standalone, not part of the app)
python test_wol.py <MAC_ADDRESS> [TARGET_IP]

# Database access
sqlite3 instance/servers.db
```

There is **no automated test suite** and no linter config — `test_wol.py` is a manual diagnostic script, not a pytest target.

## Environment Variables

```bash
# Recommended for any non-throwaway deployment (sessions persist across restarts).
# Optional: if unset, app.py logs a warning and generates a random key per boot.
# start.sh generates one on first run and persists it to .env.
FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"

# Optional: if unset, a Fernet key is generated and saved to instance/.encryption_key (chmod 600).
# Changing it makes existing encrypted credentials unreadable.
FLASK_ENCRYPTION_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"

# Wake-on-LAN feature flag — OFF by default (accepts true/1/yes/on). Requires host
# networking to actually wake hosts; see "Wake-on-LAN" below and the README.
WOL_ENABLED=false
```

## Architecture

### Single-File Application (`app.py`)

Nearly all logic lives in `app.py` (~1315 lines). HTML is in `templates/`; there is no `static/` directory or JS build. Notable cross-cutting setup:

- **CSRF**: `flask_wtf.CSRFProtect` is enabled globally (`WTF_CSRF_TIME_LIMIT = 3600`). Form templates must include the CSRF token; non-GET routes are protected.
- **Input validation**: `validate_ip_address()`, `validate_mac_address()`, `sanitize_server_name()` gate the new/edit server forms, alongside `BMC_TYPES` membership checks.
- **Jinja filters**: `local_time` and `strftime` (registered via `@app.template_filter`) convert stored UTC timestamps to local display time.
- **Password-change gate**: an `@app.before_request` hook (`check_password_change_required`) redirects any authenticated user with `password_change_required` to `/change-password`, except on the login/logout/change-password/static endpoints.
- **Feature flags**: `WOL_ENABLED` (env, default off) gates Wake-on-LAN. An `@app.context_processor` (`inject_feature_flags`) injects `wol_enabled` into every template so the WoL button/📡 indicator hide when off; `wol_command()` and the `/server/<id>/wol` route also refuse when off — defense in depth, so a direct POST is rejected even though the button is hidden. The MAC field stays visible (with a "disabled" note) so stored MACs survive edits.

**Database Models**:
- `Server`: encrypted credentials (`_redfish_password` / `_ipmi_password` columns exposed via `redfish_password` / `ipmi_password` properties that encrypt-on-set, decrypt-on-get), plus `bmc_type`, `mac_address`, `status`, `last_updated` (UTC). `check_power_status()` is a model method that queries live state via Redfish/IPMI.
- `User`: werkzeug password hashing; `password_change_required` defaults to `True` (drives the before_request gate above).

**Power control** — `send_power_command(server, command)` selects exactly one protocol by credential availability (not a fallback chain across all three):
1. **Redfish** if `redfish_user` is set — `https://{ip}/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset` (Dell-specific path). Implements `power on`/`power off`/`power cycle`; a bare `reset` returns "Command not implemented".
2. **IPMI** else if `ipmi_user` is set — `ipmitool -I lan -H {ip} -U {user} -P {pass} power [on|off|reset|cycle]`.
3. **Wake-on-LAN** else if `mac_address` is set **and** command is `power on` — magic packets via `wakeonlan`. WoL is power-on only and is only reached when no Redfish/IPMI user exists. **Gated by `WOL_ENABLED` (default off)**: when disabled, `wol_command()` returns a disabled message without sending.

### Console Auto-Login Subsystem

The most involved feature; understanding it requires reading several functions plus three templates. Two-step, token-gated flow so credentials never sit in a long-lived URL:

1. `GET /server/<id>/console` issues a short-lived (`CONSOLE_TOKEN_VALIDITY = 30s`) HMAC-SHA256 token (`generate_console_token`, keyed by `SECRET_KEY`, bound to server_id + user_id + timestamp) and returns JSON with the `auto_login_url`.
2. `GET /server/<id>/console/launch` verifies the token (`verify_console_token`, constant-time compare + expiry) and renders a BMC-specific launch page.

`get_bmc_login_config(server)` returns per-vendor login/console URLs and form field names. Template selection by `bmc_type`:
- **Supermicro** → `console_launch_supermicro.html` (browser-side form auto-submit to `/cgi/login.cgi`). Note: `supermicro_pre_authenticate()` exists as a server-side SID-extraction helper but is **not currently wired into the launch route**.
- **iDRAC** → calls `idrac_pre_authenticate(server)` then renders `console_launch_idrac.html` with the auth result.
- **else** → `console_launch.html` (manual credential helper with copy-to-clipboard).

`idrac_pre_authenticate()` is a server-side credential **pre-flight only**: it tries Redfish SessionService (iDRAC 8/9) then legacy `/data/login` (iDRAC 6/7/8). Any Redfish session it opens is deleted via `idrac_cleanup_session()` in a `finally` block before returning — the browser cannot reuse a cross-origin session, and leaking sessions would exhaust the iDRAC session table.

### Routes

- **Web UI**: `/`, `/server/new`, `/server/<id>/edit`, `/server/<id>/delete`, `/server/<id>/power/<action>`, `/server/<id>/wol`, `/check-all-servers`
- **API (JSON)**: `/api/server/<id>/power/<action>`, `/api/server/<id>/power/check`
- **Console**: `/server/<id>/console`, `/server/<id>/console/launch`
- **Auth**: `/login`, `/logout`, `/change-password`

All routes except `/login` require authentication (`@login_required`).

### Database

- SQLite at `instance/servers.db` (auto-created via `db.create_all()` inside an app context).
- `run_migrations()` runs before `create_all()` on startup. It is a hand-rolled additive migrator using raw `sqlite3` (no Alembic): it `PRAGMA table_info`s each table and `ALTER TABLE ... ADD COLUMN` for any missing column. Currently backfills `user.password_change_required` and `server.bmc_type`. **Add new columns here** when extending models, or existing databases won't pick them up.
- Default admin user (`admin` / `admin`) is created on first startup with `password_change_required = True`.

### Templates (`templates/`)

`base.html` (Bootstrap layout) · `index.html` (server list + controls) · `new_server.html` / `edit_server.html` · `login.html` / `change_password.html` · console launchers: `console_launch.html` (generic), `console_launch_idrac.html`, `console_launch_supermicro.html`.

## Deployment Options

### Docker Compose
- Built from `Dockerfile` (Alpine + Python 3.12; installs `ipmitool` plus gcc/musl-dev/linux-headers for building Python deps).
- Uses host networking for Wake-on-LAN broadcast packets.
- Bind-mounts `./instance` for the SQLite DB and `.encryption_key`.

### Docker Swarm (primary)

`docker-stack.yml` is the Swarm-native deploy file (`docker stack deploy -c docker-stack.yml --with-registry-auth lab-manager`). **This is how the app is actually deployed** — the `k8s/` manifests below are secondary/vestigial. Swarm **ignores** `build:`, `container_name:`, `network_mode:`, and `restart:`, so the stack: pulls the image from `registry.home.kilar.net` (never builds), provides host networking for WoL via the external `host` network, runs a single replica pinned to a labeled node with `update_config: order: stop-first` (SQLite is single-writer — the Recreate equivalent), and persists data in the `lab_manager_instance` named volume.

### Kubernetes (`k8s/`)
- Kustomize-based (`kustomization.yaml` wires namespace, secret, configmap, pvc, deployment, service; ingress is opt-in).
- `hostNetwork: true` + `dnsPolicy: ClusterFirstWithHostNet` for WoL (effectively 1 replica per node).
- `Recreate` strategy + single replica to avoid SQLite concurrent-write corruption.
- Liveness/readiness probes hit `/login`. Config via configmap + secret `envFrom`; data on a PVC mounted at `/app/instance`.
- See `k8s/README.md` for image build/push and configuration details.

## Protocol Implementation Notes

**Redfish**: SSL verification disabled (`verify=False`), 30s timeout; power actions map to `{"ResetType": "On|GracefulShutdown|ForceRestart"}`.

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
