# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Home Lab Server Manager - A Flask web application for managing physical servers via IPMI, Redfish, and Wake-on-LAN protocols. Provides a web interface to control server power states (on/off/restart) and monitor server status.

## Development Commands

```bash
# Docker (recommended)
docker-compose up -d                    # Start application
docker-compose up -d --build            # Rebuild after code changes
docker-compose logs -f                  # View logs
docker-compose exec lab-manager sh      # Shell access

# Local development
source .venv/bin/activate               # Activate virtualenv
pip install -r requirements.txt         # Install dependencies
python app.py                           # Run application (localhost:5000)
FLASK_DEBUG=true python app.py          # Run with debug mode

# Wake-on-LAN testing utility
python test_wol.py <MAC_ADDRESS> [TARGET_IP]

# Database access
sqlite3 instance/servers.db
```

## Required Environment Variables

```bash
# Production deployment requires:
FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"

# Optional (auto-generated if not set):
FLASK_ENCRYPTION_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
```

## Architecture

### Single-File Application (`app.py`)

All application logic resides in `app.py` (~1020 lines). Key components:

**Database Models**:
- `Server`: Server configuration with encrypted credentials (Fernet), BMC type, MAC address
- `User`: Authentication with password hashing (werkzeug), forced password change on first login

**Protocol Support** (priority order):
1. **Redfish**: REST API to `https://{ip}/redfish/v1/Systems/System.Embedded.1/` (Dell-specific endpoint)
2. **IPMI**: Command-line via `ipmitool -I lan -H {ip} -U {user} -P {pass} power [on|off|reset|cycle]`
3. **Wake-on-LAN**: Magic packets via `wakeonlan` library (power on only)

**BMC Types** (for console access):
- `idrac` (Dell iDRAC)
- `supermicro` (Supermicro IPMI)
- `ilo` (HPE iLO)
- `generic` (fallback)

**Key Functions**:
- `send_power_command()`: Routes to `redfish_command()`, `ipmi_command()`, or `wol_command()`
- `check_power_status()`: Queries actual power state via Redfish/IPMI
- `encrypt_credential()` / `decrypt_credential()`: Fernet encryption with legacy plaintext fallback
- `generate_console_token()` / `verify_console_token()`: Time-limited HMAC tokens for BMC console access

**Route Structure**:
- Web UI: `/`, `/server/new`, `/server/<id>/edit`, `/server/<id>/power/<action>`
- API: `/api/server/<id>/power/<action>`, `/api/server/<id>/power/check`
- Console: `/server/<id>/console`, `/server/<id>/console/launch`
- Auth: `/login`, `/logout`, `/change-password`

### Database

- SQLite at `instance/servers.db` (auto-created)
- Schema migrations in `run_migrations()` function
- Default admin user created on first startup (username: `admin`, password: `admin`)

### Templates

Located in `templates/`:
- `base.html`: Bootstrap layout
- `index.html`: Server list with power controls
- `new_server.html` / `edit_server.html`: Server configuration forms
- `console_launch.html`: BMC console credential helper
- `login.html` / `change_password.html`: Authentication

## Deployment Options

### Docker Compose
- Uses `network_mode: host` for Wake-on-LAN broadcast packets
- Volume mounts `./instance` for database and encryption key persistence
- Requires `FLASK_SECRET_KEY` environment variable

### Kubernetes (`k8s/`)
- Kustomize-based deployment
- Uses `hostNetwork: true` for WoL (limits to 1 replica per node)
- `Recreate` strategy to prevent SQLite corruption
- See `k8s/README.md` for configuration details

## Protocol Implementation Notes

**Redfish**:
- SSL verification disabled (`verify=False`)
- 30-second timeout on all requests
- Power actions: `{"ResetType": "On|GracefulShutdown|ForceRestart"}`

**IPMI**:
- Requires `ipmitool` binary (installed in Docker image)
- Passwords passed as command-line arguments

**Wake-on-LAN**:
- Sends magic packets on ports 7 and 9
- Also sends to subnet broadcast (assumes /24)
- Server must have WoL enabled in BIOS and be connected to network
