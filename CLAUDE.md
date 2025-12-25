# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Home Lab Server Manager - A Flask web application for managing physical servers via IPMI, Redfish, and Wake-on-LAN protocols. The application provides a web interface to control server power states (on/off/restart) and monitor server status.

## Development Environment Setup

### Docker Deployment (Recommended)

#### Prerequisites
- Docker
- Docker Compose

#### Quick Start
```bash
# Build and start the container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the container
docker-compose down
```

The application runs on `http://localhost:5000`

#### Docker Configuration

**Dockerfile**:
- Base image: `python:3.11-alpine`
- Includes `ipmitool` for IPMI management
- Build dependencies for Python packages (gcc, musl-dev, linux-headers)
- Exposes port 5000

**Network Configuration**:
- Uses `network_mode: host` to enable Wake-on-LAN functionality
- Container shares host's network stack (required for WOL broadcast packets)
- Application accessible on host's port 5000 (no port remapping)

**Volumes**:
- `./instance:/app/instance` - Persists SQLite database between container restarts

**Environment Variables**:
- `FLASK_SECRET_KEY` - Override default SECRET_KEY (recommended for production)
- `FLASK_ENV` - Set to `production` or `development`

#### Production Deployment
```bash
# Set a secure SECRET_KEY via environment variable
export FLASK_SECRET_KEY="your-secure-random-key-here"

# Start in production mode
docker-compose up -d

# Or use inline environment variable
FLASK_SECRET_KEY="your-key" docker-compose up -d
```

#### Docker Commands
```bash
# Rebuild container after code changes
docker-compose up -d --build

# Access container shell
docker-compose exec lab-manager sh

# View real-time logs
docker-compose logs -f lab-manager

# Restart container
docker-compose restart

# Remove container and volumes
docker-compose down -v
```

### Local Development (Without Docker)

#### Prerequisites
- Python 3.x
- `ipmitool` command-line utility (for IPMI server management)
- Virtual environment located at `.venv/`

#### Initial Setup
```bash
# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

The application runs on `http://0.0.0.0:5000` with debug mode enabled by default.

### Running Tests
Currently, there is no test suite configured for this project.

## Architecture

### Application Structure
- **Single-file Flask application**: All logic resides in `app.py`
- **SQLite database**: Located at `instance/servers.db` (auto-created)
- **Jinja2 templates**: Located in `templates/` directory
- **No static assets directory**: Currently not using custom CSS/JS files

### Database Models

**Server Model** (`Server`):
- Stores server configuration including name, IP address, credentials, and MAC address
- Tracks power status and last update timestamp
- Supports Redfish, IPMI, and Wake-on-LAN authentication methods
- `check_power_status()`: Queries actual server power state via API/IPMI
- Credentials stored in plain text (security consideration)
- MAC address field enables Wake-on-LAN for power on operations

**User Model** (`User`):
- Basic authentication with username/password
- Uses werkzeug password hashing
- Default admin user (username: `admin`, password: `admin`) created automatically

### Key Architectural Patterns

**Multi-Protocol Support**:
- Application checks for Redfish credentials first (`redfish_user`), then IPMI (`ipmi_user`), and finally Wake-on-LAN (`mac_address`)
- Redfish: REST API calls to `https://{ip}/redfish/v1/` using requests library
- IPMI: Command-line execution via subprocess running `ipmitool`
- Wake-on-LAN: Network magic packet sent via `wakeonlan` library (power on only)

**Power Management Flow**:
1. `send_power_command()` orchestrates the command dispatch
2. Checks current status via `check_power_status()` before sending commands
3. Routes to `redfish_command()`, `ipmi_command()`, or `wol_command()` based on available credentials
4. Wake-on-LAN used as fallback for power on when no IPMI/Redfish credentials configured
5. Updates database status after successful operations

**Route Architecture**:
- Web UI routes: `/`, `/server/new`, `/server/<id>/edit`, `/server/<id>/power/<action>`
- API routes: `/api/server/<id>/power/<action>`, `/api/server/<id>/power/check`
- All routes require authentication via `@login_required` decorator

### Important Implementation Details

**Redfish Specifics**:
- Hardcoded endpoint: `Systems/System.Embedded.1/` (Dell-specific)
- SSL verification disabled (`verify=False`)
- Power actions: `{"ResetType": "On"}` or `{"ResetType": "GracefulShutdown"}`
- 30-second timeout on all requests

**IPMI Specifics**:
- Commands executed via subprocess: `ipmitool power [on|off|reset|cycle] -I lan -H {ip} -U {user} -P {password}`
- Note: Line 76 has incorrect command format (`"power status"` should be split into separate arguments)
- 30-second timeout on all subprocess calls

**Wake-on-LAN Specifics**:
- Uses `wakeonlan` Python library to send magic packets
- Only supports power on operations (cannot turn off or restart servers)
- Requires MAC address in format: `AA:BB:CC:DD:EE:FF`
- Used as fallback when no Redfish or IPMI credentials configured
- Server must have Wake-on-LAN enabled in BIOS/UEFI settings

**Database Initialization**:
- `db.create_all()` runs at application startup within app context
- Default admin user created via `@app.before_request` hook using `g` object to prevent duplicate creation

**Security Considerations**:
- SECRET_KEY set to placeholder value - should be changed for production
- Credentials stored in plaintext in database
- SSL certificate verification disabled for Redfish
- No CSRF protection configured
- IPMI passwords passed as command-line arguments (visible in process list)

## Common Development Tasks

### Adding a New Server
Navigate to `/server/new` and provide:
- Name and IP address (required)
- Either Redfish OR IPMI credentials (username + password) OR MAC address for Wake-on-LAN
- MAC address enables Wake-on-LAN for power on (useful for servers without management interfaces)
- Optional notes field

### Debugging Power Commands
- Check `subprocess` output for IPMI errors in console logs
- Redfish responses include status codes (200/204 = success)
- Wake-on-LAN magic packets sent via UDP (no response expected)
- Server status updates only on successful commands
- Print statement at line 60 outputs Redfish system URL for debugging

### Database Access
```bash
# Direct SQLite access
sqlite3 instance/servers.db

# View all servers
SELECT * FROM server;

# View users
SELECT * FROM user;
```

### Extending Protocol Support
To add support for other management protocols:
1. Add credential fields to `Server` model
2. Implement command function similar to `ipmi_command()`, `redfish_command()`, or `wol_command()`
3. Update `send_power_command()` to check for new credentials and route accordingly
4. Modify templates to include new credential input fields
5. Update requirements.txt if new dependencies are needed

**Existing Protocols**:
- Redfish: Full power management (on/off/restart) via REST API
- IPMI: Full power management via ipmitool command-line utility
- Wake-on-LAN: Power on only via network magic packets
