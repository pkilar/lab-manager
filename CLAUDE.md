# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Home Lab Server Manager - A Flask web application for managing physical servers via IPMI and Redfish protocols. The application provides a web interface to control server power states (on/off/restart) and monitor server status.

## Development Environment Setup

### Prerequisites
- Python 3.x
- `ipmitool` command-line utility (for IPMI server management)
- Virtual environment located at `.venv/`

### Initial Setup
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
- Stores server configuration including name, IP address, credentials
- Tracks power status and last update timestamp
- Supports both Redfish and IPMI authentication methods
- `check_power_status()`: Queries actual server power state via API/IPMI
- Credentials stored in plain text (security consideration)

**User Model** (`User`):
- Basic authentication with username/password
- Uses werkzeug password hashing
- Default admin user (username: `admin`, password: `admin`) created automatically

### Key Architectural Patterns

**Dual Protocol Support**:
- Application checks for Redfish credentials first (`redfish_user`), falls back to IPMI (`ipmi_user`)
- Redfish: REST API calls to `https://{ip}/redfish/v1/` using requests library
- IPMI: Command-line execution via subprocess running `ipmitool`

**Power Management Flow**:
1. `send_power_command()` orchestrates the command dispatch
2. Checks current status via `check_power_status()` before sending commands
3. Routes to either `redfish_command()` or `ipmi_command()` based on available credentials
4. Updates database status after successful operations

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
- Either Redfish OR IPMI credentials (username + password)
- Optional notes field

### Debugging Power Commands
- Check `subprocess` output for IPMI errors in console logs
- Redfish responses include status codes (200/204 = success)
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
2. Implement command function similar to `ipmi_command()` or `redfish_command()`
3. Update `send_power_command()` to check for new credentials and route accordingly
4. Modify templates to include new credential input fields
