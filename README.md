# Home Lab Server Manager

A Flask web application for managing physical servers via IPMI and Redfish protocols. Control server power states (on/off/restart) and monitor server status through a simple web interface.

## Features

- Web-based server management interface
- Dual protocol support: Redfish and IPMI
- Power control: On, Off, Restart, Cycle
- Real-time server status monitoring
- SQLite database for server configuration
- User authentication

## Quick Start with Docker

### Prerequisites
- Docker
- Docker Compose

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd lab_manager
```

2. Start the application:
```bash
docker-compose up -d
```

3. Access the web interface:
```
http://localhost:5000
```

4. Login with default credentials:
- Username: `admin`
- Password: `admin`

**Important**: Change the default admin password after first login!

### Docker Commands

```bash
# Start the application
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the application
docker-compose down

# Rebuild after code changes
docker-compose up -d --build

# Access container shell
docker-compose exec lab-manager sh

# Remove containers and volumes
docker-compose down -v
```

## Configuration

### Environment Variables

Set these in your environment or create a `.env` file:

```bash
# Production secret key (IMPORTANT!)
FLASK_SECRET_KEY=your-secure-random-key-here

# Flask environment
FLASK_ENV=production
```

### Production Deployment

For production, always set a secure SECRET_KEY:

```bash
export FLASK_SECRET_KEY="$(openssl rand -hex 32)"
docker-compose up -d
```

## Usage

### Adding a Server

1. Navigate to the home page
2. Click "Add New Server"
3. Fill in server details:
   - **Name**: Friendly name for the server
   - **IP Address**: Server's IP address
   - **Credentials**: Either Redfish OR IPMI credentials
     - Redfish: Username and password
     - IPMI: Username and password
   - **Notes**: Optional description

### Managing Servers

- **Power On**: Turn on the server
- **Power Off**: Gracefully shutdown the server
- **Restart**: Restart the server
- **Check Status**: Query current power state
- **Edit**: Update server configuration
- **Delete**: Remove server from database

## Technical Details

### Supported Protocols

**Redfish**:
- REST API-based server management
- Preferred for Dell servers
- Uses HTTPS (SSL verification disabled)

**IPMI**:
- Traditional IPMI over LAN
- Uses `ipmitool` command-line utility
- Fallback option when Redfish unavailable

### Database

- SQLite database stored in `./instance/servers.db`
- Persisted via Docker volume
- Automatic initialization on first run

### Security Notes

- Default admin credentials should be changed immediately
- Server credentials stored in database (plaintext)
- SSL verification disabled for Redfish connections
- SECRET_KEY should be set for production deployments

## Development

See [CLAUDE.md](CLAUDE.md) for detailed development documentation.

### Local Development (Without Docker)

1. Create virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install system dependencies:
```bash
# Ubuntu/Debian
sudo apt-get install ipmitool

# macOS
brew install ipmitool

# Alpine Linux
apk add ipmitool
```

4. Run the application:
```bash
python app.py
```

## License

[Your License Here]

## Contributing

[Contributing Guidelines Here]
