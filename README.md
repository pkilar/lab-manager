# Home Lab Server Manager

A Flask web application for managing physical servers via IPMI and Redfish protocols. Control server power states (on/off/restart) and monitor server status through a simple web interface.

## Features

- Web-based server management interface
- Dual protocol support: Redfish and IPMI
- Power control: On, Off, Restart, Cycle
- Real-time server status monitoring
- Wake-on-LAN support (optional, disabled by default)
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

# Wake-on-LAN feature toggle (disabled by default). See "Wake-on-LAN" below.
WOL_ENABLED=false
```

### Production Deployment

For production, always set a secure SECRET_KEY:

```bash
export FLASK_SECRET_KEY="$(openssl rand -hex 32)"
docker-compose up -d
```

### Docker Swarm

For Docker Swarm, deploy with `docker-stack.yml` instead of `docker-compose.yml`
(Swarm ignores `build:`, `container_name:`, `network_mode:`, and `restart:`). The
stack pulls the image from the registry, uses the `host` network so Wake-on-LAN
broadcasts work, and runs a single node-pinned replica (SQLite is single-writer).

```bash
# Label the node that should hold the data volume (one time):
docker node update --label-add lab_manager_data=true <node-name>

# Deploy (--with-registry-auth lets worker nodes pull from the private registry):
docker stack deploy -c docker-stack.yml --with-registry-auth lab-manager
```

### Wake-on-LAN (opt-in)

Wake-on-LAN (WoL) powers a server **on** by broadcasting a "magic packet" to its
NIC's MAC address. It is **disabled by default** because it only works when the app
runs with host networking and the target hardware is specifically configured for
it. While disabled, the WoL button and 📡 indicator are hidden and the server-side
WoL endpoint refuses requests — but you can still store MAC addresses so they're
ready when you turn it on.

#### Enabling

Set the feature flag and restart:

```bash
# Add WOL_ENABLED=true to your .env, or pass it inline:
WOL_ENABLED=true docker-compose up -d
```

#### Requirements

WoL needs **all** of the following. If any is missing, the packet is sent but the
server won't wake:

1. **`WOL_ENABLED=true`** — the feature flag (also accepts `1`/`yes`/`on`).
2. **Host networking** — magic packets are L2 broadcasts, so the container must
   share the host's network rather than a bridged/NAT network:
   - **Docker Compose**: already set via `network_mode: host` in `docker-compose.yml`.
   - **Docker Swarm**: `network_mode` is ignored by `docker stack deploy`; attach the
     service to the external `host` network instead (a `networks:` entry with
     `external: true` and `name: host`).
   - **Kubernetes**: `hostNetwork: true` (already set in `k8s/deployment.yaml`).
3. **Same broadcast domain** — the host running this app must be on the **same L2
   subnet/VLAN** as the target. The app broadcasts to `255.255.255.255` on UDP ports
   9 and 7, plus the target's `/24` subnet broadcast on port 9; routers don't forward
   these by default.
4. **Server BIOS/UEFI configured** — enable "Wake on LAN" / "Power On by PCIe/PCI"
   and keep the NIC powered in soft-off (S5); on many boards this means disabling
   "Deep Sleep"/ErP/EuP. Use a **wired** Ethernet connection.
5. **MAC address set** — enter the target NIC's MAC on the server's Add/Edit page.

#### How it's used

- When WoL is enabled, an explicit **WoL** button appears for each server that has a MAC address.
- WoL is also the power-on method when a server has a MAC but **no** Redfish/IPMI
  credentials. It can only power **on** — off/restart require Redfish or IPMI.

#### Verifying

Watch the logs while sending a packet — each broadcast attempt is logged:

```bash
docker-compose logs -f
```

You can also test packet delivery independently of the app:

```bash
python test_wol.py <MAC_ADDRESS> [TARGET_IP]
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
