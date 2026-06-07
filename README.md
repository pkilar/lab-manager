# Home Lab Server Manager

A Go web application for managing physical servers via IPMI and Redfish protocols. Control server power states (on/off/restart) and monitor server status through a simple web interface. Ships as a single static binary with templates embedded.

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
# Session-cookie signing key (IMPORTANT!). Generate with: openssl rand -hex 32
LAB_MANAGER_SECRET_KEY=your-secure-random-key-here

# Fernet key for encrypting stored credentials (optional; auto-generated if unset)
LAB_MANAGER_ENCRYPTION_KEY=...

# Wake-on-LAN feature toggle (disabled by default). See "Wake-on-LAN" below.
WOL_ENABLED=false
```

### Production Deployment

For production, always set a secure SECRET_KEY:

```bash
export LAB_MANAGER_SECRET_KEY="$(openssl rand -hex 32)"
docker-compose up -d
```

### Docker Swarm

For Docker Swarm, deploy with `docker-stack.yml` instead of `docker-compose.yml`
(Swarm ignores `build:`, `container_name:`, `network_mode:`, and `restart:`). The
stack pulls the image from the registry, joins the shared `traefik-public` overlay
so Traefik publishes it over HTTPS, and runs a single node-pinned replica (SQLite is
single-writer). The bundled `deploy.labels` route the host `lab.pi.home.kilar.net`
(change the router rule for your own hostname); the cluster's Let's Encrypt wildcard
provides the cert, so no per-router cert config is needed. **Because it's on an
overlay rather than host networking, Wake-on-LAN does not work in this deploy** — see
[Wake-on-LAN](#wake-on-lan-opt-in).

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
   - **Docker Swarm**: the shipped `docker-stack.yml` is on the `traefik-public`
     overlay (for Traefik routing), so WoL is **not** available there. To use WoL on
     Swarm, swap that overlay for the external `host` network (a `networks:` entry
     with `external: true` and `name: host`) and drop the Traefik `deploy.labels` —
     then route to it via Traefik's file provider pointing at the node's `IP:5000`,
     since the swarm provider can't reach a host-networked service.
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

Each server with a MAC address gets an explicit **WoL** button (when the feature is enabled) you can use to send a packet on demand and watch the result in the logs.

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
- Server credentials encrypted at rest with Fernet (key in `instance/.encryption_key`)
- SSL verification disabled for Redfish connections
- SECRET_KEY should be set for production deployments

## Development

See [CLAUDE.md](CLAUDE.md) for detailed development documentation.

### Local Development (Without Docker)

Requires Go 1.26+.

1. Install the `ipmitool` system dependency (needed for IPMI power control):
```bash
# Ubuntu/Debian
sudo apt-get install ipmitool

# macOS
brew install ipmitool

# Alpine Linux
apk add ipmitool
```

2. Build and run the application (listens on `localhost:5000`):
```bash
go build -o lab-manager ./cmd/lab-manager
./lab-manager

# or run directly
go run ./cmd/lab-manager
```

3. Run the tests:
```bash
go test ./...
```

## License

[Your License Here]

## Contributing

[Contributing Guidelines Here]
