# Home Lab Server Manager

A Go web application for managing physical servers via IPMI and Redfish protocols. Control server power states (on/off/restart) and monitor server status through a simple web interface. Ships as a single static binary with templates embedded.

## Features

- Web-based server management interface
- Dual protocol support: Redfish and IPMI
- PiKVM support: KVM and web terminal buttons, power via its ATX API
- Power control: On, Off, Restart, Cycle
- Real-time server status monitoring
- Wake-on-LAN support (optional, disabled by default)
- MCP server so AI agents such as Claude Code can check status and control power (optional, disabled by default)
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
# When set it must be at least 32 characters, or the app refuses to start
# (strict mode or not). Unset: a random key per boot, sessions don't persist.
LAB_MANAGER_SECRET_KEY=your-secure-random-key-here

# Fernet key for encrypting stored credentials. Leave UNSET: the app generates
# one on first start and keeps it in instance/.encryption_key. Setting it to a
# different valid key makes every stored credential unreadable, and the Swarm
# stack does not pass it at all. See "Backing up the encryption key" below --
# that file is the one thing here you cannot regenerate.
LAB_MANAGER_ENCRYPTION_KEY=

# Wake-on-LAN feature toggle (disabled by default). See "Wake-on-LAN" below.
WOL_ENABLED=false

# BMC KVM reverse-proxy base domain (disabled by default). See "iDRAC KVM
# auto-login" and "PiKVM" below. Swarm/Traefik deploy only.
LAB_MANAGER_BMC_PROXY_DOMAIN=

# Bearer token for the MCP endpoint (disabled by default). At least 32
# characters; generate with: openssl rand -hex 32. See "MCP server for AI
# agents" below.
LAB_MANAGER_MCP_TOKEN=

# Built-in HTTPS on :5000 (disabled by default). Paths to a PEM certificate and
# key, inside the container. Set BOTH or neither; one alone is a startup error.
# See "TLS (docker-compose)" below.
LAB_MANAGER_TLS_CERT=
LAB_MANAGER_TLS_KEY=
```

### TLS (docker-compose)

**The compose deploy serves plain HTTP on :5000 unless you set TLS.** Session
cookies, the console launch token and, if enabled, the `/mcp` bearer token then
cross the network in cleartext. Do not expose `/mcp` over plain HTTP on an untrusted
LAN: either enable the built-in TLS below or front the app with a TLS-terminating
proxy (the Swarm deploy gets this from Traefik). With a token set and no TLS the app
logs a startup warning.

Set `LAB_MANAGER_TLS_CERT` and `LAB_MANAGER_TLS_KEY` to a PEM certificate and
private key and the app serves HTTPS (TLS 1.2 or newer) on :5000 instead of HTTP. The
pair is loaded at startup, so a missing, unreadable or mismatched file stops the
app with a clear error rather than failing on the first request. The startup log
line reports `scheme=https`.

```bash
# Self-signed cert for a LAN host (adjust the names), readable by PUID:PGID.
# Browsers will warn until you trust it; use your own CA or Let's Encrypt for
# anything longer-lived.
mkdir -p tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout tls/key.pem -out tls/cert.pem -days 365 \
  -subj "/CN=lab.example.lan" -addext "subjectAltName=DNS:lab.example.lan,IP:192.168.1.10"
chmod 0644 tls/cert.pem && chmod 0640 tls/key.pem
```

Then uncomment the `./tls:/tls:ro` volume and the two env lines in
`docker-compose.yml` (or set them in `.env`):

```yaml
    volumes:
      - ./tls:/tls:ro
    environment:
      - LAB_MANAGER_TLS_CERT=/tls/cert.pem
      - LAB_MANAGER_TLS_KEY=/tls/key.pem
```

The container healthcheck, if you add one, must use `https://` and `--no-check-certificate`
for a self-signed cert.

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

### Backing up the encryption key

Stored BMC credentials are encrypted with a Fernet key. **The key is not in this
repo, not in your `.env`, and not in any backup you have unless you made one on
purpose.** Without it, `servers.db` is unreadable — the passwords are gone and
every server has to be re-entered by hand.

**Where it comes from.** Nobody configures it. On first start the app looks for
`LAB_MANAGER_ENCRYPTION_KEY`, then for `instance/.encryption_key`; finding
neither, it generates 32 random bytes, base64url-encodes them to a 44-character
file, writes it `0600`, and logs `generated new encryption key`. Every start
after that reads the same file. So the key's real home is the data volume:

| Deploy | Location |
|---|---|
| docker-compose | `./instance/.encryption_key` (bind mount) |
| Swarm | the `lab_manager_instance` volume, on the node labelled `lab_manager_data=true` |

**Do not set `LAB_MANAGER_ENCRYPTION_KEY` in the Swarm stack to "configure" it.**
The variable is not passed in `docker-stack.yml`, deliberately. It can only
duplicate the file or contradict it, and both fail quietly: a malformed value is
rejected and silently falls back to the file (one `ERROR` line per start, easy to
miss for months), while a well-formed *different* value is accepted and makes
every stored credential decrypt to garbage.

**Backing it up.** Copy the file somewhere durable and secret — a password
manager, or `ansible-vault` alongside the other cluster secrets:

```bash
# Swarm: from the node holding the volume
CID=$(docker ps --filter name=lab-manager --format '{{.ID}}' | head -1)
docker exec "$CID" cat /app/instance/.encryption_key > lab-manager.key
chmod 600 lab-manager.key

# docker-compose: it is just a file
cp instance/.encryption_key lab-manager.key
```

Record its fingerprint so you can tell later whether a backup still matches the
running key, without either of them being printed:

```bash
docker exec "$CID" sha256sum /app/instance/.encryption_key | cut -c1-16
sha256sum lab-manager.key | cut -c1-16      # must match
```

Back up `servers.db` at the same time and keep them together — each is useless
without the other, and a key restored against a *different* database decrypts to
nothing.

**Restoring.** Write the file back into the volume and restart; do not set the
env var. The app uses an existing file as-is and only generates a key when none
is found, so restoring before first start is enough:

```bash
docker run --rm -i -v lab-manager_lab_manager_instance:/v alpine \
  sh -c 'cat > /v/.encryption_key && chmod 600 /v/.encryption_key' < lab-manager.key
```

The restored file is root-owned; that's fine — the container entrypoint re-owns
`/app/instance` to the unprivileged app user on every start.

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

1. **`WOL_ENABLED=true`** — the feature flag (also accepts `1`/`yes`/`on`; a value that isn't one of those or `false`/`0`/`no`/`off` stops startup with an error rather than silently meaning "off").
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

### iDRAC KVM auto-login (opt-in)

By default, the **Console** button for an iDRAC opens the iDRAC login page and hands
you the verified credentials to paste — true one-click auto-login isn't possible
across origins. When you enable the **KVM reverse proxy**, an extra **KVM** button
appears on iDRAC rows that logs you straight into the iDRAC web UI (and its HTML5
Virtual Console) with no typing.

It works by serving each iDRAC under its own subdomain, `idrac-<id>.<your-domain>`,
proxied through lab-manager: lab-manager performs the iDRAC login server-side, holds
the iDRAC session token server-side, and relays the browser's traffic (including the
KVM WebSocket) to the iDRAC. Because the browser talks only to lab-manager, the iDRAC
sees a single consistent client and the login sticks. The iDRAC session token is never
exposed to the browser. (The serial console / SOL remains available as a fallback.)

#### Enabling (Docker Swarm / Traefik only)

This feature needs the Traefik reverse-proxy deploy; it does nothing in the
host-networked `docker-compose` setup. Requirements:

1. **`LAB_MANAGER_BMC_PROXY_DOMAIN`** set to your base domain (e.g.
   `pi.home.kilar.net`) in the stack environment.
2. A Traefik router sending `idrac-*.<domain>` to the lab-manager service — already
   included in `docker-stack.yml` (a `HostRegexp` router reusing the default
   wildcard cert).
3. Wildcard DNS (`*.<domain>`) resolving to the cluster, and a TLS cert covering the
   one-label `idrac-<id>.<domain>` names (the cluster's `*.pi.home.kilar.net` wildcard
   already covers `idrac-<id>.pi.home.kilar.net`).

Only iDRAC servers with stored credentials show the KVM button.

### PiKVM

Choose **PiKVM** as the BMC type and enter the PiKVM web login (e.g. `admin`) as the
**Redfish** username/password (the IPMI fields work too; Redfish wins if both are
set). A PiKVM row gets:

- **Console**: the PiKVM KVM page (`/kvm/`).
- **📟 Terminal**: the PiKVM web terminal (`/extras/webterm/ttyd/`), in place of the
  IPMI serial console, which a PiKVM does not serve.
- **Start / Stop / Restart**: the PiKVM ATX API (`/api/atx`), so these only work if
  the ATX board's button wires are connected to the host. Stop is a short (graceful)
  power-button press; Restart presses the reset button.
- **Status** trusts the ATX power LED only when it reads on. Otherwise it checks the
  HDMI video signal, which takes up to 5s when there is no signal. This covers
  builds whose LED sense wire isn't connected, where the LED always reads off. A host
  that turns HDMI off when its display sleeps will show Off.

With `LAB_MANAGER_BMC_PROXY_DOMAIN` set, Console and Terminal open already logged in
through `pikvm-<id>.<your-domain>`. This is the same reverse proxy as the iDRAC
feature, and the `docker-stack.yml` router already matches `pikvm-*`. The proxy is
the only way to log in automatically: PiKVM's `auth_token` cookie is
`SameSite=Strict`, so a cookie set by a cross-site login is never sent on the
navigation that follows. Without the proxy, both buttons open the PiKVM's own pages
and you log in there (🔑 shows the credentials).

### MCP server for AI agents (opt-in)

Setting `LAB_MANAGER_MCP_TOKEN` turns on a [Model Context Protocol](https://modelcontextprotocol.io)
endpoint at `/mcp`, so an AI agent such as Claude Code can see your servers, check
their power state and power them on or off. The app serves it itself (streamable
HTTP, stateless, on the same host and port as the web UI), so it works in both the
`docker-compose` and the Swarm deploy. With the variable unset, `/mcp` returns 404.

#### Enabling

1. Generate a token: `openssl rand -hex 32`. The app refuses to start if the token
   is shorter than 32 characters or contains anything but letters, digits and
   `-._~+/=`.
2. Set `LAB_MANAGER_MCP_TOKEN` to it (`.env` for docker-compose; the Portainer stack
   environment for Swarm, since `docker stack deploy` does not read `.env`) and
   redeploy.

#### Connecting Claude Code

```bash
claude mcp add --transport http --scope user lab-manager \
  https://lab.pi.home.kilar.net/mcp --header "Authorization: Bearer <token>"
```

`--scope user` keeps the token in your private `~/.claude.json`. Don't use
`--scope project`, which writes it into the repository's `.mcp.json`. The endpoint
only takes a static bearer token (no OAuth), so use a client that lets you set the
`Authorization` header.

#### Tools

| Tool | What it does |
|------|--------------|
| `list_servers` | Every server's id, name, IP, BMC type, power-control path, last recorded status and notes. Reads the database only; no BMC is contacted. |
| `check_power_status` | Reads one server's power state from its BMC and records it. Up to ~30s on a slow or unreachable BMC; if the BMC can't be read, the last recorded status comes back marked `live: false`. |
| `check_all_power_status` | The same for every server, in parallel. |
| `power_on` | Powers on through the server's power-control path (PiKVM, Redfish, IPMI, or Wake-on-LAN for MAC-only servers). |
| `power_off` | Graceful shutdown on Redfish and PiKVM; on IPMI it cuts power immediately. Marked destructive. |
| `power_cycle` | Hard reset (Redfish ForceRestart, IPMI power cycle, PiKVM reset button). Marked destructive. |

Power tools return once the BMC accepts the command, not when the server has finished
booting or shutting down. Ask for `check_power_status` afterwards to confirm.

#### Security

- The token grants power control over every server. Treat it like
  `LAB_MANAGER_SECRET_KEY`. To rotate it, set a new value and redeploy; the old one
  stops working immediately.
- Stored BMC credentials, MAC addresses and serial-console settings are never sent
  over MCP, and there are no tools to add, edit or delete servers. Server notes *are*
  returned by `list_servers`, so keep secrets out of them.
- `/mcp` ignores the web session cookie and needs no CSRF token: the bearer token is
  the only way in. Cross-origin browser requests to it are rejected.
- `power_off` and `power_cycle` carry MCP's destructive hint, and Claude Code asks
  before every tool call unless you allow it. Every power command sent over MCP is
  logged as `mcp power command`.

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

**PiKVM ATX** (BMC type PiKVM only):
- kvmd HTTP API (`/api/atx`, `/api/atx/power`), HTTPS with SSL verification disabled
- Stateless auth via the `X-KVMD-User` / `X-KVMD-Passwd` headers, so no session is left behind

### Database

- SQLite database stored in `./instance/servers.db`
- Persisted via Docker volume
- Automatic initialization on first run

### Security Notes

- Default admin credentials should be changed immediately
- Server credentials encrypted at rest with Fernet (key in `instance/.encryption_key`)
- SSL verification disabled for Redfish connections
- The container runs the app as an unprivileged user: the entrypoint re-owns
  `/app/instance` and drops root via `su-exec`. Default uid/gid `10001`; set
  `PUID`/`PGID` to override (`docker-compose.yml` uses `1000` so the bind-mounted
  `./instance` stays readable from the host). Volumes from older root-run images
  are migrated automatically on first start.
- `PUID`/`PGID` must be plain decimal numbers of at most 10 digits. Leading zeros are
  stripped first, so `00`, `000` and `0` all count as 0, and uid 0 or gid 0 is
  refused: the container will not run the app as root (`+0`, `-1`, `abc` and empty
  values are rejected too). `01000` is accepted as `1000`.
- `LAB_MANAGER_SECRET_KEY` should be set for production deployments, and must be at
  least 32 characters whenever it is set (`openssl rand -hex 32`); a shorter value is a
  startup error
- The container drops all Linux capabilities except the five its entrypoint needs
  (`CHOWN`, `FOWNER`, `SETUID`, `SETGID`, `DAC_READ_SEARCH`), has a read-only root
  filesystem with a `tmpfs` `/tmp`, and (compose only) `no-new-privileges`
- The optional MCP endpoint (`/mcp`) accepts only the `LAB_MANAGER_MCP_TOKEN` bearer
  token and never returns stored credentials; see "MCP server for AI agents"

## Development

See [CLAUDE.md](CLAUDE.md) for detailed development documentation.

### Local Development (Without Docker)

Requires Go 1.27.4+.

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
