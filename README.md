# Netops Toolkit

Comprehensive network operations toolkit with device management, IP translation, and network diagnostics supporting Cisco, Palo Alto, and FortiGate devices.

## Key Features

- **IP Address Translator**: Translates IP addresses in text to show hostname and interface info (no login required)
- **Command Run Tool**: Execute commands on multiple devices simultaneously with bulk processing
- **DNS Lookup Tool**: Bulk DNS resolution with custom DNS servers and configurable save/load functionality
- **Traceroute Tool**: Real-time parallel traceroutes with hop-by-hop display and IP translation
- **Device Management**: Add and manage network devices with encrypted credential storage
- **Interface Collection**: Automated collection from multiple vendors with CSV import/export
- **TACACS+ Authentication**: Configurable through web interface
- **Session Logging**: Comprehensive logging of device interactions with web-based log viewer

## Quick Start

```bash
# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Configure encryption key in .env
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Initialize and run
python init_db.py
python run.py
```

Access at http://localhost:5000

## Usage

**Default Login:** `admin` / `Admin@123` (change after first login)

### IP Address Translator
- Home page (no login required)
- Paste text with IP addresses
- Get format: `IP(hostname-interface)` with hover tooltips
- Example: `192.168.1.1` → `192.168.1.1(router1-gi1/0/1)`

### Command Run Tool
- Execute commands on multiple devices simultaneously
- Save/load device lists and command sets for reuse
- Real-time output display with copy functionality
- Bulk operations with parallel processing

### DNS Lookup Tool
- Bulk DNS resolution (A, PTR, MX, NS, TXT records)
- Custom DNS server configuration
- Save/load DNS server lists
- Single-line simplified output for A and PTR records

### Traceroute Tool
- Real-time parallel traceroutes to multiple targets
- Hop-by-hop display in separate containers per target
- IP address translation integration
- Configurable timeout, probes per hop, and packet size
- Copy results functionality

### Device Management
- Add devices: Devices → Add Device
- Collect interfaces: Click refresh icon or bulk collect
- CSV import/export for bulk device and interface management
- View data: Interfaces page with filtering and export

### Session Logging
- Comprehensive logging of all device interactions
- Web-based session log viewer with filtering
- Track connection attempts, command execution, and timing

## Configuration

**Settings (Admin):**
- Connection timeouts and retry settings
- TACACS+ authentication (server, port, secret)

**Supported Vendors:**
- Cisco IOS/NXOS/IOS-XR
- Palo Alto Networks
- FortiGate

## Production

```bash
# Production deployment
gunicorn -w 4 -b 0.0.0.0:5000 run:app
```

Set strong `SECRET_KEY` and `ENCRYPTION_KEY` in production environment.