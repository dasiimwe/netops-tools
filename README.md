# netops Toolkit

Comprehensive network operations toolkit with device management, IP translation, BGP looking glass, and network diagnostics supporting Cisco, Palo Alto, and FortiGate devices.

## Key Features

- **IP Address Translator**: Translates IP addresses in text to show hostname and interface info (no login required)
- **BGP Looking Glass**: Real-time BGP route and routing table lookups with streaming output and IP translation
- **Command Run Tool**: Execute commands on multiple devices simultaneously with bulk processing
- **DNS Lookup Tool**: Bulk DNS resolution with custom DNS servers and configurable save/load functionality
- **Traceroute Tool**: Real-time parallel traceroutes with hop-by-hop display and IP translation
- **TCP Handshake Visualizer**: View 3-way handshake packet capture and analysis
- **URL/App Insights**: Browser-based URL diagnostics and connectivity testing
- **WhoAmI Tool**: Display user's IP address and connection information
- **Device Management**: Add and manage network devices with encrypted credential storage
- **Interface Collection**: Automated collection from multiple vendors with CSV import/export
- **Credential Pools**: Flexible credential management with pools and device assignments
- **TACACS+ Authentication**: Configurable through web interface
- **Session Logging**: Comprehensive logging of device interactions with web-based log viewer

## Quick Start

```bash
# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Initialize database
python init_db.py

# Run application
python run.py
```

### First-Time Setup

When you first run the application, you'll be automatically redirected to the **Setup Wizard** at `http://localhost:5000/setup` which will:

1. **Generate Environment Configuration** - Automatically creates `.env` file with secure encryption keys
2. **Create Admin User** - Set up your administrator account with strong password requirements
3. **Complete Setup** - Ready to start managing network devices

**Manual Setup Alternative:**
```bash
# If you prefer manual setup
cp .env.example .env
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Add the generated key to ENCRYPTION_KEY in .env
```

Access at http://localhost:5000

## Usage

**Default Login:** `admin` / `Admin@123` (change after first login)

### IP Address Translator
- Home page (no login required)
- Paste text with IP addresses
- Get format: `IP(hostname-interface)` with hover tooltips
- Example: `192.168.1.1` → `192.168.1.1(router1-gi1/0/1)`
- Supports both light and dark theme tooltips

### BGP Looking Glass
- Real-time BGP route and routing table lookups
- **Streaming output** - See results as each device responds
- **Multi-device support** - Query multiple devices simultaneously with checkbox selection
- **4-column device layout** - Organized alphabetically with smart grouping
- **IP translation** - Automatically translate IPs in output (toggle on/off)
- **Copy to clipboard** - One-click copy of all results
- **Vendor support**:
  - Cisco (IOS/NXOS/IOS-XR): `show ip route`, `show ip bgp`
  - Palo Alto: `show routing route destination`, `show routing protocol bgp loc-rib prefix`
  - FortiGate: `get router info routing-table details`, `get router info bgp network`
- Configure available devices in Settings → BGP Looking Glass tab

### Command Run Tool
- Execute commands on multiple devices simultaneously
- Save/load device lists and command sets for reuse
- Real-time output display with copy functionality
- Bulk operations with parallel processing
- Command validation with configurable rules

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

### TCP Handshake Visualizer
- Capture and display TCP 3-way handshake packets
- Visual representation of SYN, SYN-ACK, ACK packets
- Configurable interface and packet count

### Device Management
- Add devices: Devices → Add Device
- Collect interfaces: Click refresh icon or bulk collect
- CSV import/export for bulk device and interface management
- View data: Interfaces page with filtering and export
- Support for credential pools with priority ordering
- Device-specific credential assignments

### Session Logging
- Comprehensive logging of all device interactions
- Web-based session log viewer with filtering
- Track connection attempts, command execution, and timing

## Configuration

**Settings (Admin):**

### Connection Settings
- Connection and command timeouts
- Retry logic (enabled, count, delay)
- Max concurrent connections for bulk operations

### User Interface Settings
- Interface collection progress display
- IP Translator tooltip theme (light/dark)
- Tool visibility toggles (show/hide individual tools)
- Device connector dropdown visibility

### Security Settings
- Password complexity requirements (length, uppercase, lowercase, numbers, special characters)
- TACACS+ authentication (server, port, secret, timeout)
- Session management

### Credentials Management
- Default credential pool selection
- Credential pools with priority ordering
- Device-specific credential assignments

### Command Rules
- Safe command prefixes (allow list)
- Dangerous command patterns (block list)
- Standalone allowed commands
- Export/import rule configurations
- Test command validation

### BGP Looking Glass
- Device selection with search functionality
- Alphabetically ordered device list
- Configure which devices are available for BGP lookups

**Supported Vendors:**
- Cisco IOS/NXOS/IOS-XR
- Palo Alto Networks (PAN-OS)
- FortiGate (FortiOS)

## Recent Features & Improvements

### BGP Looking Glass Enhancements
- **Real-time streaming output** - Results appear as devices respond, no waiting for all devices
- **Checkbox device selection** - 4-column grid layout with alphabetical sorting and smart grouping
- **IP translation integration** - Toggle IP translation on/off for command output
- **Copy to clipboard** - One-click copy functionality with visual feedback
- **Vendor-specific commands** - Properly formatted commands for each vendor type
- **CIDR handling** - Automatically strips CIDR notation for Cisco route lookups

### Settings Organization
- **Dedicated BGP Looking Glass tab** - Configure available devices with search functionality
- **Improved device search** - Real-time filtering by hostname, IP, or vendor
- **Device counter** - Shows number of selected devices in settings

### API & Backend Improvements
- **Field name consistency** - Fixed Device model field references (`hostname` and `vendor`)
- **Streaming responses** - Server-Sent Events (SSE) for real-time updates
- **Application context handling** - Proper Flask context management for streaming
- **Error handling** - Graceful error messages and fallbacks

### UI/UX Enhancements
- **Select All/Deselect All** buttons for device selection
- **Hover tooltips** on device names showing full info
- **Visual feedback** on copy operations
- **Auto-scrolling** results during streaming output
- **Bootstrap icons** integration throughout the interface

## Production

```bash
# Production deployment
gunicorn -w 4 -b 0.0.0.0:5000 run:app
```

Set strong `SECRET_KEY` and `ENCRYPTION_KEY` in production environment.

## Architecture

### Database Models
- **Users** - Local and TACACS+ authentication
- **Devices** - Network device inventory with vendor info
- **Interfaces** - Interface details with IP addresses
- **Credentials & Pools** - Flexible credential management
- **Settings** - Application configuration
- **BGPLookingGlassDevice** - BGP tool device associations
- **SessionLog** - Detailed interaction logging
- **AuditLog** - User action auditing

### Key Technologies
- **Backend**: Flask, SQLAlchemy, Flask-Login
- **Database**: SQLite (development), PostgreSQL/MySQL (production)
- **Device Connectivity**: Netmiko, Paramiko
- **Frontend**: Vanilla JavaScript, Bootstrap Icons
- **Security**: Fernet encryption, bcrypt password hashing
