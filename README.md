# Netops Toolkit

Network device management and IP translation tool supporting Cisco, Palo Alto, and FortiGate devices.

## Key Features

- **IP Address Translator**: Translates IP addresses in text to show hostname and interface info (no login required)
- **Device Management**: Add and manage network devices with encrypted credential storage
- **Interface Collection**: Automated collection from multiple vendors
- **TACACS+ Authentication**: Configurable through web interface

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

### Device Management
- Add devices: Devices → Add Device
- Collect interfaces: Click refresh icon or bulk collect
- View data: Interfaces page with filtering and export

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