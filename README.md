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

### Application Settings

Access Settings (admin only) to configure:
- Connection retry settings
- Timeout values
- Maximum concurrent connections
- TACACS+ authentication (server, port, timeout, shared secret)

### Adding New Vendors

To add support for a new vendor:

1. Create connector in `app/device_connectors/vendor_name.py`
2. Inherit from `BaseConnector` class
3. Implement required methods:
   - `get_netmiko_device_type()`
   - `get_interface_commands()`
   - `parse_interfaces()`
4. Register in `app/device_connectors/__init__.py`

## Security Notes

- All device credentials are encrypted before storage
- Session cookies are HTTP-only and secure (in production)
- Audit logging tracks all device access
- Support for external authentication via TACACS+ (configured through web interface)
- IP translator available publicly (no authentication required)
- Admin functions require login and proper permissions

## Production Deployment

For production deployment:

1. Set `FLASK_ENV=production` in `.env`
2. Use a production WSGI server:
```bash
gunicorn -w 4 -b 0.0.0.0:5000 run:app
```
3. Configure HTTPS/TLS
4. Use a production database (PostgreSQL recommended)
5. Set strong `SECRET_KEY` and `ENCRYPTION_KEY`

## Troubleshooting

### Device Connection Issues

- Verify SSH access to device
- Check credentials have sufficient privileges
- Review timeout settings if connections are slow
- Check audit logs for error details

### Database Issues

- Ensure write permissions for SQLite database
- For production, migrate to PostgreSQL or MySQL

### TACACS+ Configuration

- TACACS+ settings are now configured through the web interface (Settings page)
- Environment variables for TACACS+ are deprecated but can still be used for initial setup
- Use the "Test Connection" button to verify TACACS+ server connectivity

### IP Translator Issues

- If IP addresses are not being translated, verify device interfaces are collected and stored
- Interface names are automatically shortened (e.g., GigabitEthernet1/0/1 → gi1/0/1)
- Tooltips require JavaScript to be enabled

## License

This project is for internal use. All rights reserved.