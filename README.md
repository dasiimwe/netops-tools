# Network Device Interface Manager

A Flask-based web application for managing network devices and collecting interface information. Supports multiple vendors including Cisco (IOS, NXOS, IOS-XR), Palo Alto Networks, and FortiGate devices.

## Features

- **Multi-vendor Support**: Cisco IOS/NXOS/IOS-XR, Palo Alto, FortiGate
- **Secure Credential Storage**: Device credentials encrypted in database
- **Dual Authentication**: Local users and TACACS+ support
- **Interface Collection**: Automated collection of interface configurations and IP addresses
- **Bulk Operations**: Collect from multiple devices simultaneously
- **Web Interface**: User-friendly dashboard for device management
- **Audit Logging**: Track all user actions and device access
- **Extensible Architecture**: Easy to add support for new vendors

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment (recommended)

### Setup Steps

1. Clone the repository:
```bash
cd /Users/dna/git-projects/netops-tools/netops-tools
```

2. Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Copy environment configuration:
```bash
cp .env.example .env
```

5. Edit `.env` and configure:
   - Generate encryption key: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
   - Add the key to `ENCRYPTION_KEY` in `.env`
   - Configure TACACS+ settings if needed

6. Initialize database:
```bash
python init_db.py
```

7. Run the application:
```bash
python run.py
```

The application will be available at http://localhost:5000

## Default Login

- Username: `admin`
- Password: `Admin@123`

**Important**: Change the default password after first login!

## Usage

### Adding Devices

1. Navigate to Devices → Add Device
2. Enter device information:
   - Hostname and IP address
   - Select vendor and device type
   - Provide SSH credentials
   - Optionally assign to a group

### Collecting Interface Data

- **Single Device**: Click the refresh icon next to a device
- **Bulk Collection**: Select multiple devices and click "Bulk Collect"

### Viewing Interfaces

- Go to Interfaces to see all collected interface data
- Filter by device, status, or IP version
- Export data as JSON for external processing

## Configuration

### Application Settings

Access Settings (admin only) to configure:
- Connection retry settings
- Timeout values
- Maximum concurrent connections
- TACACS+ authentication

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
- Support for external authentication via TACACS+

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

## License

This project is for internal use. All rights reserved.