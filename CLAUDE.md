# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Network Device Interface Manager - A Flask-based web application for managing network devices and collecting interface information. Supports Cisco (IOS, NXOS, IOS-XR), Palo Alto, and FortiGate devices with extensible architecture for adding more vendors.

## Common Development Commands

### Setup and Dependencies
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python init_db.py

# Run database migrations
flask db upgrade
```

### Running the Application
```bash
# Development mode
flask run --debug

# Production mode with gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Testing
```bash
# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_device_connection.py

# Run with coverage
pytest --cov=app tests/
```

### Code Quality
```bash
# Python linting
pylint app/
flake8 app/
black app/ --check

# Format Python code
black app/
```

## Architecture

### Project Structure
```
netops-tools/
├── app/
│   ├── __init__.py           # Flask app initialization
│   ├── models.py             # SQLAlchemy database models
│   ├── auth/                 # Authentication module
│   │   ├── local_auth.py     # Local authentication
│   │   └── tacacs_auth.py    # TACACS+ authentication
│   ├── device_connectors/    # Device connection modules
│   │   ├── base_connector.py # Abstract base connector
│   │   ├── cisco_ios.py      # Cisco IOS/IOS-XE
│   │   ├── cisco_nxos.py     # Cisco NXOS
│   │   ├── cisco_iosxr.py    # Cisco IOS-XR
│   │   ├── paloalto.py       # Palo Alto Networks
│   │   └── fortigate.py      # FortiGate
│   ├── parsers/              # Output parsers for each vendor
│   ├── routes/               # Flask route blueprints
│   ├── templates/            # Jinja2 HTML templates
│   └── static/               # CSS, JS, images
├── migrations/               # Database migrations
├── tests/                    # Test files
├── config.py                 # Application configuration
├── requirements.txt          # Python dependencies
└── run.py                    # Application entry point
```

### Database Schema

Key tables:
- **users**: User authentication (local and TACACS)
- **devices**: Network devices with encrypted credentials
- **interfaces**: Interface details with IP addresses
- **device_groups**: Optional device grouping
- **settings**: Application settings (retry logic, timeouts)

### Key Design Patterns

1. **Vendor Abstraction**: Base connector class with vendor-specific implementations
2. **Parser Strategy**: Separate parsing logic for each vendor's command output
3. **Credential Encryption**: Use cryptography.fernet for database credential storage
4. **Connection Pooling**: Reuse SSH connections when collecting from multiple devices
5. **Async Operations**: Use Celery for bulk device operations

### Authentication Flow

1. **Local Auth**: Flask-Login with bcrypt password hashing
2. **TACACS+ Auth**: tacacs-plus library for external authentication
3. **Session Management**: Redis for session storage in production

### Device Connection Flow

1. Decrypt device credentials from database
2. Establish netmiko connection with vendor-specific driver
3. Execute commands (show interfaces, show ip interface brief)
4. Parse output based on vendor type
5. Store only interfaces with IPv4/IPv6 addresses
6. Update device reachability status

### Extending for New Vendors

To add a new vendor (e.g., Arista, Juniper):
1. Create new connector in `app/device_connectors/`
2. Inherit from `BaseConnector` class
3. Implement `connect()`, `get_interfaces()` methods
4. Create parser in `app/parsers/`
5. Register in `VENDOR_MAPPING` dictionary

### Security Best Practices

1. All device credentials encrypted with app-specific key
2. CSRF protection on all forms
3. SQL injection prevention via SQLAlchemy ORM
4. Rate limiting on authentication endpoints
5. Audit logging for all device access
6. TLS/HTTPS in production

### Error Handling

1. Device unreachable: Mark in database, display in UI
2. Authentication failure: Log attempt, notify user
3. Parser errors: Fallback to raw output storage
4. Connection timeouts: Configurable retry with exponential backoff