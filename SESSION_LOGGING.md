# Session Logging for Network Device Debugging

This document describes the session logging feature implemented to debug netmiko connections and interface collection operations.

## Overview

Session logging captures detailed information about every interaction with network devices, including:
- Connection attempts and results
- Commands sent to devices
- Command responses received
- Timing information
- Error details
- Session lifecycle events

## Event Types

The following event types are logged:

| Event Type | Description |
|------------|-------------|
| `interface_collection_start` | Beginning of interface collection process |
| `connection_start` | Starting SSH connection attempt |
| `connection_success` | Successful SSH connection established |
| `connection_failed` | SSH connection failed |
| `interface_commands_planned` | List of commands to be executed |
| `command_sent` | Command sent to device |
| `command_response` | Response received from device |
| `command_failed` | Command execution failed |
| `interface_collection_success` | Interface collection completed successfully |
| `interface_collection_failed` | Interface collection failed |
| `disconnection` | SSH connection closed |

## Database Schema

Session logs are stored in the `session_logs` table:

```sql
CREATE TABLE session_logs (
    id INTEGER PRIMARY KEY,
    session_id VARCHAR(36) NOT NULL,  -- UUID grouping session events
    device_id INTEGER REFERENCES devices(id),
    user_id INTEGER REFERENCES users(id),
    event_type VARCHAR(50) NOT NULL,
    command TEXT,              -- Command sent (for command events)
    response TEXT,             -- Response received (for response events)
    error_message TEXT,        -- Error details (for failed events)
    duration_ms INTEGER,       -- Duration in milliseconds
    timestamp DATETIME NOT NULL
);
```

## Usage

### Enabling Session Logging

Session logging is enabled by default when creating device connectors with device and user IDs:

```python
from app.device_connectors.paloalto import PaloAltoConnector

# Create connector with session logging enabled
connector = PaloAltoConnector(
    host='192.168.1.1',
    username='admin',
    password='password',
    device_id=1,          # Required for logging
    user_id=1,           # Required for logging
    enable_session_logging=True  # Default: True
)

# Collect interfaces (this generates session logs)
interfaces = connector.get_interfaces()
```

### Disabling Session Logging

```python
# Disable session logging for performance-critical operations
connector = PaloAltoConnector(
    host='192.168.1.1',
    username='admin',
    password='password',
    enable_session_logging=False
)
```

### Viewing Session Logs

#### Using the Command Line Tool

```bash
# View latest 50 log entries
python view_session_logs.py

# List recent session IDs
python view_session_logs.py --list

# View specific session
python view_session_logs.py <session-id>
```

#### Using Python API

```python
from app.models import SessionLog

# Get logs for specific session
logs = SessionLog.query.filter_by(session_id='uuid-here').all()

# Get recent logs for a device
logs = SessionLog.query.filter_by(device_id=1).order_by(
    SessionLog.timestamp.desc()
).limit(10).all()

# Get failed connection attempts
failed_logs = SessionLog.query.filter_by(
    event_type='connection_failed'
).all()
```

## Example Session Log Output

```
================================================================================
Session: 06787c15-dded-47cd-a9d5-91f4d8f7687d
Device: fw01.company.com | User: netops
================================================================================

[21:34:53.170] INTERFACE_COLLECTION_START

[21:34:53.171] CONNECTION_START

[21:34:53.171] CONNECTION_SUCCESS
  Duration: 1ms

[21:34:53.171] INTERFACE_COMMANDS_PLANNED
  Command: Commands to execute: show interface all, show interface logical

[21:34:53.172] COMMAND_SENT
  Command: show interface all

[21:34:53.172] COMMAND_RESPONSE
  Command: show interface all
  Response:
    name: ethernet1/1
    comment: WAN Interface to ISP
    ip address: 192.168.100.1/24
    ... (10 more lines)
  Duration: 1ms

[21:34:53.173] COMMAND_SENT
  Command: show interface logical

[21:34:53.173] COMMAND_RESPONSE
  Command: show interface logical
  Response:
    vlan.100    100    vsys1    DMZ        VLAN        100    10.10.100.1/24
    vlan.200    200    vsys1    INSIDE     VLAN        200    192.168.200.1/24
    ... (1 more lines)
  Duration: 1ms

[21:34:53.174] INTERFACE_COLLECTION_SUCCESS
  Response: Found 5 interfaces with IP addresses: ethernet1/1, ethernet1/2, vlan.100, vlan.200, vlan.300
  Duration: 4ms

[21:34:53.174] DISCONNECTION
```

## Troubleshooting with Session Logs

### Debug Connection Issues

```python
# Find failed connections for a device
failed_connections = SessionLog.query.filter_by(
    device_id=device_id,
    event_type='connection_failed'
).order_by(SessionLog.timestamp.desc()).all()

for log in failed_connections:
    print(f"Failed at {log.timestamp}: {log.error_message}")
```

### Analyze Command Performance

```python
# Find slow commands
slow_commands = SessionLog.query.filter(
    SessionLog.event_type == 'command_response',
    SessionLog.duration_ms > 5000  # Over 5 seconds
).all()
```

### Track Authentication Issues

```python
# Find authentication failures
auth_failures = SessionLog.query.filter(
    SessionLog.error_message.like('%Authentication%')
).all()
```

## Performance Considerations

- Session logging adds minimal overhead (typically <1ms per event)
- Large command outputs are stored in full - consider truncation for very large responses
- Logs should be periodically cleaned up to prevent database growth
- Disable logging for high-frequency automated operations if needed

## Security Notes

- Command responses may contain sensitive device configuration data
- Access to session logs should be restricted to authorized personnel
- Consider implementing log retention policies
- Device credentials are never logged (only connection success/failure)

## Integration with Flask Routes

When using in Flask routes, ensure proper database context:

```python
from flask import current_app
from app.models import Device, User

@device_bp.route('/collect/<int:device_id>')
@login_required
def collect_interfaces(device_id):
    device = Device.query.get_or_404(device_id)

    # Get device credentials
    username, password = device.get_credentials(current_app.config['ENCRYPTION_KEY'])

    # Create connector with session logging
    connector = get_connector(
        device.vendor,
        device.ip_address,
        username,
        password,
        device_id=device.id,
        user_id=current_user.id,
        enable_session_logging=True
    )

    # This will generate session logs
    interfaces = connector.get_interfaces()

    return jsonify({'interfaces': interfaces})
```