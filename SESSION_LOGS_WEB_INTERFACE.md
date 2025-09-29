# Session Logs Web Interface

A comprehensive web interface for browsing and analyzing session logs from network device interactions.

## Features

### 📊 Main Session Logs Page (`/session-logs/`)

**Filtering Options:**
- **Session ID**: Filter by specific session identifier
- **Device**: Filter by specific network device
- **User**: Filter by user who initiated the session
- **Event Type**: Filter by event types (connection_start, command_sent, etc.)
- **Time Period**: Last hour, 6 hours, 24 hours, week, or month
- **Search**: Full-text search across commands, responses, and error messages
- **Per Page**: Adjust number of results per page (25, 50, 100)

**Features:**
- Real-time auto-refresh (every 30 seconds when no filters are active)
- Color-coded event types for easy identification
- Pagination for large result sets
- Quick session ID links to detailed view

### 🔍 Session Detail View (`/session-logs/session/<session_id>`)

**Session Summary:**
- Device and user information
- Total events and session duration
- Error count and start time
- Visual event type breakdown

**Timeline View:**
- Chronological display of all session events
- Color-coded event markers
- Expandable command responses
- Duration tracking for each event
- Export functionality (JSON format)

### 📈 Statistics Dashboard

**Real-time Statistics:**
- Total events in selected time period
- Number of unique sessions
- Error event count
- Average command execution time
- Events breakdown by type

### 🛠 Admin Features

**Log Cleanup:**
- Delete logs older than specified days
- Confirmation dialogs for safety
- Bulk deletion with progress feedback

## Navigation

The Session Logs page is accessible through:
1. **Sidebar Navigation**: Click "Session Logs" in the admin section
2. **Direct URL**: `/session-logs/`
3. **From other pages**: Look for session log links in device management pages

## Event Types and Colors

| Event Type | Color | Description |
|------------|-------|-------------|
| **Connection Start** | Blue | Beginning of SSH connection attempt |
| **Connection Success** | Green | Successful SSH connection established |
| **Connection Failed** | Red | SSH connection failed |
| **Command Sent** | Purple | Command sent to device |
| **Command Response** | Teal | Response received from device |
| **Command Failed** | Red | Command execution failed |
| **Interface Collection Start** | Blue | Beginning of interface collection |
| **Interface Collection Success** | Green | Interface collection completed |
| **Interface Collection Failed** | Red | Interface collection failed |
| **Disconnection** | Gray | SSH connection closed |

## Usage Examples

### 🔍 Debugging Connection Issues

1. Go to `/session-logs/`
2. Set **Event Type** to "Connection Failed"
3. Select recent **Time Period** (e.g., "Last 24 Hours")
4. Review error messages to identify patterns

### 📊 Performance Analysis

1. Click **Statistics** button on main page
2. Review "Average Command Time" metric
3. Filter by specific devices to compare performance
4. Use **Search** to find slow commands (e.g., search for high duration)

### 🔎 Troubleshooting Specific Device

1. Select target device from **Device** dropdown
2. Set appropriate time period
3. Review session timeline for patterns
4. Click session ID links for detailed analysis

### 🕵️ Auditing User Activity

1. Select user from **User** dropdown
2. Set time period for audit scope
3. Review all sessions initiated by that user
4. Export specific sessions for compliance records

## API Endpoints

### Sessions API
```
GET /session-logs/api/sessions?hours_back=24
```
Returns recent session summaries with metadata.

### Statistics API
```
GET /session-logs/api/stats?hours_back=24
```
Returns aggregated statistics for the specified time period.

## Security Considerations

- **Authentication Required**: All session log pages require user login
- **Admin Features**: Log cleanup is restricted to admin users only
- **Data Sensitivity**: Session logs contain device interaction data - access should be restricted appropriately
- **Data Retention**: Regular cleanup of old logs is recommended for security and performance

## Performance Tips

- Use specific filters to reduce result sets
- Utilize pagination for large datasets
- Consider regular log cleanup for optimal performance
- Use the search feature for targeted troubleshooting

## Integration with Device Operations

When device connectors are configured with session logging enabled:

```python
# Session logging is automatically enabled when device_id and user_id are provided
connector = PaloAltoConnector(
    host='device.example.com',
    username='admin',
    password='password',
    device_id=device.id,        # Links to device record
    user_id=current_user.id,    # Links to user record
    enable_session_logging=True # Enables detailed logging
)

# All subsequent operations will be logged
interfaces = connector.get_interfaces()
```

The web interface will then display these logged sessions for review and analysis.

## Mobile Responsiveness

The interface is fully responsive and works on:
- Desktop browsers
- Tablets
- Mobile phones
- Touch-enabled devices

All features are accessible across device types with appropriate layout adjustments.