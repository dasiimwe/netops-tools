# Bulk Device Import Feature

A comprehensive CSV-based bulk import system for adding multiple network devices to the Network Device Manager.

## Overview

The bulk import feature allows administrators to:
- Import multiple devices from a CSV file
- Automatically create device groups
- Set device credentials during import
- View detailed import results with error reporting
- Download a pre-formatted CSV template

## Features

### 📊 **CSV Template**
- Pre-formatted template with sample data
- Downloadable from the web interface
- Includes all supported fields with examples

### 🔍 **Validation & Error Handling**
- Required field validation
- Vendor validation against supported types
- Duplicate hostname detection
- Data format validation (IP addresses, ports, etc.)
- Detailed error reporting with row numbers

### 📈 **Progress Tracking**
- Real-time import progress
- Success/error count tracking
- Detailed results summary
- Individual error descriptions

### 🔐 **Security Features**
- Credential encryption during import
- Audit logging for all imports
- Authentication required for access

## Usage

### 1. **Access Bulk Import**
Navigate to: **Devices → Bulk Import** or visit `/devices/bulk-import`

### 2. **Download Template**
Click **"Download Template"** to get the CSV template with sample data.

### 3. **Prepare CSV File**
Edit the template with your device information following the format requirements.

### 4. **Upload and Import**
- Select your CSV file using the upload area
- Click **"Import Devices"** to process the file
- Review the import results

## CSV Format

### Required Fields
| Field | Description | Example |
|-------|-------------|---------|
| `hostname` | Device hostname | `fw01.company.com` |
| `ip_address` | Device IP address | `192.168.1.1` |
| `vendor` | Device vendor | `paloalto` |

### Optional Fields
| Field | Description | Default | Example |
|-------|-------------|---------|---------|
| `device_type` | Device type | `network_device` | `firewall` |
| `port` | SSH port | `22` | `2222` |
| `username` | Device username | - | `admin` |
| `password` | Device password | - | `Admin@123` |
| `group_name` | Device group | - | `Firewalls` |
| `description` | Device description | - | `Main office firewall` |

### Supported Vendors
- `cisco_ios` - Cisco IOS/IOS-XE devices
- `cisco_nxos` - Cisco Nexus devices
- `cisco_iosxr` - Cisco IOS-XR devices
- `paloalto` - Palo Alto Networks devices
- `fortigate` - FortiGate devices

## CSV Template Example

```csv
hostname,ip_address,vendor,device_type,port,username,password,group_name,description
fw01.company.com,192.168.1.1,paloalto,firewall,22,admin,Admin@123,Firewalls,Main office firewall
sw01.company.com,192.168.1.10,cisco_ios,switch,22,admin,Switch@123,Switches,Core switch - Building A
rtr01.company.com,192.168.1.20,cisco_ios,router,22,admin,Router@123,Routers,WAN edge router
fw02.branch.com,10.10.1.1,fortigate,firewall,22,admin,Forti@123,Firewalls,Branch office firewall
sw02.company.com,192.168.1.11,cisco_nxos,switch,22,admin,Switch@123,Switches,Distribution switch - Building B
rtr02.company.com,192.168.1.21,cisco_iosxr,router,22,admin,Router@123,Routers,Core router - MPLS
sw03.company.com,192.168.1.12,cisco_ios,switch,2222,netops,NetOps@123,Switches,Access switch - Floor 3
```

## Import Process

### 1. **File Upload**
- Drag & drop CSV file onto upload area
- Or click to browse and select file
- File validation occurs before upload

### 2. **Processing**
- CSV parsing and validation
- Duplicate hostname checking
- Device group creation (if needed)
- Credential encryption
- Database insertion

### 3. **Results Display**
- Import summary with statistics
- List of successfully imported devices
- Detailed error report for failed imports
- Options to retry or return to device list

## Import Results

### Success Summary
- Total devices processed
- Success count and percentage
- Error count and details
- Processing time

### Successful Imports Table
| Column | Description |
|--------|-------------|
| Hostname | Device hostname |
| IP Address | Device IP address |
| Vendor | Device vendor type |
| Group | Assigned device group |

### Error Report Table
| Column | Description |
|--------|-------------|
| Row | CSV row number |
| Hostname | Device hostname (if available) |
| Error | Detailed error description |

## Error Types

### Common Import Errors
- **Missing Required Fields**: Hostname, IP address, or vendor not provided
- **Invalid Vendor**: Vendor not in supported list
- **Duplicate Hostname**: Device with same hostname already exists
- **Invalid Data Format**: Port number not numeric, invalid IP format
- **File Processing Error**: CSV format issues, encoding problems

### Error Resolution
1. **Download Error Report**: Review specific error descriptions
2. **Fix CSV File**: Correct the identified issues
3. **Re-import**: Upload the corrected CSV file
4. **Partial Success**: Successfully imported devices remain in system

## API Endpoints

### Bulk Import Page
```
GET /devices/bulk-import
POST /devices/bulk-import
```

### Template Download
```
GET /devices/bulk-import/template
```

## Security Considerations

### Data Protection
- Device credentials encrypted using application encryption key
- CSV files processed in memory (not stored on server)
- Audit logging for all import activities

### Access Control
- Authentication required for all import operations
- Import activities logged with user identification
- Admin-level permissions recommended

### Best Practices
- Use strong passwords in CSV files
- Secure CSV files during transport and storage
- Regularly rotate device credentials after import
- Review import logs for unauthorized access

## Integration with Existing Features

### Device Groups
- Auto-creates groups specified in CSV
- Links devices to existing groups
- Maintains group hierarchy

### Credential Management
- Integrates with encrypted credential storage
- Uses application encryption key
- Supports individual device credentials

### Audit Logging
- Records all import activities
- Tracks user, timestamp, and device details
- Integrates with existing audit system

### Session Logging
- Device connection attempts logged
- Integration with session logging system
- Troubleshooting support for imported devices

## Performance Considerations

### File Size Limits
- Recommended: < 1000 devices per import
- Memory usage scales with file size
- Processing time depends on validation complexity

### Database Performance
- Bulk operations use database transactions
- Rollback on critical errors
- Commit successful imports even with partial failures

### Network Impact
- No network connectivity required during import
- Device validation occurs during interface collection
- Import process is database-only operation

## Troubleshooting

### Common Issues

**Template Download Fails**
- Check file permissions in application directory
- Verify web server file serving configuration

**Import Hangs or Times Out**
- Reduce CSV file size
- Check database connectivity
- Review application logs for errors

**All Imports Fail**
- Verify CSV format matches template
- Check file encoding (UTF-8 recommended)
- Validate required fields are present

**Partial Import Success**
- Review error report for specific issues
- Fix CSV file and re-import failed devices
- Successful imports are retained

### Log Locations
- Application logs: `logs/app.log`
- Import activities: Audit logs in database
- Session logs: Session logs table

## Advanced Usage

### Custom Templates
Create custom CSV templates for specific environments:
```python
# Generate template programmatically
from app.routes.device_routes import download_template
```

### Batch Processing
For large deployments:
1. Split large CSV files into smaller batches
2. Import during maintenance windows
3. Validate imports before production use

### Integration Scripts
```bash
# Download template via CLI
curl -O http://your-server/devices/bulk-import/template

# Automated import validation
python validate_csv.py devices.csv
```

## Future Enhancements

### Planned Features
- Excel file support (.xlsx)
- Import scheduling
- Progress indicators during upload
- Email notifications for large imports
- Import history and rollback capabilities

### API Extensions
- RESTful API for programmatic imports
- Webhook notifications for import completion
- Integration with external device discovery tools