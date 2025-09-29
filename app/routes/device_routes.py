from flask import render_template, redirect, url_for, flash, request, jsonify, send_file, current_app
from flask_login import login_required, current_user
from app.routes import device_bp
from app.models import db, Device, DeviceGroup, Interface, AuditLog
from app.device_connectors import get_connector
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import csv
import io
import os
from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)

@device_bp.route('/')
@login_required
def list_devices():
    devices = Device.query.all()
    groups = DeviceGroup.query.all()
    return render_template('devices/list.html', devices=devices, groups=groups)

@device_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_device():
    if request.method == 'POST':
        hostname = request.form.get('hostname')
        ip_address = request.form.get('ip_address')
        vendor = request.form.get('vendor')
        
        # Check if device already exists
        existing = Device.query.filter_by(hostname=hostname).first()
        if existing:
            flash(f'Device {hostname} already exists', 'danger')
        else:
            device = Device(
                hostname=hostname,
                ip_address=ip_address,
                vendor=vendor
            )
            
            db.session.add(device)
            db.session.commit()
            
            # Log device addition
            audit_log = AuditLog(
                user_id=current_user.id,
                device_id=device.id,
                action='device_added',
                details=f'Added device: {hostname}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()
            
            flash(f'Device {hostname} added successfully', 'success')
            return redirect(url_for('devices.list_devices'))
    
    return render_template('devices/add.html')

@device_bp.route('/<int:device_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_device(device_id):
    device = Device.query.get_or_404(device_id)
    
    if request.method == 'POST':
        device.hostname = request.form.get('hostname')
        device.ip_address = request.form.get('ip_address')
        device.vendor = request.form.get('vendor')
        
        device.updated_at = datetime.utcnow()
        db.session.commit()
        
        flash(f'Device {device.hostname} updated successfully', 'success')
        return redirect(url_for('devices.list_devices'))
    
    return render_template('devices/edit.html', device=device)

@device_bp.route('/<int:device_id>/delete', methods=['POST'])
@login_required
def delete_device(device_id):
    device = Device.query.get_or_404(device_id)
    hostname = device.hostname
    
    # Log device deletion
    audit_log = AuditLog(
        user_id=current_user.id,
        action='device_deleted',
        details=f'Deleted device: {hostname}',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    
    db.session.delete(device)
    db.session.commit()
    
    flash(f'Device {hostname} deleted successfully', 'success')
    return redirect(url_for('devices.list_devices'))

@device_bp.route('/<int:device_id>/collect', methods=['POST'])
@login_required
def collect_interfaces(device_id):
    device = Device.query.get_or_404(device_id)
    
    # Get default credential
    from app.models import Credential
    default_credential = Credential.get_default()
    
    if not default_credential:
        flash('No default credential configured. Please add and set a default credential first.', 'warning')
        return redirect(url_for('devices.list_devices'))
    try:
        from flask import current_app
        
        # Get decrypted credentials from default credential
        username, password = default_credential.get_credentials(current_app.config['ENCRYPTION_KEY'])
        
        # Get connector for device
        connector = get_connector(
            vendor=device.vendor,
            host=device.ip_address,
            username=username,
            password=password,
            port=22,  # Default SSH port
            timeout=current_app.config['DEVICE_CONNECTION_TIMEOUT'],
            retry_enabled=current_app.config['DEVICE_RETRY_ENABLED'],
            retry_count=current_app.config['DEVICE_RETRY_COUNT'],
            retry_delay=current_app.config['DEVICE_RETRY_DELAY']
        )
        
        # Collect interface data
        interfaces_data = connector.get_interfaces()

        # Update database using upsert strategy
        _upsert_interfaces(device.id, interfaces_data)
        
        # Update device status
        device.is_reachable = True
        device.last_successful_connection = datetime.utcnow()
        device.last_reachability_check = datetime.utcnow()
        device.last_error = None
        
        # Log collection
        audit_log = AuditLog(
            user_id=current_user.id,
            device_id=device.id,
            action='interface_collection',
            details=f'Collected {len(interfaces_data)} interfaces from {device.hostname}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        
        db.session.commit()
        
        flash(f'Successfully collected {len(interfaces_data)} interfaces from {device.hostname}', 'success')
        
    except Exception as e:
        logger.error(f'Error collecting interfaces from {device.hostname}: {str(e)}')
        
        # Update device status
        device.is_reachable = False
        device.last_reachability_check = datetime.utcnow()
        device.last_error = str(e)
        db.session.commit()
        
        flash(f'Error collecting interfaces from {device.hostname}: {str(e)}', 'danger')
    
    return redirect(url_for('devices.list_devices'))

@device_bp.route('/bulk_collect', methods=['POST'])
@login_required
def bulk_collect():
    device_ids = request.form.getlist('device_ids[]')
    
    if not device_ids:
        flash('No devices selected', 'warning')
        return redirect(url_for('devices.list_devices'))
    
    # Get default credential
    from app.models import Credential
    default_credential = Credential.get_default()
    
    if not default_credential:
        flash('No default credential configured. Please add and set a default credential first.', 'warning')
        return redirect(url_for('devices.list_devices'))
    
    from flask import current_app
    max_workers = current_app.config['MAX_CONCURRENT_CONNECTIONS']
    
    success_count = 0
    error_count = 0
    
    def collect_from_device(device):
        try:
            username, password = default_credential.get_credentials(current_app.config['ENCRYPTION_KEY'])
            
            connector = get_connector(
                vendor=device.vendor,
                host=device.ip_address,
                username=username,
                password=password,
                port=22,  # Default SSH port
                timeout=current_app.config['DEVICE_CONNECTION_TIMEOUT'],
                retry_enabled=current_app.config['DEVICE_RETRY_ENABLED'],
                retry_count=current_app.config['DEVICE_RETRY_COUNT'],
                retry_delay=current_app.config['DEVICE_RETRY_DELAY']
            )
            
            interfaces_data = connector.get_interfaces()

            # Update database using upsert strategy
            _upsert_interfaces(device.id, interfaces_data)
            
            device.is_reachable = True
            device.last_successful_connection = datetime.utcnow()
            device.last_reachability_check = datetime.utcnow()
            device.last_error = None
            
            return True, device.hostname, len(interfaces_data)
            
        except Exception as e:
            device.is_reachable = False
            device.last_reachability_check = datetime.utcnow()
            device.last_error = str(e)
            return False, device.hostname, str(e)
    
    # Execute collections in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for device_id in device_ids:
            device = Device.query.get(device_id)
            if device:
                future = executor.submit(collect_from_device, device)
                futures.append(future)
        
        for future in as_completed(futures):
            success, hostname, result = future.result()
            if success:
                success_count += 1
                logger.info(f'Collected {result} interfaces from {hostname}')
            else:
                error_count += 1
                logger.error(f'Failed to collect from {hostname}: {result}')
    
    # Commit all database changes
    db.session.commit()
    
    # Log bulk collection
    audit_log = AuditLog(
        user_id=current_user.id,
        action='bulk_interface_collection',
        details=f'Bulk collection: {success_count} successful, {error_count} failed',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()
    
    flash(f'Bulk collection complete: {success_count} successful, {error_count} failed', 'info')
    return redirect(url_for('devices.list_devices'))

@device_bp.route('/groups')
@login_required
def list_groups():
    groups = DeviceGroup.query.all()
    return render_template('devices/groups.html', groups=groups)

@device_bp.route('/groups/add', methods=['POST'])
@login_required
def add_group():
    name = request.form.get('name')
    description = request.form.get('description')
    
    existing = DeviceGroup.query.filter_by(name=name).first()
    if existing:
        flash(f'Group {name} already exists', 'danger')
    else:
        group = DeviceGroup(name=name, description=description)
        db.session.add(group)
        db.session.commit()
        flash(f'Group {name} created successfully', 'success')
    
    return redirect(url_for('devices.list_groups'))


@device_bp.route('/bulk-import', methods=['GET', 'POST'])
@login_required
def bulk_import():
    """Bulk import devices from CSV file"""
    if request.method == 'POST':
        # Check if file was uploaded
        if 'csv_file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)

        file = request.files['csv_file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)

        if file and file.filename.lower().endswith('.csv'):
            try:
                # Read CSV content
                csv_content = file.read().decode('utf-8')

                # Process the CSV
                results = process_device_csv(csv_content)

                # Display results
                if results['errors']:
                    flash(f"Import completed with errors. {results['success_count']} devices imported, {results['error_count']} failed.", 'warning')
                    return render_template('devices/bulk_import.html',
                                         import_results=results)
                else:
                    flash(f"Successfully imported {results['success_count']} devices", 'success')
                    return redirect(url_for('devices.list_devices'))

            except Exception as e:
                logger.error(f"CSV import error: {str(e)}")
                flash(f'Error processing CSV file: {str(e)}', 'error')
        else:
            flash('Please upload a CSV file', 'error')

    return render_template('devices/bulk_import.html')


@device_bp.route('/bulk-import/template')
@login_required
def download_template():
    """Download CSV template for device import"""
    template_path = os.path.join(os.path.dirname(current_app.root_path), 'device_import_template.csv')

    if os.path.exists(template_path):
        return send_file(template_path, as_attachment=True,
                        download_name='device_import_template.csv')
    else:
        # Generate template on the fly if file doesn't exist
        output = io.StringIO()
        writer = csv.writer(output)

        # Header row
        writer.writerow([
            'hostname', 'ip_address', 'vendor'
        ])

        # Sample rows
        writer.writerow([
            'fw01.company.com', '192.168.1.1', 'paloalto'
        ])
        writer.writerow([
            'sw01.company.com', '192.168.1.10', 'cisco_ios'
        ])
        writer.writerow([
            'rtr01.company.com', '192.168.1.20', 'cisco_ios'
        ])

        output.seek(0)

        # Create response
        response = current_app.response_class(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=device_import_template.csv'}
        )
        return response


def process_device_csv(csv_content):
    """Process CSV content and import devices"""
    results = {
        'success_count': 0,
        'error_count': 0,
        'errors': [],
        'imported_devices': []
    }

    try:
        # Parse CSV
        csv_reader = csv.DictReader(io.StringIO(csv_content))
        row_number = 1

        # Valid vendors
        valid_vendors = ['cisco_ios', 'cisco_nxos', 'cisco_iosxr', 'paloalto', 'fortigate']

        for row in csv_reader:
            row_number += 1

            try:
                # Validate required fields
                required_fields = ['hostname', 'ip_address', 'vendor']
                missing_fields = [field for field in required_fields if not row.get(field, '').strip()]

                if missing_fields:
                    results['errors'].append({
                        'row': row_number,
                        'hostname': row.get('hostname', 'Unknown'),
                        'error': f"Missing required fields: {', '.join(missing_fields)}"
                    })
                    results['error_count'] += 1
                    continue

                # Validate vendor
                vendor = row['vendor'].strip().lower()
                if vendor not in valid_vendors:
                    results['errors'].append({
                        'row': row_number,
                        'hostname': row['hostname'],
                        'error': f"Invalid vendor '{vendor}'. Valid options: {', '.join(valid_vendors)}"
                    })
                    results['error_count'] += 1
                    continue

                # Check if device already exists
                existing_device = Device.query.filter_by(hostname=row['hostname'].strip()).first()
                if existing_device:
                    results['errors'].append({
                        'row': row_number,
                        'hostname': row['hostname'],
                        'error': "Device with this hostname already exists"
                    })
                    results['error_count'] += 1
                    continue

                # Create device (simplified - no groups, credentials, ports, or device_type)
                device = Device(
                    hostname=row['hostname'].strip(),
                    ip_address=row['ip_address'].strip(),
                    vendor=vendor
                )

                db.session.add(device)
                db.session.flush()  # Get device ID

                # Create audit log (check if we have current_user context)
                try:
                    audit_log = AuditLog(
                        user_id=current_user.id if current_user.is_authenticated else None,
                        device_id=device.id,
                        action='device_imported',
                        details=f'Imported device from CSV: {device.hostname}',
                        ip_address=request.remote_addr if request else '127.0.0.1'
                    )
                    db.session.add(audit_log)
                except:
                    # Skip audit log if context is not available (e.g., in testing)
                    pass

                results['imported_devices'].append({
                    'hostname': device.hostname,
                    'ip_address': device.ip_address,
                    'vendor': device.vendor
                })
                results['success_count'] += 1

            except ValueError as e:
                results['errors'].append({
                    'row': row_number,
                    'hostname': row.get('hostname', 'Unknown'),
                    'error': f"Invalid data format: {str(e)}"
                })
                results['error_count'] += 1

            except Exception as e:
                results['errors'].append({
                    'row': row_number,
                    'hostname': row.get('hostname', 'Unknown'),
                    'error': f"Unexpected error: {str(e)}"
                })
                results['error_count'] += 1

        # Commit all changes if no errors, or rollback if there were critical errors
        if results['success_count'] > 0:
            db.session.commit()
            logger.info(f"Bulk import completed: {results['success_count']} devices imported, {results['error_count']} errors")
        else:
            db.session.rollback()

    except Exception as e:
        db.session.rollback()
        logger.error(f"CSV processing error: {str(e)}")
        results['errors'].append({
            'row': 'File',
            'hostname': 'N/A',
            'error': f"File processing error: {str(e)}"
        })
        results['error_count'] += 1

    return results


def _upsert_interfaces(device_id, interfaces_data):
    """
    Upsert interfaces using a strategy that preserves manual interfaces
    and only updates what has actually changed.
    """
    # Get all existing interfaces for the device
    existing_interfaces = {intf.name: intf for intf in Interface.query.filter_by(device_id=device_id).all()}

    # Track interfaces that were updated from collection
    collected_interface_names = set()

    # Process collected interfaces
    for intf_data in interfaces_data:
        interface_name = intf_data['name']
        collected_interface_names.add(interface_name)

        existing_intf = existing_interfaces.get(interface_name)

        if existing_intf:
            # Interface exists - check if it needs updating
            needs_update = False
            changes = []

            # Only update interfaces that were originally collected, preserve manual ones
            if existing_intf.source == 'collected':
                # Check each field for changes
                new_description = intf_data.get('description', '') or ''
                if existing_intf.description != new_description:
                    changes.append(f'description: "{existing_intf.description}" -> "{new_description}"')
                    existing_intf.description = new_description
                    needs_update = True

                new_ipv4 = intf_data.get('ipv4_address')
                if existing_intf.ipv4_address != new_ipv4:
                    changes.append(f'ipv4: "{existing_intf.ipv4_address}" -> "{new_ipv4}"')
                    existing_intf.ipv4_address = new_ipv4
                    needs_update = True

                new_ipv6 = intf_data.get('ipv6_address')
                if existing_intf.ipv6_address != new_ipv6:
                    changes.append(f'ipv6: "{existing_intf.ipv6_address}" -> "{new_ipv6}"')
                    existing_intf.ipv6_address = new_ipv6
                    needs_update = True

                new_status = intf_data.get('status', 'unknown')
                if existing_intf.status != new_status:
                    changes.append(f'status: "{existing_intf.status}" -> "{new_status}"')
                    existing_intf.status = new_status
                    needs_update = True

                if needs_update:
                    existing_intf.last_updated = datetime.utcnow()
                    logger.info(f'Updated interface {interface_name}: {"; ".join(changes)}')
            else:
                # Manual interface - log that it was skipped
                logger.debug(f'Skipping manual interface {interface_name} during collection')
        else:
            # New interface - create it
            interface = Interface(
                device_id=device_id,
                name=interface_name,
                description=intf_data.get('description', '') or '',
                ipv4_address=intf_data.get('ipv4_address'),
                ipv6_address=intf_data.get('ipv6_address'),
                status=intf_data.get('status', 'unknown'),
                source='collected'
            )
            db.session.add(interface)
            logger.info(f'Added new interface {interface_name}')

    # Find interfaces that were previously collected but are no longer present
    # (Don't remove manual interfaces)
    for intf_name, existing_intf in existing_interfaces.items():
        if (existing_intf.source == 'collected' and
            intf_name not in collected_interface_names):
            # Interface was collected before but is no longer present
            logger.info(f'Removing interface {intf_name} - no longer present on device')
            db.session.delete(existing_intf)