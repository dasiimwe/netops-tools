from flask import render_template, redirect, url_for, flash, request, jsonify, send_file, current_app, Response
from flask_login import login_required, current_user
from app.routes import device_bp
from app.models import db, Device, DeviceGroup, Interface, AuditLog, Settings, Credential, CredentialPool, DeviceCredentialAssignment
from app.device_connectors import get_connector
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from sqlalchemy import or_, desc, asc, func
import logging
import csv
import io
import os
import json
import time
import uuid
from werkzeug.utils import secure_filename

logger = logging.getLogger(__name__)

def get_credentials_for_device(device, encryption_key):
    """
    Get credentials to try for a device in priority order:
    1. Device-specific credential assignment
    2. Device-specific credential pool assignment
    3. Default credential pool (if configured)
    4. Default credential (fallback)

    Returns list of tuples: [(credential_obj, (username, password)), ...]
    """
    credentials_to_try = []

    # Check for device-specific assignment
    assignment = DeviceCredentialAssignment.query.filter_by(device_id=device.id).first()
    if assignment:
        try:
            credentials_list = assignment.get_credentials_to_try(encryption_key)
            credentials_to_try.extend(credentials_list)
            logger.info(f"Using {assignment.assignment_type} assignment for {device.hostname}: "
                       f"{len(credentials_list)} credentials to try")
        except Exception as e:
            logger.error(f"Error getting assigned credentials for {device.hostname}: {e}")

    # If no device assignment, try default credential pool
    if not credentials_to_try:
        default_pool = CredentialPool.get_default()
        if default_pool:
            try:
                for credential in default_pool.get_credentials_list():
                    try:
                        username, password = credential.get_credentials(encryption_key)
                        credentials_to_try.append((credential, (username, password)))
                    except Exception as e:
                        logger.warning(f"Could not decrypt credential {credential.name}: {e}")
                        continue
                logger.info(f"Using default credential pool '{default_pool.name}' for {device.hostname}: "
                           f"{len(credentials_to_try)} credentials to try")
            except Exception as e:
                logger.error(f"Error getting default credential pool for {device.hostname}: {e}")

    # Final fallback to default credential
    if not credentials_to_try:
        default_credential = Credential.get_default()
        if default_credential:
            try:
                username, password = default_credential.get_credentials(encryption_key)
                credentials_to_try.append((default_credential, (username, password)))
                logger.info(f"Using default credential '{default_credential.name}' for {device.hostname}")
            except Exception as e:
                logger.error(f"Error getting default credential for {device.hostname}: {e}")

    if not credentials_to_try:
        logger.error(f"No credentials available for {device.hostname}")

    return credentials_to_try

def try_connect_with_credentials(device, credentials_list, **connector_kwargs):
    """
    Try to connect to a device using a list of credentials.
    Returns tuple: (success, connector, credential_used, error_message)
    """
    for credential, (username, password) in credentials_list:
        try:
            logger.info(f"Trying credential '{credential.name}' for {device.hostname}")

            connector = get_connector(
                vendor=device.vendor,
                host=device.ip_address,
                username=username,
                password=password,
                **connector_kwargs
            )

            # Try to connect
            success = connector.connect()
            if success:
                logger.info(f"Successfully connected to {device.hostname} using credential '{credential.name}'")
                return True, connector, credential, None
            else:
                logger.warning(f"Failed to connect to {device.hostname} using credential '{credential.name}'")
                connector.disconnect()

        except Exception as e:
            logger.warning(f"Error connecting to {device.hostname} with credential '{credential.name}': {e}")
            continue

    return False, None, None, f"Failed to connect with any of {len(credentials_list)} available credentials"

@device_bp.route('/')
@login_required
def list_devices():
    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'hostname')
    sort_order = request.args.get('sort_order', 'asc')
    vendor_filter = request.args.get('vendor', '')
    status_filter = request.args.get('status', '')
    group_filter = request.args.get('group', '', type=int)

    # Validate per_page limits
    if per_page not in [5, 10, 25, 50, 100]:
        per_page = 10

    # Validate sort_by field
    valid_sort_fields = ['hostname', 'ip_address', 'vendor', 'is_reachable', 'last_reachability_check']
    if sort_by not in valid_sort_fields:
        sort_by = 'hostname'

    # Validate sort_order
    if sort_order not in ['asc', 'desc']:
        sort_order = 'asc'

    # Start building the query
    query = Device.query

    # Apply search filter
    if search:
        search_filter = or_(
            Device.hostname.ilike(f'%{search}%'),
            Device.ip_address.ilike(f'%{search}%')
        )
        query = query.filter(search_filter)

    # Apply vendor filter
    if vendor_filter:
        query = query.filter(Device.vendor == vendor_filter)

    # Apply status filter
    if status_filter == 'reachable':
        query = query.filter(Device.is_reachable == True)
    elif status_filter == 'unreachable':
        query = query.filter(Device.is_reachable == False)

    # Apply group filter
    if group_filter:
        query = query.filter(Device.group_id == group_filter)

    # Special handling for interface count sorting
    if sort_by == 'interface_count':
        # Use a subquery to count interfaces
        interface_count_subq = db.session.query(
            Interface.device_id,
            func.count(Interface.id).label('interface_count')
        ).group_by(Interface.device_id).subquery()

        query = query.outerjoin(interface_count_subq, Device.id == interface_count_subq.c.device_id)

        if sort_order == 'desc':
            query = query.order_by(desc(func.coalesce(interface_count_subq.c.interface_count, 0)))
        else:
            query = query.order_by(asc(func.coalesce(interface_count_subq.c.interface_count, 0)))
    else:
        # Apply normal sorting
        sort_column = getattr(Device, sort_by)
        if sort_order == 'desc':
            query = query.order_by(desc(sort_column))
        else:
            query = query.order_by(asc(sort_column))

    # Apply pagination
    devices_paginated = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    # Get additional data for filters and bulk operations
    groups = DeviceGroup.query.all()
    available_credentials = Credential.query.order_by(Credential.name).all()
    available_pools = CredentialPool.query.order_by(CredentialPool.name).all()

    # Get unique vendors for filter dropdown
    vendors = db.session.query(Device.vendor).distinct().order_by(Device.vendor).all()
    vendors = [v[0] for v in vendors if v[0]]

    # Get device statistics
    total_devices = Device.query.count()
    reachable_devices = Device.query.filter_by(is_reachable=True).count()
    unreachable_devices = Device.query.filter_by(is_reachable=False).count()

    return render_template('devices/list.html',
                         devices=devices_paginated.items,
                         pagination=devices_paginated,
                         groups=groups,
                         available_credentials=available_credentials,
                         available_pools=available_pools,
                         vendors=vendors,
                         search=search,
                         sort_by=sort_by,
                         sort_order=sort_order,
                         vendor_filter=vendor_filter,
                         status_filter=status_filter,
                         group_filter=group_filter,
                         per_page=per_page,
                         total_devices=total_devices,
                         reachable_devices=reachable_devices,
                         unreachable_devices=unreachable_devices)

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

    # Get credential assignment data for template
    device_assignment = DeviceCredentialAssignment.query.filter_by(device_id=device.id).first()
    available_credentials = Credential.query.order_by(Credential.name).all()
    available_pools = CredentialPool.query.order_by(CredentialPool.name).all()
    default_pool = CredentialPool.get_default()

    return render_template('devices/edit.html',
                         device=device,
                         device_assignment=device_assignment,
                         available_credentials=available_credentials,
                         available_pools=available_pools,
                         default_pool=default_pool)

@device_bp.route('/<int:device_id>/assign-credentials', methods=['POST'])
@login_required
def assign_credentials(device_id):
    """Assign credentials or credential pool to a device"""
    device = Device.query.get_or_404(device_id)

    try:
        assignment_type = request.form.get('assignment_type')

        # Remove existing assignment if any
        existing_assignment = DeviceCredentialAssignment.query.filter_by(device_id=device.id).first()
        if existing_assignment:
            db.session.delete(existing_assignment)

        if assignment_type == 'none':
            # Just remove assignment, no new one to create
            pass
        elif assignment_type == 'credential':
            credential_id = request.form.get('credential_id')
            if not credential_id:
                flash('Please select a credential', 'danger')
                return redirect(url_for('devices.edit_device', device_id=device_id))

            credential = Credential.query.get(credential_id)
            if not credential:
                flash('Selected credential not found', 'danger')
                return redirect(url_for('devices.edit_device', device_id=device_id))

            assignment = DeviceCredentialAssignment(
                device_id=device.id,
                assignment_type='credential',
                credential_id=credential_id
            )
            db.session.add(assignment)

            # Log assignment
            audit_log = AuditLog(
                user_id=current_user.id,
                action='device_credential_assigned',
                details=f'Assigned credential "{credential.name}" to device {device.hostname}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)

            flash(f'Assigned credential "{credential.name}" to device {device.hostname}', 'success')

        elif assignment_type == 'pool':
            credential_pool_id = request.form.get('credential_pool_id')
            if not credential_pool_id:
                flash('Please select a credential pool', 'danger')
                return redirect(url_for('devices.edit_device', device_id=device_id))

            pool = CredentialPool.query.get(credential_pool_id)
            if not pool:
                flash('Selected credential pool not found', 'danger')
                return redirect(url_for('devices.edit_device', device_id=device_id))

            assignment = DeviceCredentialAssignment(
                device_id=device.id,
                assignment_type='pool',
                credential_pool_id=credential_pool_id
            )
            db.session.add(assignment)

            # Log assignment
            audit_log = AuditLog(
                user_id=current_user.id,
                action='device_credential_pool_assigned',
                details=f'Assigned credential pool "{pool.name}" to device {device.hostname}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)

            flash(f'Assigned credential pool "{pool.name}" to device {device.hostname}', 'success')

        db.session.commit()

    except Exception as e:
        db.session.rollback()
        flash(f'Error assigning credentials: {str(e)}', 'danger')

    return redirect(url_for('devices.edit_device', device_id=device_id))

@device_bp.route('/<int:device_id>/remove-credential-assignment', methods=['POST'])
@login_required
def remove_credential_assignment(device_id):
    """Remove credential assignment from a device"""
    device = Device.query.get_or_404(device_id)

    try:
        assignment = DeviceCredentialAssignment.query.filter_by(device_id=device.id).first()
        if assignment:
            assignment_desc = f"{assignment.assignment_type}: "
            if assignment.assignment_type == 'credential':
                assignment_desc += assignment.credential.name
            elif assignment.assignment_type == 'pool':
                assignment_desc += assignment.credential_pool.name

            # Log removal
            audit_log = AuditLog(
                user_id=current_user.id,
                action='device_credential_assignment_removed',
                details=f'Removed credential assignment ({assignment_desc}) from device {device.hostname}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)

            db.session.delete(assignment)
            db.session.commit()

            flash(f'Removed credential assignment from device {device.hostname}', 'success')
        else:
            flash('No credential assignment found for this device', 'info')

    except Exception as e:
        db.session.rollback()
        flash(f'Error removing credential assignment: {str(e)}', 'danger')

    return redirect(url_for('devices.edit_device', device_id=device_id))

@device_bp.route('/bulk-assign-credentials', methods=['POST'])
@login_required
def bulk_assign_credentials():
    """Bulk assign credentials or credential pools to multiple devices"""
    try:
        assignment_type = request.form.get('assignment_type')
        device_ids = request.form.getlist('device_ids[]')

        if not device_ids:
            flash('No devices selected', 'danger')
            return redirect(url_for('devices.list_devices'))

        devices = Device.query.filter(Device.id.in_(device_ids)).all()
        if len(devices) != len(device_ids):
            flash('Some selected devices were not found', 'danger')
            return redirect(url_for('devices.list_devices'))

        success_count = 0
        error_count = 0

        for device in devices:
            try:
                # Remove existing assignment if any
                existing_assignment = DeviceCredentialAssignment.query.filter_by(device_id=device.id).first()
                if existing_assignment:
                    db.session.delete(existing_assignment)

                if assignment_type == 'none':
                    # Just remove assignment, no new one to create
                    success_count += 1
                elif assignment_type == 'credential':
                    credential_id = request.form.get('credential_id')
                    if not credential_id:
                        error_count += 1
                        continue

                    credential = Credential.query.get(credential_id)
                    if not credential:
                        error_count += 1
                        continue

                    assignment = DeviceCredentialAssignment(
                        device_id=device.id,
                        assignment_type='credential',
                        credential_id=credential_id
                    )
                    db.session.add(assignment)
                    success_count += 1

                elif assignment_type == 'pool':
                    credential_pool_id = request.form.get('credential_pool_id')
                    if not credential_pool_id:
                        error_count += 1
                        continue

                    pool = CredentialPool.query.get(credential_pool_id)
                    if not pool:
                        error_count += 1
                        continue

                    assignment = DeviceCredentialAssignment(
                        device_id=device.id,
                        assignment_type='pool',
                        credential_pool_id=credential_pool_id
                    )
                    db.session.add(assignment)
                    success_count += 1

            except Exception as e:
                logger.error(f"Error assigning credentials to device {device.hostname}: {e}")
                error_count += 1

        # Log bulk assignment
        if assignment_type == 'none':
            details = f'Bulk removed credential assignments from {success_count} devices'
        elif assignment_type == 'credential':
            credential_name = credential.name if 'credential' in locals() else 'Unknown'
            details = f'Bulk assigned credential "{credential_name}" to {success_count} devices'
        elif assignment_type == 'pool':
            pool_name = pool.name if 'pool' in locals() else 'Unknown'
            details = f'Bulk assigned credential pool "{pool_name}" to {success_count} devices'

        audit_log = AuditLog(
            user_id=current_user.id,
            action='bulk_credential_assignment',
            details=details,
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        # Show results
        if success_count > 0:
            flash(f'Successfully updated credentials for {success_count} device(s)', 'success')
        if error_count > 0:
            flash(f'Failed to update credentials for {error_count} device(s)', 'warning')

    except Exception as e:
        db.session.rollback()
        flash(f'Error during bulk credential assignment: {str(e)}', 'danger')

    return redirect(url_for('devices.list_devices'))

@device_bp.route('/<int:device_id>/test-connection', methods=['POST'])
@login_required
def test_connection(device_id):
    """Test connection to a device using assigned credentials"""
    device = Device.query.get_or_404(device_id)

    try:
        encryption_key = current_app.config['ENCRYPTION_KEY']

        # Get credentials for this device
        credentials_list = get_credentials_for_device(device, encryption_key)

        if not credentials_list:
            return jsonify({
                'success': False,
                'error': 'No credentials available for this device',
                'credentials_tried': 0
            })

        # Try to connect
        import time
        start_time = time.time()

        success, connector, credential_used, error_message = try_connect_with_credentials(
            device, credentials_list
        )

        connection_time = int((time.time() - start_time) * 1000)  # Convert to milliseconds

        if success:
            # Disconnect immediately - this is just a test
            connector.disconnect()

            # Log successful test
            audit_log = AuditLog(
                user_id=current_user.id,
                action='device_connection_test_success',
                details=f'Successfully tested connection to {device.hostname} using credential "{credential_used.name}"',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()

            return jsonify({
                'success': True,
                'credential_name': credential_used.name,
                'connection_time': connection_time,
                'credentials_tried': len(credentials_list)
            })
        else:
            # Log failed test
            audit_log = AuditLog(
                user_id=current_user.id,
                action='device_connection_test_failed',
                details=f'Failed to test connection to {device.hostname}: {error_message}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()

            return jsonify({
                'success': False,
                'error': error_message,
                'credentials_tried': len(credentials_list)
            })

    except Exception as e:
        logger.error(f"Error testing connection to {device.hostname}: {e}")

        # Log error
        audit_log = AuditLog(
            user_id=current_user.id,
            action='device_connection_test_error',
            details=f'Error testing connection to {device.hostname}: {str(e)}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        return jsonify({
            'success': False,
            'error': f'Connection test error: {str(e)}',
            'credentials_tried': 0
        }), 500

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

    # Check if request is JSON (from inline progress)
    is_json_request = request.is_json or request.headers.get('Content-Type') == 'application/json'

    try:
        from flask import current_app
        encryption_key = current_app.config['ENCRYPTION_KEY']

        # Get credentials to try for this device
        credentials_list = get_credentials_for_device(device, encryption_key)

        if not credentials_list:
            if is_json_request:
                return jsonify({'success': False, 'error': 'No credentials configured for device collection'}), 400
            flash('No credentials configured for device collection. Please configure credentials.', 'warning')
            return redirect(url_for('devices.list_devices'))

        # Try to connect with available credentials
        success, connector, credential_used, error_msg = try_connect_with_credentials(
            device, credentials_list,
            port=22,
            timeout=current_app.config['DEVICE_CONNECTION_TIMEOUT'],
            retry_enabled=current_app.config['DEVICE_RETRY_ENABLED'],
            retry_count=current_app.config['DEVICE_RETRY_COUNT'],
            retry_delay=current_app.config['DEVICE_RETRY_DELAY'],
            device_id=device.id,
            user_id=current_user.id,
            enable_session_logging=True
        )

        if not success:
            device.is_reachable = False
            device.last_reachability_check = datetime.utcnow()
            device.last_error = error_msg
            db.session.commit()
            if is_json_request:
                return jsonify({'success': False, 'error': error_msg}), 400
            flash(f'Failed to connect to {device.hostname}: {error_msg}', 'danger')
            return redirect(url_for('devices.list_devices'))

        try:
            # Collect interface data
            interfaces_data = connector.get_interfaces()

            # Update database using upsert strategy
            _upsert_interfaces(device.id, interfaces_data)

            # Update device status
            device.is_reachable = True
            device.last_successful_connection = datetime.utcnow()
            device.last_reachability_check = datetime.utcnow()
            device.last_error = None

            # Log collection with credential used
            audit_log = AuditLog(
                user_id=current_user.id,
                device_id=device.id,
                action='interface_collection',
                details=f'Collected {len(interfaces_data)} interfaces from {device.hostname} using credential "{credential_used.name}"',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()

            if is_json_request:
                return jsonify({'success': True, 'interfaces_found': len(interfaces_data), 'credential_used': credential_used.name})

            flash(f'Successfully collected {len(interfaces_data)} interfaces from {device.hostname} using credential "{credential_used.name}"', 'success')

        finally:
            # Ensure connection is closed
            connector.disconnect()

    except Exception as e:
        logger.error(f'Error collecting interfaces from {device.hostname}: {str(e)}')

        # Update device status
        device.is_reachable = False
        device.last_reachability_check = datetime.utcnow()
        device.last_error = str(e)
        db.session.commit()

        if is_json_request:
            return jsonify({'success': False, 'error': str(e)}), 500

        flash(f'Error collecting interfaces from {device.hostname}: {str(e)}', 'danger')

    return redirect(url_for('devices.list_devices'))

@device_bp.route('/bulk_collect', methods=['POST'])
@login_required
def bulk_collect():
    device_ids = request.form.getlist('device_ids[]')
    
    if not device_ids:
        flash('No devices selected', 'warning')
        return redirect(url_for('devices.list_devices'))
    
    # Check that we have some form of credentials configured
    from app.models import Credential, CredentialPool
    has_default_credential = Credential.get_default() is not None
    has_default_pool = CredentialPool.get_default() is not None
    has_any_credentials = Credential.query.count() > 0

    if not (has_default_credential or has_default_pool or has_any_credentials):
        flash('No credentials configured for device collection. Please configure credentials first.', 'warning')
        return redirect(url_for('devices.list_devices'))
    
    from flask import current_app
    max_workers = current_app.config['MAX_CONCURRENT_CONNECTIONS']
    
    success_count = 0
    error_count = 0
    
    def collect_from_device(device, app_context, encryption_key, config, user_id):
        with app_context:
            try:
                # Get credentials to try for this device
                credentials_list = get_credentials_for_device(device, encryption_key)

                if not credentials_list:
                    device.is_reachable = False
                    device.last_reachability_check = datetime.utcnow()
                    device.last_error = 'No credentials configured for device'
                    return False, device.hostname, 'No credentials configured for device'

                # Try to connect with available credentials
                success, connector, credential_used, error_msg = try_connect_with_credentials(
                    device, credentials_list,
                    port=22,
                    timeout=config['DEVICE_CONNECTION_TIMEOUT'],
                    retry_enabled=config['DEVICE_RETRY_ENABLED'],
                    retry_count=config['DEVICE_RETRY_COUNT'],
                    retry_delay=config['DEVICE_RETRY_DELAY'],
                    device_id=device.id,
                    user_id=user_id,
                    enable_session_logging=True
                )

                if not success:
                    device.is_reachable = False
                    device.last_reachability_check = datetime.utcnow()
                    device.last_error = error_msg
                    return False, device.hostname, error_msg

                try:
                    # Get interface commands and execute them
                    commands = connector.get_interface_commands()
                    command_outputs = {}

                    for command in commands:
                        try:
                            output = connector.execute_command(command)
                            command_outputs[command] = output
                        except Exception as e:
                            logger.error(f"Command '{command}' failed on {device.hostname}: {e}")
                            command_outputs[command] = ''

                    # Parse interfaces and filter those with IP addresses
                    all_interfaces = connector.parse_interfaces(command_outputs)
                    interfaces_data = [
                        intf for intf in all_interfaces
                        if (intf.get('ipv4_address') and intf.get('ipv4_address').strip()) or
                           (intf.get('ipv6_address') and intf.get('ipv6_address').strip())
                    ]

                    # Update database using upsert strategy
                    _upsert_interfaces(device.id, interfaces_data)

                    device.is_reachable = True
                    device.last_successful_connection = datetime.utcnow()
                    device.last_reachability_check = datetime.utcnow()
                    device.last_error = None

                finally:
                    # Always disconnect
                    connector.disconnect()

                return True, device.hostname, f"{len(interfaces_data)} interfaces (using {credential_used.name})"

            except Exception as e:
                device.is_reachable = False
                device.last_reachability_check = datetime.utcnow()
                device.last_error = str(e)
                return False, device.hostname, str(e)
    
    # Execute collections in parallel
    app_context = current_app.app_context()
    encryption_key = current_app.config['ENCRYPTION_KEY']
    user_id = current_user.id
    config = {
        'DEVICE_CONNECTION_TIMEOUT': current_app.config['DEVICE_CONNECTION_TIMEOUT'],
        'DEVICE_RETRY_ENABLED': current_app.config['DEVICE_RETRY_ENABLED'],
        'DEVICE_RETRY_COUNT': current_app.config['DEVICE_RETRY_COUNT'],
        'DEVICE_RETRY_DELAY': current_app.config['DEVICE_RETRY_DELAY']
    }

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for device_id in device_ids:
            device = Device.query.get(device_id)
            if device:
                future = executor.submit(collect_from_device, device, app_context, encryption_key, config, user_id)
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
    """Download CSV template for device import - generated dynamically"""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        'hostname', 'ip_address', 'vendor'
    ])

    # Sample rows with all supported vendors
    writer.writerow([
        'fw01.company.com', '192.168.1.1', 'paloalto'
    ])
    writer.writerow([
        'sw01.company.com', '192.168.1.10', 'cisco_ios'
    ])
    writer.writerow([
        'rtr01.company.com', '192.168.1.20', 'cisco_ios'
    ])
    writer.writerow([
        'fw02.branch.com', '10.10.1.1', 'fortigate'
    ])
    writer.writerow([
        'fw03.branch.com', '10.10.1.2', 'cisco_asa'
    ])
    writer.writerow([
        'sw02.company.com', '192.168.1.11', 'cisco_nxos'
    ])
    writer.writerow([
        'sw03.company.com', '192.168.1.12', 'arista'
    ])
    writer.writerow([
        'rtr02.company.com', '192.168.1.21', 'cisco_iosxr'
    ])
    writer.writerow([
        'rtr03.company.com', '192.168.1.22', 'juniper'
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


# Global progress tracking
progress_sessions = {}

@device_bp.route('/<int:device_id>/collect-progress', methods=['POST'])
@login_required
def collect_interfaces_with_progress(device_id):
    """Start interface collection with progress tracking"""
    try:
        logger.info(f"Starting collect-progress for device_id: {device_id}")
        device = Device.query.get(device_id)
        if not device:
            logger.error(f"Device {device_id} not found")
            return jsonify({'error': f'Device {device_id} not found', 'progress_enabled': False}), 404

        logger.info(f"Found device: {device.hostname}")

        # Check if progress bar is enabled
        show_progress = Settings.get_value('show_interface_progress', True)
        logger.info(f"Progress setting: {show_progress}")
        if not show_progress:
            logger.info("Progress disabled, returning progress_enabled=False")
            # Return JSON to tell frontend to use regular collection
            return jsonify({'progress_enabled': False, 'session_id': None})

        # Generate unique session ID
        session_id = str(uuid.uuid4())

        # Initialize progress session
        progress_sessions[session_id] = {
            'device_id': device_id,
            'device_hostname': device.hostname,
            'user_id': current_user.id,
            'status': 'starting',
            'commands': [],
            'current_command': None,
            'error': None,
            'interfaces_found': 0,
            'start_time': datetime.utcnow(),
            'completed': False
        }

        # Start collection in background with app context
        from threading import Thread
        thread = Thread(target=_collect_with_progress, args=(session_id, current_app._get_current_object()))
        thread.daemon = True
        thread.start()

        return jsonify({'session_id': session_id, 'progress_enabled': True})
    except Exception as e:
        logger.error(f"Error starting interface collection with progress: {str(e)}")
        return jsonify({'error': str(e), 'progress_enabled': False}), 500

@device_bp.route('/progress-stream/<session_id>')
@login_required
def progress_stream(session_id):
    """SSE endpoint for progress updates"""
    def generate():
        try:
            while session_id in progress_sessions:
                session = progress_sessions[session_id]

                # Send current progress
                data = {
                    'type': 'progress',
                    'device_hostname': session['device_hostname'],
                    'status': session['status'],
                    'commands': session['commands'],
                    'current_command': session['current_command'],
                    'interfaces_found': session['interfaces_found'],
                    'error': session['error']
                }

                yield f"data: {json.dumps(data)}\n\n"

                # Check if completed
                if session['completed']:
                    # Send completion event
                    completion_data = {
                        'type': 'complete',
                        'success': session['error'] is None,
                        'error': session['error'],
                        'interfaces_found': session['interfaces_found']
                    }
                    yield f"data: {json.dumps(completion_data)}\n\n"

                    # Clean up session after 5 seconds
                    time.sleep(5)
                    if session_id in progress_sessions:
                        del progress_sessions[session_id]
                    break

                time.sleep(0.5)  # Update every 500ms

        except Exception as e:
            logger.error(f"Progress stream error: {e}")
            # Send error and cleanup
            error_data = {
                'type': 'error',
                'error': str(e)
            }
            yield f"data: {json.dumps(error_data)}\n\n"
            if session_id in progress_sessions:
                del progress_sessions[session_id]

    return Response(generate(), mimetype='text/event-stream',
                   headers={'Cache-Control': 'no-cache',
                           'Connection': 'keep-alive'})

def _collect_with_progress(session_id, app):
    """Collect interfaces with progress tracking"""
    with app.app_context():
        session = progress_sessions[session_id]

        try:
            device_id = session['device_id']
            device = Device.query.get(device_id)

            if not device:
                session['error'] = 'Device not found'
                session['completed'] = True
                return

            session['status'] = 'getting_credentials'

            # Get credentials to try for this device
            credentials_list = get_credentials_for_device(device, app.config['ENCRYPTION_KEY'])

            if not credentials_list:
                session['error'] = 'No credentials configured for device collection'
                session['completed'] = True
                return

            session['status'] = 'connecting'

            # Try to connect with available credentials
            success, connector, credential_used, error_msg = try_connect_with_credentials(
                device, credentials_list,
                port=22,
                timeout=app.config['DEVICE_CONNECTION_TIMEOUT'],
                retry_enabled=app.config['DEVICE_RETRY_ENABLED'],
                retry_count=app.config['DEVICE_RETRY_COUNT'],
                retry_delay=app.config['DEVICE_RETRY_DELAY'],
                device_id=device.id,
                user_id=session.get('user_id'),
                enable_session_logging=True
            )

            if not success:
                session['error'] = error_msg
                session['completed'] = True
                return

            session['status'] = 'connected'
            session['credential_used'] = credential_used.name

            # Get interface commands
            commands = connector.get_interface_commands()
            session['commands'] = [{'command': cmd, 'status': 'pending', 'output_length': 0} for cmd in commands]

            # Execute commands with progress tracking
            command_outputs = {}
            for i, command in enumerate(commands):
                session['current_command'] = command
                session['commands'][i]['status'] = 'executing'

                try:
                    output = connector.execute_command(command)
                    command_outputs[command] = output

                    session['commands'][i]['status'] = 'completed'
                    session['commands'][i]['output_length'] = len(output)

                except Exception as e:
                    session['commands'][i]['status'] = 'failed'
                    session['commands'][i]['error'] = str(e)
                    logger.error(f"Command '{command}' failed: {e}")
                    command_outputs[command] = ''

            session['status'] = 'parsing'
            session['current_command'] = 'Parsing interface data...'

            # Create progress callback for dynamic commands
            def progress_callback(progress_data):
                try:
                    # Add dynamic command to session if not already there
                    command = progress_data.get('command', '')
                    if command and not any(cmd['command'] == command for cmd in session['commands']):
                        session['commands'].append({
                            'command': command,
                            'status': progress_data.get('status', 'executing'),
                            'output_length': progress_data.get('output_length', 0),
                            'error': progress_data.get('error', '')
                        })
                    else:
                        # Update existing command
                        for cmd in session['commands']:
                            if cmd['command'] == command:
                                cmd['status'] = progress_data.get('status', cmd['status'])
                                cmd['output_length'] = progress_data.get('output_length', cmd.get('output_length', 0))
                                if progress_data.get('error'):
                                    cmd['error'] = progress_data.get('error')
                                break

                    # Update current command display
                    interface = progress_data.get('interface', '')
                    progress = progress_data.get('progress', '')
                    if interface and progress:
                        session['current_command'] = f"Getting description for {interface} ({progress})"
                except Exception as e:
                    logger.warning(f"Error in progress callback: {e}")

            # Parse interfaces and filter those with IP addresses
            all_interfaces = connector.parse_interfaces(command_outputs, progress_callback)
            interfaces_data = [
                intf for intf in all_interfaces
                if (intf.get('ipv4_address') and intf.get('ipv4_address').strip()) or
                   (intf.get('ipv6_address') and intf.get('ipv6_address').strip())
            ]
            session['interfaces_found'] = len(interfaces_data)

            session['status'] = 'updating_database'
            session['current_command'] = 'Updating database...'

            # Update database
            _upsert_interfaces(device.id, interfaces_data)

            # Update device status
            device.is_reachable = True
            device.last_successful_connection = datetime.utcnow()
            device.last_reachability_check = datetime.utcnow()
            device.last_error = None

            # Log collection with credential used
            audit_log = AuditLog(
                user_id=session.get('user_id'),
                device_id=device.id,
                action='interface_collection_progress',
                details=f'Collected {len(interfaces_data)} interfaces from {device.hostname} using credential "{session.get("credential_used", "unknown")}" with progress tracking',
                ip_address='system'
            )
            db.session.add(audit_log)
            db.session.commit()

            session['status'] = 'completed'
            session['current_command'] = None

        except Exception as e:
            logger.error(f'Error in progress collection: {e}')
            session['error'] = str(e)
            session['status'] = 'failed'

            # Update device status
            try:
                device = Device.query.get(session['device_id'])
                if device:
                    device.is_reachable = False
                    device.last_reachability_check = datetime.utcnow()
                    device.last_error = str(e)
                    db.session.commit()
            except:
                pass

        finally:
            # Ensure connection is closed
            try:
                if 'connector' in locals():
                    connector.disconnect()
            except:
                pass
            session['completed'] = True


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

@device_bp.route('/export_csv')
@login_required
def export_csv():
    """Export all devices to CSV (compatible with import format)"""
    from flask import make_response

    # Get all devices
    devices = Device.query.order_by(Device.hostname).all()

    output = io.StringIO()
    writer = csv.writer(output)

    # Write header row (matches import template format)
    writer.writerow([
        'hostname',
        'ip_address',
        'vendor'
    ])

    # Write data rows
    for device in devices:
        writer.writerow([
            device.hostname,
            device.ip_address,
            device.vendor  # Keep vendor as-is (e.g., cisco_ios, paloalto) for import compatibility
        ])

    # Create response with timestamp in filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = f'attachment; filename=devices_export_{timestamp}.csv'
    response.headers['Content-Type'] = 'text/csv'

    # Log export
    audit_log = AuditLog(
        user_id=current_user.id,
        action='devices_exported_csv',
        details=f'Exported {len(devices)} devices to CSV',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()

    return response

@device_bp.route('/export_json')
@login_required
def export_json():
    """Export all devices to JSON"""
    from flask import make_response

    # Get all devices with interfaces
    devices = Device.query.order_by(Device.hostname).all()

    data = []
    for device in devices:
        interfaces = []
        for interface in device.interfaces:
            interfaces.append({
                'name': interface.name,
                'description': interface.description,
                'ipv4_address': interface.ipv4_address,
                'ipv6_address': interface.ipv6_address,
                'status': interface.status
            })

        data.append({
            'hostname': device.hostname,
            'ip_address': device.ip_address,
            'vendor': device.vendor,
            'device_type': device.device_type,
            'location': device.location,
            'is_reachable': device.is_reachable,
            'interfaces': interfaces,
            'updated_at': device.updated_at.isoformat() if device.updated_at else None,
            'created_at': device.created_at.isoformat() if device.created_at else None
        })

    # Create response with timestamp in filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    response = make_response(json.dumps(data, indent=2))
    response.headers['Content-Disposition'] = f'attachment; filename=devices_export_{timestamp}.json'
    response.headers['Content-Type'] = 'application/json'

    # Log export
    audit_log = AuditLog(
        user_id=current_user.id,
        action='devices_exported_json',
        details=f'Exported {len(devices)} devices to JSON',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()

    return response

@device_bp.route('/bulk-edit-vendor', methods=['POST'])
@login_required
def bulk_edit_vendor():
    """Bulk update vendor for multiple devices"""
    from flask import make_response

    try:
        data = request.get_json()
        device_ids = data.get('device_ids', [])
        vendor = data.get('vendor', '')

        if not device_ids:
            return jsonify({'success': False, 'message': 'No devices selected'}), 400

        if not vendor:
            return jsonify({'success': False, 'message': 'No vendor selected'}), 400

        # Validate vendor
        valid_vendors = ['cisco_ios', 'cisco_nxos', 'cisco_iosxr', 'cisco_asa', 'arista', 'juniper', 'paloalto', 'fortigate']
        if vendor not in valid_vendors:
            return jsonify({'success': False, 'message': 'Invalid vendor'}), 400

        # Update devices
        updated_count = 0
        for device_id in device_ids:
            device = Device.query.get(device_id)
            if device:
                device.vendor = vendor
                updated_count += 1

        db.session.commit()

        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            action='bulk_vendor_update',
            details=f'Updated vendor to {vendor} for {updated_count} devices',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        return jsonify({
            'success': True,
            'updated_count': updated_count,
            'message': f'Successfully updated {updated_count} device(s)'
        })

    except Exception as e:
        logger.error(f"Bulk vendor update error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500