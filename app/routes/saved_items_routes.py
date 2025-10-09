from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import current_user
from app.routes import saved_items_bp
from app.models import db, SavedDeviceList, SavedCommand, AuditLog
from datetime import datetime
import json

# ===== Saved Device Lists =====

@saved_items_bp.route('/device-lists')
def list_device_lists():
    """List all saved device lists"""
    device_lists = SavedDeviceList.query.order_by(SavedDeviceList.updated_at.desc()).all()
    return render_template('saved_items/device_lists.html', device_lists=device_lists)

@saved_items_bp.route('/device-lists/create', methods=['GET', 'POST'])
def create_device_list():
    """Create a new saved device list"""
    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            devices_text = request.form.get('devices', '')

            if not name:
                flash('Name is required', 'danger')
                return redirect(request.url)

            # Parse devices - handle both JSON array and newline-separated text
            try:
                devices = json.loads(devices_text)
                if not isinstance(devices, list):
                    devices = [devices]
            except json.JSONDecodeError:
                # Fall back to newline-separated parsing
                devices = [d.strip() for d in devices_text.split('\n') if d.strip()]

            if not devices:
                flash('At least one device is required', 'danger')
                return redirect(request.url)

            # Create saved device list
            device_list = SavedDeviceList(
                name=name,
                description=description,
                created_by=current_user.id if current_user.is_authenticated else None
            )
            device_list.set_devices_list(devices)

            db.session.add(device_list)

            # Log creation
            audit_log = AuditLog(
                user_id=current_user.id if current_user.is_authenticated else None,
                action='saved_device_list_created',
                details=f'Created saved device list: {name} with {len(devices)} device(s)',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()

            flash(f'Device list "{name}" created successfully', 'success')
            return redirect(url_for('saved_items.list_device_lists'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating device list: {str(e)}', 'danger')
            return redirect(request.url)

    return render_template('saved_items/create_device_list.html')

@saved_items_bp.route('/device-lists/<int:list_id>/edit', methods=['GET', 'POST'])
def edit_device_list(list_id):
    """Edit a saved device list"""
    device_list = SavedDeviceList.query.get_or_404(list_id)

    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            devices_text = request.form.get('devices', '')

            if not name:
                flash('Name is required', 'danger')
                return redirect(request.url)

            # Parse devices
            try:
                devices = json.loads(devices_text)
                if not isinstance(devices, list):
                    devices = [devices]
            except json.JSONDecodeError:
                devices = [d.strip() for d in devices_text.split('\n') if d.strip()]

            if not devices:
                flash('At least one device is required', 'danger')
                return redirect(request.url)

            # Update device list
            device_list.name = name
            device_list.description = description
            device_list.set_devices_list(devices)
            device_list.updated_at = datetime.utcnow()

            # Log update
            audit_log = AuditLog(
                user_id=current_user.id if current_user.is_authenticated else None,
                action='saved_device_list_updated',
                details=f'Updated saved device list: {name}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()

            flash(f'Device list "{name}" updated successfully', 'success')
            return redirect(url_for('saved_items.list_device_lists'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error updating device list: {str(e)}', 'danger')
            return redirect(request.url)

    # Convert devices list to newline-separated text for editing
    devices_text = '\n'.join(device_list.get_devices_list())

    return render_template('saved_items/edit_device_list.html',
                         device_list=device_list,
                         devices_text=devices_text)

@saved_items_bp.route('/device-lists/<int:list_id>/delete', methods=['POST'])
def delete_device_list(list_id):
    """Delete a saved device list"""
    device_list = SavedDeviceList.query.get_or_404(list_id)
    name = device_list.name

    try:
        # Log deletion
        audit_log = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action='saved_device_list_deleted',
            details=f'Deleted saved device list: {name}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)

        db.session.delete(device_list)
        db.session.commit()

        flash(f'Device list "{name}" deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting device list: {str(e)}', 'danger')

    return redirect(url_for('saved_items.list_device_lists'))

@saved_items_bp.route('/api/device-lists')
def get_all_device_lists():
    """Get all saved device lists as JSON"""
    device_lists = SavedDeviceList.query.order_by(SavedDeviceList.updated_at.desc()).all()
    return jsonify([{
        'id': dl.id,
        'name': dl.name,
        'description': dl.description,
        'devices': dl.get_devices_list(),
        'updated_at': dl.updated_at.isoformat() if dl.updated_at else None
    } for dl in device_lists])

@saved_items_bp.route('/api/device-lists/<int:list_id>')
def get_device_list(list_id):
    """Get a saved device list as JSON"""
    device_list = SavedDeviceList.query.get_or_404(list_id)
    return jsonify({
        'id': device_list.id,
        'name': device_list.name,
        'description': device_list.description,
        'devices': device_list.get_devices_list()
    })

@saved_items_bp.route('/api/device-lists/<int:list_id>/update', methods=['POST', 'PUT'])
def update_device_list_api(list_id):
    """Update a device list via API"""
    device_list = SavedDeviceList.query.get_or_404(list_id)

    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        devices = data.get('devices', [])

        if not name:
            return jsonify({'success': False, 'error': 'Name is required'}), 400

        if not devices or not isinstance(devices, list):
            return jsonify({'success': False, 'error': 'Devices must be a non-empty list'}), 400

        device_list.name = name
        device_list.set_devices_list(devices)
        device_list.updated_at = datetime.utcnow()

        audit_log = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action='saved_device_list_updated_api',
            details=f'Updated saved device list via API: {name}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        return jsonify({'success': True, 'message': f'Device list "{name}" updated'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@saved_items_bp.route('/api/device-lists/<int:list_id>/delete', methods=['POST', 'DELETE'])
def delete_device_list_api(list_id):
    """Delete a device list via API"""
    device_list = SavedDeviceList.query.get_or_404(list_id)

    name = device_list.name
    try:
        audit_log = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action='saved_device_list_deleted_api',
            details=f'Deleted saved device list via API: {name}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.delete(device_list)
        db.session.commit()

        return jsonify({'success': True, 'message': f'Device list "{name}" deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# ===== Saved Commands =====

@saved_items_bp.route('/commands')
def list_commands():
    """List all saved commands"""
    commands = SavedCommand.query.order_by(SavedCommand.updated_at.desc()).all()
    return render_template('saved_items/commands.html', commands=commands)

@saved_items_bp.route('/commands/create', methods=['GET', 'POST'])
def create_command():
    """Create a new saved command"""
    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            vendor = request.form.get('vendor', '').strip()
            commands_text = request.form.get('commands', '')

            if not name:
                flash('Name is required', 'danger')
                return redirect(request.url)

            # Parse commands
            try:
                commands = json.loads(commands_text)
                if not isinstance(commands, list):
                    commands = [commands]
            except json.JSONDecodeError:
                commands = [c.strip() for c in commands_text.split('\n') if c.strip()]

            if not commands:
                flash('At least one command is required', 'danger')
                return redirect(request.url)

            # Create saved command
            saved_command = SavedCommand(
                name=name,
                description=description,
                vendor=vendor if vendor else None,
                created_by=current_user.id if current_user.is_authenticated else None
            )
            saved_command.set_commands_list(commands)

            db.session.add(saved_command)

            # Log creation
            audit_log = AuditLog(
                user_id=current_user.id if current_user.is_authenticated else None,
                action='saved_command_created',
                details=f'Created saved command: {name} with {len(commands)} command(s)',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()

            flash(f'Command "{name}" created successfully', 'success')
            return redirect(url_for('saved_items.list_commands'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating command: {str(e)}', 'danger')
            return redirect(request.url)

    vendors = ['all', 'cisco_ios', 'cisco_nxos', 'cisco_iosxr', 'cisco_asa', 'arista', 'juniper', 'paloalto', 'fortigate']
    return render_template('saved_items/create_command.html', vendors=vendors)

@saved_items_bp.route('/commands/<int:command_id>/edit', methods=['GET', 'POST'])
def edit_command(command_id):
    """Edit a saved command"""
    saved_command = SavedCommand.query.get_or_404(command_id)

    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            vendor = request.form.get('vendor', '').strip()
            commands_text = request.form.get('commands', '')

            if not name:
                flash('Name is required', 'danger')
                return redirect(request.url)

            # Parse commands
            try:
                commands = json.loads(commands_text)
                if not isinstance(commands, list):
                    commands = [commands]
            except json.JSONDecodeError:
                commands = [c.strip() for c in commands_text.split('\n') if c.strip()]

            if not commands:
                flash('At least one command is required', 'danger')
                return redirect(request.url)

            # Update command
            saved_command.name = name
            saved_command.description = description
            saved_command.vendor = vendor if vendor else None
            saved_command.set_commands_list(commands)
            saved_command.updated_at = datetime.utcnow()

            # Log update
            audit_log = AuditLog(
                user_id=current_user.id if current_user.is_authenticated else None,
                action='saved_command_updated',
                details=f'Updated saved command: {name}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()

            flash(f'Command "{name}" updated successfully', 'success')
            return redirect(url_for('saved_items.list_commands'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error updating command: {str(e)}', 'danger')
            return redirect(request.url)

    # Convert commands list to newline-separated text for editing
    commands_text = '\n'.join(saved_command.get_commands_list())

    vendors = ['all', 'cisco_ios', 'cisco_nxos', 'cisco_iosxr', 'cisco_asa', 'arista', 'juniper', 'paloalto', 'fortigate']
    return render_template('saved_items/edit_command.html',
                         saved_command=saved_command,
                         commands_text=commands_text,
                         vendors=vendors)

@saved_items_bp.route('/commands/<int:command_id>/delete', methods=['POST'])
def delete_command(command_id):
    """Delete a saved command"""
    saved_command = SavedCommand.query.get_or_404(command_id)
    name = saved_command.name

    try:
        # Log deletion
        audit_log = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action='saved_command_deleted',
            details=f'Deleted saved command: {name}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)

        db.session.delete(saved_command)
        db.session.commit()

        flash(f'Command "{name}" deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting command: {str(e)}', 'danger')

    return redirect(url_for('saved_items.list_commands'))

@saved_items_bp.route('/api/commands')
def get_all_commands():
    """Get all saved commands as JSON"""
    commands = SavedCommand.query.order_by(SavedCommand.updated_at.desc()).all()
    return jsonify([{
        'id': cmd.id,
        'name': cmd.name,
        'description': cmd.description,
        'vendor': cmd.vendor,
        'commands': cmd.get_commands_list(),
        'updated_at': cmd.updated_at.isoformat() if cmd.updated_at else None
    } for cmd in commands])

@saved_items_bp.route('/api/commands/<int:command_id>')
def get_command(command_id):
    """Get a saved command as JSON"""
    saved_command = SavedCommand.query.get_or_404(command_id)
    return jsonify({
        'id': saved_command.id,
        'name': saved_command.name,
        'description': saved_command.description,
        'vendor': saved_command.vendor,
        'commands': saved_command.get_commands_list()
    })

@saved_items_bp.route('/api/commands/<int:command_id>/update', methods=['POST', 'PUT'])
def update_command_api(command_id):
    """Update a command via API"""
    saved_command = SavedCommand.query.get_or_404(command_id)

    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        commands = data.get('commands', [])
        vendor = data.get('vendor', 'all')

        if not name:
            return jsonify({'success': False, 'error': 'Name is required'}), 400

        if not commands or not isinstance(commands, list):
            return jsonify({'success': False, 'error': 'Commands must be a non-empty list'}), 400

        saved_command.name = name
        saved_command.vendor = vendor if vendor else None
        saved_command.set_commands_list(commands)
        saved_command.updated_at = datetime.utcnow()

        audit_log = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action='saved_command_updated_api',
            details=f'Updated saved command via API: {name}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        return jsonify({'success': True, 'message': f'Command "{name}" updated'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@saved_items_bp.route('/api/commands/<int:command_id>/delete', methods=['POST', 'DELETE'])
def delete_command_api(command_id):
    """Delete a command via API"""
    saved_command = SavedCommand.query.get_or_404(command_id)

    name = saved_command.name
    try:
        audit_log = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action='saved_command_deleted_api',
            details=f'Deleted saved command via API: {name}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.delete(saved_command)
        db.session.commit()

        return jsonify({'success': True, 'message': f'Command "{name}" deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# ===== Quick save from command runner =====

@saved_items_bp.route('/api/quick-save-devices', methods=['POST'])
def quick_save_devices():
    """Quick save device list from command runner"""
    try:
        data = request.get_json()
        devices = data.get('devices', [])
        name = data.get('name', f'Device List {datetime.utcnow().strftime("%Y-%m-%d %H:%M")}')

        if not devices:
            return jsonify({'success': False, 'error': 'No devices provided'}), 400

        device_list = SavedDeviceList(
            name=name,
            description='Saved from command runner',
            created_by=current_user.id if current_user.is_authenticated else None
        )
        device_list.set_devices_list(devices)

        db.session.add(device_list)
        db.session.commit()

        return jsonify({
            'success': True,
            'id': device_list.id,
            'message': f'Saved {len(devices)} device(s)'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@saved_items_bp.route('/api/quick-save-commands', methods=['POST'])
def quick_save_commands():
    """Quick save commands from command runner"""
    try:
        data = request.get_json()
        commands = data.get('commands', [])
        name = data.get('name', f'Commands {datetime.utcnow().strftime("%Y-%m-%d %H:%M")}')
        vendor = data.get('vendor', 'all')

        if not commands:
            return jsonify({'success': False, 'error': 'No commands provided'}), 400

        saved_command = SavedCommand(
            name=name,
            description='Saved from command runner',
            vendor=vendor,
            created_by=current_user.id if current_user.is_authenticated else None
        )
        saved_command.set_commands_list(commands)

        db.session.add(saved_command)
        db.session.commit()

        return jsonify({
            'success': True,
            'id': saved_command.id,
            'message': f'Saved {len(commands)} command(s)'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
