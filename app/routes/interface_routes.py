from flask import render_template, request, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user
from app.routes import interface_bp
from app.models import db, Device, Interface, AuditLog
from sqlalchemy import or_
from datetime import datetime

@interface_bp.route('/')
@login_required
def list_interfaces():
    # Get filter parameters
    device_id = request.args.get('device_id')
    search = request.args.get('search')
    status = request.args.get('status')
    has_ipv4 = request.args.get('has_ipv4')
    has_ipv6 = request.args.get('has_ipv6')
    
    # Build query
    query = Interface.query.join(Device)
    
    if device_id:
        query = query.filter(Interface.device_id == device_id)
    
    if search:
        query = query.filter(or_(
            Interface.name.contains(search),
            Interface.description.contains(search),
            Interface.ipv4_address.contains(search),
            Interface.ipv6_address.contains(search),
            Device.hostname.contains(search)
        ))
    
    if status:
        query = query.filter(Interface.status == status)
    
    if has_ipv4 == 'yes':
        query = query.filter(Interface.ipv4_address.isnot(None))
    elif has_ipv4 == 'no':
        query = query.filter(Interface.ipv4_address.is_(None))
    
    if has_ipv6 == 'yes':
        query = query.filter(Interface.ipv6_address.isnot(None))
    elif has_ipv6 == 'no':
        query = query.filter(Interface.ipv6_address.is_(None))
    
    interfaces = query.all()
    devices = Device.query.all()
    
    return render_template('interfaces/list.html', 
                         interfaces=interfaces, 
                         devices=devices,
                         filters={
                             'device_id': device_id,
                             'search': search,
                             'status': status,
                             'has_ipv4': has_ipv4,
                             'has_ipv6': has_ipv6
                         })

@interface_bp.route('/device/<int:device_id>')
@login_required
def device_interfaces(device_id):
    device = Device.query.get_or_404(device_id)
    interfaces = Interface.query.filter_by(device_id=device_id).all()
    
    return render_template('interfaces/device.html', 
                         device=device, 
                         interfaces=interfaces)

@interface_bp.route('/api/summary')
@login_required
def api_summary():
    """API endpoint for interface summary statistics"""
    
    total_interfaces = Interface.query.count()
    ipv4_interfaces = Interface.query.filter(Interface.ipv4_address.isnot(None)).count()
    ipv6_interfaces = Interface.query.filter(Interface.ipv6_address.isnot(None)).count()
    
    # Count by status
    status_counts = db.session.query(
        Interface.status, 
        db.func.count(Interface.id)
    ).group_by(Interface.status).all()
    
    # Count by device
    device_counts = db.session.query(
        Device.hostname,
        db.func.count(Interface.id)
    ).join(Interface).group_by(Device.hostname).all()
    
    return jsonify({
        'total': total_interfaces,
        'ipv4_count': ipv4_interfaces,
        'ipv6_count': ipv6_interfaces,
        'status_distribution': dict(status_counts),
        'device_distribution': dict(device_counts)
    })

@interface_bp.route('/api/export')
@login_required
def api_export():
    """Export interface data as JSON"""
    
    interfaces = Interface.query.join(Device).all()
    
    data = []
    for interface in interfaces:
        data.append({
            'device_hostname': interface.device.hostname,
            'device_ip': interface.device.ip_address,
            'device_vendor': interface.device.vendor,
            'interface_name': interface.name,
            'description': interface.description,
            'ipv4_address': interface.ipv4_address,
            'ipv6_address': interface.ipv6_address,
            'status': interface.status,
            'last_updated': interface.last_updated.isoformat() if interface.last_updated else None
        })
    
    return jsonify(data)

@interface_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_interface():
    """Manually add a new interface"""
    if request.method == 'POST':
        device_id = request.form.get('device_id')
        name = request.form.get('name')
        description = request.form.get('description', '')
        ipv4_address = request.form.get('ipv4_address', None)
        ipv6_address = request.form.get('ipv6_address', None)
        status = request.form.get('status', 'unknown')

        # Validate device exists
        device = Device.query.get(device_id)
        if not device:
            flash('Invalid device selected', 'danger')
            return redirect(url_for('interfaces.add_interface'))

        # Check if interface already exists for this device
        existing = Interface.query.filter_by(device_id=device_id, name=name).first()
        if existing:
            flash(f'Interface {name} already exists for device {device.hostname}', 'danger')
            return redirect(url_for('interfaces.add_interface'))

        # Create new interface
        interface = Interface(
            device_id=device_id,
            name=name,
            description=description,
            ipv4_address=ipv4_address if ipv4_address else None,
            ipv6_address=ipv6_address if ipv6_address else None,
            status=status,
            source='manual'
        )

        db.session.add(interface)

        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            device_id=device_id,
            action='interface_added_manually',
            details=f'Manually added interface {name} to {device.hostname}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)

        db.session.commit()

        flash(f'Interface {name} added successfully to {device.hostname}', 'success')
        return redirect(url_for('interfaces.device_interfaces', device_id=device_id))

    # GET request - show form
    devices = Device.query.order_by(Device.hostname).all()
    return render_template('interfaces/add.html', devices=devices)

@interface_bp.route('/<int:interface_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_interface(interface_id):
    """Edit an existing interface"""
    interface = Interface.query.get_or_404(interface_id)

    if request.method == 'POST':
        old_values = {
            'name': interface.name,
            'description': interface.description,
            'ipv4_address': interface.ipv4_address,
            'ipv6_address': interface.ipv6_address,
            'status': interface.status
        }

        interface.name = request.form.get('name')
        interface.description = request.form.get('description', '')
        interface.ipv4_address = request.form.get('ipv4_address') or None
        interface.ipv6_address = request.form.get('ipv6_address') or None
        interface.status = request.form.get('status', 'unknown')
        interface.last_updated = datetime.utcnow()

        # Log changes
        changes = []
        for field, old_value in old_values.items():
            new_value = getattr(interface, field)
            if old_value != new_value:
                changes.append(f'{field}: {old_value} → {new_value}')

        if changes:
            audit_log = AuditLog(
                user_id=current_user.id,
                device_id=interface.device_id,
                action='interface_edited',
                details=f'Edited interface {interface.name} on {interface.device.hostname}: {"; ".join(changes)}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)

        db.session.commit()

        flash(f'Interface {interface.name} updated successfully', 'success')
        return redirect(url_for('interfaces.device_interfaces', device_id=interface.device_id))

    # GET request - show form
    return render_template('interfaces/edit.html', interface=interface)

@interface_bp.route('/<int:interface_id>/delete', methods=['POST'])
@login_required
def delete_interface(interface_id):
    """Delete an interface"""
    interface = Interface.query.get_or_404(interface_id)
    device_id = interface.device_id
    interface_name = interface.name
    device_hostname = interface.device.hostname

    # Log deletion
    audit_log = AuditLog(
        user_id=current_user.id,
        device_id=device_id,
        action='interface_deleted',
        details=f'Deleted interface {interface_name} from {device_hostname}',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)

    db.session.delete(interface)
    db.session.commit()

    flash(f'Interface {interface_name} deleted successfully', 'success')
    return redirect(url_for('interfaces.device_interfaces', device_id=device_id))