from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app.routes import credential_pool_bp
from app.models import db, CredentialPool, CredentialPoolMember, Credential, AuditLog
from datetime import datetime

@credential_pool_bp.route('/')
@login_required
def list_pools():
    """List all credential pools"""
    pools = CredentialPool.query.order_by(CredentialPool.name).all()
    return render_template('credential_pools/list.html', pools=pools)

@credential_pool_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_pool():
    """Add a new credential pool"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        is_default = request.form.get('is_default') == 'on'

        if not name:
            flash('Pool name is required', 'danger')
            return redirect(url_for('credential_pools.add_pool'))

        # Check if pool already exists
        existing = CredentialPool.query.filter_by(name=name).first()
        if existing:
            flash(f'Credential pool "{name}" already exists', 'danger')
            return redirect(url_for('credential_pools.add_pool'))

        try:
            # Create new pool
            pool = CredentialPool(
                name=name,
                description=description,
                created_by=current_user.id
            )

            db.session.add(pool)
            db.session.flush()  # Get the ID

            # Set as default if requested
            if is_default:
                pool.set_as_default()

            # Log creation
            audit_log = AuditLog(
                user_id=current_user.id,
                action='credential_pool_created',
                details=f'Created credential pool: {name}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()

            flash(f'Credential pool "{name}" created successfully', 'success')
            return redirect(url_for('credential_pools.edit_pool', pool_id=pool.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating credential pool: {str(e)}', 'danger')

    return render_template('credential_pools/add.html')

@credential_pool_bp.route('/<int:pool_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_pool(pool_id):
    """Edit credential pool and manage its members"""
    pool = CredentialPool.query.get_or_404(pool_id)

    if request.method == 'POST':
        # Update pool details (the template sends a simple form)
        pool.name = request.form.get('name', '').strip()
        pool.description = request.form.get('description', '').strip()
        is_default = request.form.get('is_default') == 'on'

        if not pool.name:
            flash('Pool name is required', 'danger')
            return redirect(url_for('credential_pools.edit_pool', pool_id=pool_id))

        try:
            if is_default and not pool.is_default:
                pool.set_as_default()
            elif not is_default and pool.is_default:
                pool.is_default = False

            pool.updated_at = datetime.utcnow()

            # Log update
            audit_log = AuditLog(
                user_id=current_user.id,
                action='credential_pool_updated',
                details=f'Updated credential pool: {pool.name}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()

            flash(f'Credential pool "{pool.name}" updated successfully', 'success')

        except Exception as e:
            db.session.rollback()
            flash(f'Error updating credential pool: {str(e)}', 'danger')

        return redirect(url_for('credential_pools.edit_pool', pool_id=pool_id))

    # Get available credentials not in this pool
    pool_credential_ids = [member.credential_id for member in pool.credentials]
    available_credentials = Credential.query.filter(
        ~Credential.id.in_(pool_credential_ids)
    ).order_by(Credential.name).all()

    # Get pool members ordered by their order
    pool_members = (db.session.query(CredentialPoolMember)
                   .filter_by(pool_id=pool.id)
                   .order_by(CredentialPoolMember.order)
                   .all())

    return render_template('credential_pools/edit.html',
                         pool=pool,
                         available_credentials=available_credentials,
                         pool_members=pool_members)

@credential_pool_bp.route('/<int:pool_id>/delete', methods=['POST'])
@login_required
def delete_pool(pool_id):
    """Delete a credential pool"""
    pool = CredentialPool.query.get_or_404(pool_id)
    pool_name = pool.name

    try:
        # Check if pool is assigned to any devices
        from app.models import DeviceCredentialAssignment
        assigned_devices = DeviceCredentialAssignment.query.filter_by(
            assignment_type='pool',
            credential_pool_id=pool_id
        ).count()

        if assigned_devices > 0:
            flash(f'Cannot delete credential pool "{pool_name}" - it is assigned to {assigned_devices} device(s)', 'danger')
            return redirect(url_for('credential_pools.list_pools'))

        # Log deletion
        audit_log = AuditLog(
            user_id=current_user.id,
            action='credential_pool_deleted',
            details=f'Deleted credential pool: {pool_name}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)

        # Delete pool (cascade will handle members)
        db.session.delete(pool)
        db.session.commit()

        flash(f'Credential pool "{pool_name}" deleted successfully', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting credential pool: {str(e)}', 'danger')

    return redirect(url_for('credential_pools.list_pools'))

@credential_pool_bp.route('/<int:pool_id>/set_default', methods=['POST'])
@login_required
def set_default(pool_id):
    """Set a credential pool as default"""
    pool = CredentialPool.query.get_or_404(pool_id)

    try:
        pool.set_as_default()

        # Log action
        audit_log = AuditLog(
            user_id=current_user.id,
            action='credential_pool_set_default',
            details=f'Set credential pool "{pool.name}" as default',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        flash(f'Credential pool "{pool.name}" set as default', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error setting default credential pool: {str(e)}', 'danger')

    return redirect(url_for('credential_pools.list_pools'))

@credential_pool_bp.route('/<int:pool_id>/members', methods=['POST'])
@login_required
def add_member(pool_id):
    """Add a credential to the pool via API"""
    pool = CredentialPool.query.get_or_404(pool_id)

    try:
        data = request.get_json()
        credential_id = data.get('credential_id')

        if not credential_id:
            return jsonify({'success': False, 'error': 'Credential ID is required'}), 400

        credential = Credential.query.get(credential_id)
        if not credential:
            return jsonify({'success': False, 'error': 'Credential not found'}), 404

        # Check if credential is already in pool
        existing = CredentialPoolMember.query.filter_by(
            pool_id=pool.id,
            credential_id=credential_id
        ).first()

        if existing:
            return jsonify({'success': False, 'error': f'Credential "{credential.name}" is already in this pool'}), 400

        # Get next order number
        max_order = db.session.query(db.func.max(CredentialPoolMember.order)).filter_by(pool_id=pool.id).scalar() or 0

        member = CredentialPoolMember(
            pool_id=pool.id,
            credential_id=credential_id,
            order=max_order + 1
        )
        db.session.add(member)

        # Log addition
        audit_log = AuditLog(
            user_id=current_user.id,
            action='credential_pool_member_added',
            details=f'Added credential "{credential.name}" to pool "{pool.name}"',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        return jsonify({'success': True, 'message': f'Added credential "{credential.name}" to pool'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@credential_pool_bp.route('/<int:pool_id>/members/<int:member_id>', methods=['DELETE'])
@login_required
def remove_member(pool_id, member_id):
    """Remove a credential from the pool via API"""
    pool = CredentialPool.query.get_or_404(pool_id)
    member = CredentialPoolMember.query.get_or_404(member_id)

    if member.pool_id != pool.id:
        return jsonify({'success': False, 'error': 'Member does not belong to this pool'}), 400

    try:
        credential_name = member.credential.name

        # Log removal
        audit_log = AuditLog(
            user_id=current_user.id,
            action='credential_pool_member_removed',
            details=f'Removed credential "{credential_name}" from pool "{pool.name}"',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)

        db.session.delete(member)
        db.session.commit()

        return jsonify({'success': True, 'message': f'Removed credential "{credential_name}" from pool'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@credential_pool_bp.route('/<int:pool_id>/members/<int:member_id>/reorder', methods=['POST'])
@login_required
def reorder_member(pool_id, member_id):
    """Reorder a credential in the pool via API"""
    pool = CredentialPool.query.get_or_404(pool_id)
    member = CredentialPoolMember.query.get_or_404(member_id)

    if member.pool_id != pool.id:
        return jsonify({'success': False, 'error': 'Member does not belong to this pool'}), 400

    try:
        data = request.get_json()
        direction = data.get('direction')

        if direction not in ['up', 'down']:
            return jsonify({'success': False, 'error': 'Direction must be "up" or "down"'}), 400

        current_order = member.order

        if direction == 'up':
            # Find member with order just above current
            target_member = CredentialPoolMember.query.filter(
                CredentialPoolMember.pool_id == pool.id,
                CredentialPoolMember.order < current_order
            ).order_by(CredentialPoolMember.order.desc()).first()

            if target_member:
                # Swap orders
                target_member.order, member.order = member.order, target_member.order
        else:  # down
            # Find member with order just below current
            target_member = CredentialPoolMember.query.filter(
                CredentialPoolMember.pool_id == pool.id,
                CredentialPoolMember.order > current_order
            ).order_by(CredentialPoolMember.order.asc()).first()

            if target_member:
                # Swap orders
                target_member.order, member.order = member.order, target_member.order

        # Log reorder
        audit_log = AuditLog(
            user_id=current_user.id,
            action='credential_pool_member_reordered',
            details=f'Moved credential "{member.credential.name}" {direction} in pool "{pool.name}"',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        return jsonify({'success': True, 'message': f'Moved credential {direction}'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@credential_pool_bp.route('/api/<int:pool_id>/test', methods=['POST'])
@login_required
def test_pool(pool_id):
    """Test credentials in a pool by trying to decrypt them"""
    pool = CredentialPool.query.get_or_404(pool_id)

    try:
        from flask import current_app
        encryption_key = current_app.config['ENCRYPTION_KEY']

        results = []
        for member in db.session.query(CredentialPoolMember).filter_by(pool_id=pool_id).order_by(CredentialPoolMember.order).all():
            credential = member.credential
            try:
                username, password = credential.get_credentials(encryption_key)
                results.append({
                    'credential_name': credential.name,
                    'order': member.order,
                    'status': 'success',
                    'username': username,
                    'message': 'Credentials decrypted successfully'
                })
            except Exception as e:
                results.append({
                    'credential_name': credential.name,
                    'order': member.order,
                    'status': 'error',
                    'message': f'Decryption failed: {str(e)}'
                })

        return jsonify({
            'success': True,
            'pool_name': pool.name,
            'results': results
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@credential_pool_bp.route('/usage-report')
@login_required
def usage_report():
    """Show credential and credential pool usage across devices"""
    from app.models import Device

    # Get all credential pools with their assignments
    pools = CredentialPool.query.order_by(CredentialPool.name).all()

    # Get all individual credentials with their assignments
    credentials = Credential.query.order_by(Credential.name).all()

    # Get devices without specific assignments (using default)
    devices_without_assignment = Device.query.filter(
        ~Device.id.in_(
            db.session.query(DeviceCredentialAssignment.device_id)
        )
    ).order_by(Device.hostname).all()

    # Get default credential pool
    default_pool = CredentialPool.get_default()
    default_credential = Credential.get_default()

    # Build pool usage data
    pool_usage = []
    for pool in pools:
        assignments = DeviceCredentialAssignment.query.filter_by(
            assignment_type='pool',
            credential_pool_id=pool.id
        ).all()

        assigned_devices = [assignment.device for assignment in assignments]

        pool_usage.append({
            'pool': pool,
            'assigned_devices': assigned_devices,
            'assignment_count': len(assigned_devices),
            'is_default': pool.is_default
        })

    # Build credential usage data
    credential_usage = []
    for credential in credentials:
        assignments = DeviceCredentialAssignment.query.filter_by(
            assignment_type='credential',
            credential_id=credential.id
        ).all()

        assigned_devices = [assignment.device for assignment in assignments]

        # Also check if this credential is in any pools that are assigned
        pool_assignments = DeviceCredentialAssignment.query.filter_by(
            assignment_type='pool'
        ).all()

        indirectly_assigned_devices = []
        for assignment in pool_assignments:
            if assignment.credential_pool and credential in assignment.credential_pool.get_credentials_list():
                indirectly_assigned_devices.append(assignment.device)

        credential_usage.append({
            'credential': credential,
            'directly_assigned_devices': assigned_devices,
            'indirectly_assigned_devices': indirectly_assigned_devices,
            'direct_assignment_count': len(assigned_devices),
            'indirect_assignment_count': len(indirectly_assigned_devices),
            'is_default': credential.is_default
        })

    # Statistics
    total_devices = Device.query.count()
    devices_with_specific_assignment = DeviceCredentialAssignment.query.count()
    devices_using_default = total_devices - devices_with_specific_assignment

    stats = {
        'total_devices': total_devices,
        'devices_with_specific_assignment': devices_with_specific_assignment,
        'devices_using_default': devices_using_default,
        'total_credential_pools': len(pools),
        'total_credentials': len(credentials),
        'default_pool': default_pool,
        'default_credential': default_credential
    }

    return render_template('credential_pools/usage_report.html',
                         pool_usage=pool_usage,
                         credential_usage=credential_usage,
                         devices_without_assignment=devices_without_assignment,
                         stats=stats)