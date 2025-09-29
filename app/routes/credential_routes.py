from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app.routes import credential_bp
from app.models import db, Credential, AuditLog
from datetime import datetime

@credential_bp.route('/')
@login_required
def list_credentials():
    credentials = Credential.query.all()
    return render_template('credentials/list.html', credentials=credentials)

@credential_bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_credential():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        username = request.form.get('username')
        password = request.form.get('password')
        is_default = request.form.get('is_default') == 'on'
        
        # Check if credential name already exists
        existing = Credential.query.filter_by(name=name).first()
        if existing:
            flash(f'Credential name "{name}" already exists', 'danger')
        else:
            try:
                from flask import current_app
                
                credential = Credential(
                    name=name,
                    description=description,
                    created_by=current_user.id
                )
                
                # Encrypt and store credentials
                credential.set_credentials(username, password, current_app.config['ENCRYPTION_KEY'])
                
                db.session.add(credential)
                db.session.commit()
                
                # Set as default if requested
                if is_default:
                    credential.set_as_default()
                
                # Log credential creation
                audit_log = AuditLog(
                    user_id=current_user.id,
                    action='credential_created',
                    details=f'Created credential: {name}',
                    ip_address=request.remote_addr
                )
                db.session.add(audit_log)
                db.session.commit()
                
                flash(f'Credential "{name}" created successfully', 'success')
                return redirect(url_for('credentials.list_credentials'))
                
            except Exception as e:
                db.session.rollback()
                flash(f'Error creating credential: {str(e)}', 'danger')
    
    return render_template('credentials/add.html')

@credential_bp.route('/<int:credential_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_credential(credential_id):
    credential = Credential.query.get_or_404(credential_id)
    
    if request.method == 'POST':
        credential.name = request.form.get('name')
        credential.description = request.form.get('description')
        is_default = request.form.get('is_default') == 'on'
        
        # Update password if provided
        new_username = request.form.get('username')
        new_password = request.form.get('password')
        if new_username and new_password:
            from flask import current_app
            credential.set_credentials(new_username, new_password, current_app.config['ENCRYPTION_KEY'])
        
        try:
            credential.updated_at = datetime.utcnow()
            db.session.commit()
            
            # Set as default if requested
            if is_default:
                credential.set_as_default()
            elif credential.is_default and not is_default:
                credential.is_default = False
                db.session.commit()
            
            # Log credential update
            audit_log = AuditLog(
                user_id=current_user.id,
                action='credential_updated',
                details=f'Updated credential: {credential.name}',
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()
            
            flash(f'Credential "{credential.name}" updated successfully', 'success')
            return redirect(url_for('credentials.list_credentials'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating credential: {str(e)}', 'danger')
    
    # Get decrypted credentials for display
    try:
        from flask import current_app
        username, password = credential.get_credentials(current_app.config['ENCRYPTION_KEY'])
    except:
        username, password = '', ''
    
    return render_template('credentials/edit.html', credential=credential, username=username)

@credential_bp.route('/<int:credential_id>/delete', methods=['POST'])
@login_required
def delete_credential(credential_id):
    credential = Credential.query.get_or_404(credential_id)
    
    # Prevent deletion of default credential if it's the only one
    if credential.is_default:
        total_credentials = Credential.query.count()
        if total_credentials <= 1:
            flash('Cannot delete the only credential', 'danger')
            return redirect(url_for('credentials.list_credentials'))
    
    name = credential.name
    
    try:
        # Log credential deletion
        audit_log = AuditLog(
            user_id=current_user.id,
            action='credential_deleted',
            details=f'Deleted credential: {name}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        
        db.session.delete(credential)
        db.session.commit()
        
        flash(f'Credential "{name}" deleted successfully', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting credential: {str(e)}', 'danger')
    
    return redirect(url_for('credentials.list_credentials'))

@credential_bp.route('/<int:credential_id>/set_default', methods=['POST'])
@login_required
def set_default_credential(credential_id):
    credential = Credential.query.get_or_404(credential_id)
    
    try:
        credential.set_as_default()
        
        # Log default credential change
        audit_log = AuditLog(
            user_id=current_user.id,
            action='credential_default_changed',
            details=f'Set default credential: {credential.name}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()
        
        flash(f'"{credential.name}" is now the default credential', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error setting default credential: {str(e)}', 'danger')
    
    return redirect(url_for('credentials.list_credentials'))

@credential_bp.route('/test/<int:credential_id>', methods=['POST'])
@login_required
def test_credential(credential_id):
    """Test credential connectivity (placeholder for future implementation)"""
    credential = Credential.query.get_or_404(credential_id)
    
    # TODO: Implement actual credential testing with a test device
    # For now, just return success if credential exists
    
    return jsonify({
        'success': True,
        'message': f'Credential "{credential.name}" is ready for use'
    })