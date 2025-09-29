from flask import render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from app.routes import settings_bp
from app.models import db, Settings, AuditLog
from app.auth import test_tacacs_connection

@settings_bp.route('/')
@login_required
def index():
    if not current_user.is_admin:
        flash('Admin access required', 'danger')
        return redirect(url_for('main.index'))
    
    # Get all settings
    settings = {
        'retry_enabled': Settings.get_value('retry_enabled', True),
        'retry_count': Settings.get_value('retry_count', 3),
        'retry_delay': Settings.get_value('retry_delay', 5),
        'connection_timeout': Settings.get_value('connection_timeout', 30),
        'command_timeout': Settings.get_value('command_timeout', 30),
        'max_concurrent': Settings.get_value('max_concurrent', 10),
        'tacacs_enabled': Settings.get_value('tacacs_enabled', False),
        'tacacs_server': Settings.get_value('tacacs_server', ''),
        'tacacs_port': Settings.get_value('tacacs_port', 49),
        'tacacs_timeout': Settings.get_value('tacacs_timeout', 10),
        'tacacs_secret': Settings.get_value('tacacs_secret', '')
    }
    
    return render_template('settings/index.html', settings=settings)

@settings_bp.route('/update', methods=['POST'])
@login_required
def update():
    if not current_user.is_admin:
        flash('Admin access required', 'danger')
        return redirect(url_for('main.index'))
    
    # Update connection settings
    Settings.set_value('retry_enabled', 
                      request.form.get('retry_enabled') == 'on',
                      'bool',
                      'Enable connection retry on failure')
    
    Settings.set_value('retry_count',
                      int(request.form.get('retry_count', 3)),
                      'int',
                      'Number of retry attempts')
    
    Settings.set_value('retry_delay',
                      int(request.form.get('retry_delay', 5)),
                      'int',
                      'Delay between retries (seconds)')
    
    Settings.set_value('connection_timeout',
                      int(request.form.get('connection_timeout', 30)),
                      'int',
                      'Connection timeout (seconds)')
    
    Settings.set_value('command_timeout',
                      int(request.form.get('command_timeout', 30)),
                      'int',
                      'Command timeout (seconds)')
    
    Settings.set_value('max_concurrent',
                      int(request.form.get('max_concurrent', 10)),
                      'int',
                      'Maximum concurrent connections for bulk operations')
    
    Settings.set_value('tacacs_enabled',
                      request.form.get('tacacs_enabled') == 'on',
                      'bool',
                      'Enable TACACS+ authentication')

    # Update TACACS+ settings
    Settings.set_value('tacacs_server',
                      request.form.get('tacacs_server', '').strip(),
                      'string',
                      'TACACS+ server hostname or IP address')

    Settings.set_value('tacacs_port',
                      int(request.form.get('tacacs_port', 49)),
                      'int',
                      'TACACS+ server port')

    Settings.set_value('tacacs_timeout',
                      int(request.form.get('tacacs_timeout', 10)),
                      'int',
                      'TACACS+ connection timeout (seconds)')

    # Store TACACS+ secret securely (encrypt if needed)
    tacacs_secret = request.form.get('tacacs_secret', '').strip()
    if tacacs_secret:  # Only update if a value is provided
        Settings.set_value('tacacs_secret',
                          tacacs_secret,
                          'string',
                          'TACACS+ shared secret key')

    # Log settings update
    audit_log = AuditLog(
        user_id=current_user.id,
        action='settings_updated',
        details='Application settings updated',
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()
    
    flash('Settings updated successfully', 'success')
    return redirect(url_for('settings.index'))

@settings_bp.route('/test_tacacs', methods=['POST'])
@login_required
def test_tacacs():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Admin access required'}), 403
    
    if test_tacacs_connection():
        return jsonify({'success': True, 'message': 'TACACS+ server connection successful'})
    else:
        return jsonify({'success': False, 'message': 'Failed to connect to TACACS+ server'})

@settings_bp.route('/audit_logs')
@login_required
def audit_logs():
    if not current_user.is_admin:
        flash('Admin access required', 'danger')
        return redirect(url_for('main.index'))
    
    page = request.args.get('page', 1, type=int)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    
    return render_template('settings/audit_logs.html', logs=logs)