from flask import render_template, request, flash, redirect, url_for, jsonify
from flask_login import login_required, current_user
from app.routes import settings_bp
from app.models import db, Settings, AuditLog, CredentialPool
from app.auth import test_tacacs_connection
import json

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
        'tacacs_secret': Settings.get_value('tacacs_secret', ''),
        # Password complexity settings
        'password_min_length': Settings.get_value('password_min_length', True),
        'password_require_uppercase': Settings.get_value('password_require_uppercase', True),
        'password_require_lowercase': Settings.get_value('password_require_lowercase', True),
        'password_require_number': Settings.get_value('password_require_number', True),
        'password_require_special': Settings.get_value('password_require_special', True),
        # Interface collection progress bar
        'show_interface_progress': Settings.get_value('show_interface_progress', True),
        # Tooltip theme
        'tooltip_theme': Settings.get_value('tooltip_theme', 'light'),
        # Default credential pool
        'default_credential_pool_id': Settings.get_value('default_credential_pool_id', None),
        # Tool visibility settings
        'tool_ip_translator': Settings.get_value('tool_ip_translator', True),
        'tool_command_runner': Settings.get_value('tool_command_runner', True),
        'tool_dns_lookup': Settings.get_value('tool_dns_lookup', True),
        'tool_traceroute': Settings.get_value('tool_traceroute', True),
        'tool_url_insights': Settings.get_value('tool_url_insights', True),
        'tool_tcp_handshake': Settings.get_value('tool_tcp_handshake', True),
        'tool_whoami': Settings.get_value('tool_whoami', True)
    }

    # Get credential pool data for template
    available_credential_pools = CredentialPool.query.order_by(CredentialPool.name).all()
    current_default_pool = CredentialPool.get_default()

    return render_template('settings/index.html',
                         settings=settings,
                         available_credential_pools=available_credential_pools,
                         current_default_pool=current_default_pool)

@settings_bp.route('/update', methods=['POST'])
@login_required
def update():
    if not current_user.is_admin:
        flash('Admin access required', 'danger')
        return redirect(url_for('main.index'))

    # Update connection settings (check form_id)
    if request.form.get('form_id') == 'connection':
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

    # Update password complexity settings (check form_id)
    if request.form.get('form_id') == 'password':
        Settings.set_value('password_min_length',
                          request.form.get('password_min_length') == 'on',
                          'bool',
                          'Require minimum 8 characters for passwords')

        Settings.set_value('password_require_uppercase',
                          request.form.get('password_require_uppercase') == 'on',
                          'bool',
                          'Require at least one uppercase letter in passwords')

        Settings.set_value('password_require_lowercase',
                          request.form.get('password_require_lowercase') == 'on',
                          'bool',
                          'Require at least one lowercase letter in passwords')

        Settings.set_value('password_require_number',
                          request.form.get('password_require_number') == 'on',
                          'bool',
                          'Require at least one number in passwords')

        Settings.set_value('password_require_special',
                          request.form.get('password_require_special') == 'on',
                          'bool',
                          'Require at least one special character in passwords')

    # Update TACACS+ settings (check form_id)
    if request.form.get('form_id') == 'tacacs':
        Settings.set_value('tacacs_enabled',
                          request.form.get('tacacs_enabled') == 'on',
                          'bool',
                          'Enable TACACS+ authentication')

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

    # Update UI settings (check form_id)
    if request.form.get('form_id') == 'ui_settings':
        Settings.set_value('show_interface_progress',
                          request.form.get('show_interface_progress') == 'on',
                          'bool',
                          'Show detailed progress bar during interface collection')

        Settings.set_value('tooltip_theme',
                          request.form.get('tooltip_theme', 'light'),
                          'string',
                          'IP Translator tooltip color theme')

    # Update tool visibility settings (check form_id)
    if request.form.get('form_id') == 'tool_visibility':
        Settings.set_value('tool_ip_translator',
                          request.form.get('tool_ip_translator') == 'on',
                          'bool',
                          'Show IP Translator tool on home page')

        Settings.set_value('tool_command_runner',
                          request.form.get('tool_command_runner') == 'on',
                          'bool',
                          'Show Command Run Tool on home page')

        Settings.set_value('tool_dns_lookup',
                          request.form.get('tool_dns_lookup') == 'on',
                          'bool',
                          'Show DNS Lookup tool on home page')

        Settings.set_value('tool_traceroute',
                          request.form.get('tool_traceroute') == 'on',
                          'bool',
                          'Show Traceroute tool on home page')

        Settings.set_value('tool_url_insights',
                          request.form.get('tool_url_insights') == 'on',
                          'bool',
                          'Show URL/App Insights tool on home page')

        Settings.set_value('tool_tcp_handshake',
                          request.form.get('tool_tcp_handshake') == 'on',
                          'bool',
                          'Show TCP Handshake tool on home page')

        Settings.set_value('tool_whoami',
                          request.form.get('tool_whoami') == 'on',
                          'bool',
                          'Show WhoAmI tool on home page')

    # Update default credential pool setting (check form_id)
    if request.form.get('form_id') == 'credentials':
        default_credential_pool_id = request.form.get('default_credential_pool_id')
        if default_credential_pool_id and default_credential_pool_id.strip():
            # Validate that the pool exists
            pool = CredentialPool.query.get(int(default_credential_pool_id))
            if pool:
                # Clear any existing default pool
                CredentialPool.query.filter_by(is_default=True).update({CredentialPool.is_default: False})
                # Set the new default pool
                pool.is_default = True
                Settings.set_value('default_credential_pool_id',
                                  int(default_credential_pool_id),
                                  'int',
                                  'Default credential pool for device authentication')
            else:
                flash('Selected credential pool not found', 'warning')
        else:
            # Clear default pool setting
            CredentialPool.query.filter_by(is_default=True).update({CredentialPool.is_default: False})
            Settings.set_value('default_credential_pool_id',
                              None,
                              'string',
                              'Default credential pool for device authentication')

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

@settings_bp.route('/api/command-rules', methods=['GET'])
@login_required
def get_command_rules():
    """Get current command validation rules"""
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Admin access required'}), 403

    # Get command rules from database or use defaults
    default_rules = {
        'safePrefixes': [
            'show ',
            'execute ping ',
            'execute traceroute ',
            'ping ',
            'traceroute ',
            'trace ',
            'get system ',
            'diagnose '
        ],
        'dangerousPatterns': [
            'delete',
            'remove',
            'erase',
            'format',
            'reload',
            'reboot',
            'shutdown',
            'clear',
            'reset',
            'write',
            'copy',
            'configure',
            'config',
            'exit',
            'quit',
            'end',
            'commit',
            'save'
        ],
        'standaloneCommands': [
            'uptime',
            'version',
            'date',
            'clock',
            'whoami',
            'pwd'
        ]
    }

    try:
        # Try to get rules from database
        rules_json = Settings.get_value('command_validation_rules', None)
        if rules_json:
            rules = json.loads(rules_json)
        else:
            rules = default_rules

        return jsonify({'success': True, 'rules': rules})

    except Exception as e:
        # Return default rules if there's an error
        return jsonify({'success': True, 'rules': default_rules})

@settings_bp.route('/api/command-rules', methods=['POST'])
@login_required
def save_command_rules():
    """Save command validation rules"""
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Admin access required'}), 403

    try:
        data = request.get_json()

        # Validate data structure
        if not isinstance(data, dict):
            return jsonify({'success': False, 'message': 'Invalid data format'}), 400

        required_keys = ['safePrefixes', 'dangerousPatterns', 'standaloneCommands']
        for key in required_keys:
            if key not in data or not isinstance(data[key], list):
                return jsonify({'success': False, 'message': f'Missing or invalid {key}'}), 400

        # Save rules to database
        Settings.set_value('command_validation_rules',
                          json.dumps(data),
                          'json',
                          'Command validation rules for Command Run Tool')

        # Log the change
        audit_log = AuditLog(
            user_id=current_user.id,
            action='command_rules_updated',
            details=f'Command validation rules updated. Safe prefixes: {len(data["safePrefixes"])}, '
                   f'Dangerous patterns: {len(data["dangerousPatterns"])}, '
                   f'Standalone commands: {len(data["standaloneCommands"])}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        return jsonify({'success': True, 'message': 'Command rules saved successfully'})

    except Exception as e:
        return jsonify({'success': False, 'message': f'Error saving rules: {str(e)}'}), 500