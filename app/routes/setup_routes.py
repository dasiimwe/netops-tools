import os
import secrets
from flask import render_template, request, flash, redirect, url_for, jsonify, current_app
from app.routes import setup_bp
from app.models import db, User, Settings
from app.auth import create_local_user, validate_password_strength
from cryptography.fernet import Fernet
import logging

logger = logging.getLogger(__name__)

def is_setup_complete():
    """Check if the application setup is complete"""
    try:
        # Check if .env file exists and has required keys
        env_path = os.path.join(os.path.dirname(current_app.root_path), '.env')
        if not os.path.exists(env_path):
            return False

        # Read .env and check for required keys
        with open(env_path, 'r') as f:
            env_content = f.read()
            required_keys = ['SECRET_KEY', 'ENCRYPTION_KEY']
            for key in required_keys:
                if f'{key}=' not in env_content or f'{key}=\n' in env_content or f'{key}=' in env_content.split('\n')[-1]:
                    # Key is empty or missing
                    return False

        # Check if admin user exists
        admin_user = User.query.filter_by(is_admin=True, is_active=True).first()
        if not admin_user:
            return False

        return True
    except Exception as e:
        logger.error(f"Error checking setup completion: {e}")
        return False

@setup_bp.route('/')
def index():
    """Initial setup page"""
    if is_setup_complete():
        flash('Setup is already complete. You can access the application normally.', 'info')
        return redirect(url_for('main.index'))

    # Get current setup status
    setup_status = {
        'env_file_exists': os.path.exists(os.path.join(os.path.dirname(current_app.root_path), '.env')),
        'has_admin_user': User.query.filter_by(is_admin=True, is_active=True).first() is not None,
        'has_encryption_key': False,
        'has_secret_key': False
    }

    # Check if .env has required keys
    env_path = os.path.join(os.path.dirname(current_app.root_path), '.env')
    if setup_status['env_file_exists']:
        try:
            with open(env_path, 'r') as f:
                env_content = f.read()
                setup_status['has_secret_key'] = 'SECRET_KEY=' in env_content and len([line for line in env_content.split('\n') if line.startswith('SECRET_KEY=') and '=' in line and line.split('=', 1)[1].strip()]) > 0
                setup_status['has_encryption_key'] = 'ENCRYPTION_KEY=' in env_content and len([line for line in env_content.split('\n') if line.startswith('ENCRYPTION_KEY=') and '=' in line and line.split('=', 1)[1].strip()]) > 0
        except Exception as e:
            logger.error(f"Error reading .env file: {e}")

    return render_template('setup/index.html', setup_status=setup_status)

@setup_bp.route('/generate-env', methods=['POST'])
def generate_env():
    """Generate or update .env file with encryption keys"""
    try:
        env_path = os.path.join(os.path.dirname(current_app.root_path), '.env')
        env_example_path = os.path.join(os.path.dirname(current_app.root_path), '.env.example')

        # Generate new keys
        secret_key = secrets.token_urlsafe(32)
        encryption_key = Fernet.generate_key().decode()

        # Read .env.example as template
        if os.path.exists(env_example_path):
            with open(env_example_path, 'r') as f:
                env_content = f.read()
        else:
            # Fallback template if .env.example doesn't exist
            env_content = """# Flask Configuration
FLASK_ENV=development
SECRET_KEY=your-secret-key-here-change-in-production

# Database
DATABASE_URL=sqlite:///network_devices.db

# Device Connection Settings
DEVICE_CONNECTION_TIMEOUT=30
DEVICE_COMMAND_TIMEOUT=30
DEVICE_RETRY_ENABLED=true
DEVICE_RETRY_COUNT=3
DEVICE_RETRY_DELAY=5

# Encryption Key for Device Credentials
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ENCRYPTION_KEY=

# TACACS+ Configuration (optional)
TACACS_SERVER=
TACACS_PORT=49
TACACS_SECRET=
TACACS_TIMEOUT=10

# Bulk Operations
MAX_CONCURRENT_CONNECTIONS=10

# Logging
LOG_LEVEL=INFO
LOG_FILE=app.log
"""

        # Update the keys in the content
        lines = env_content.split('\n')
        updated_lines = []

        for line in lines:
            if line.startswith('SECRET_KEY='):
                updated_lines.append(f'SECRET_KEY={secret_key}')
            elif line.startswith('ENCRYPTION_KEY='):
                updated_lines.append(f'ENCRYPTION_KEY={encryption_key}')
            else:
                updated_lines.append(line)

        # Write the updated .env file
        with open(env_path, 'w') as f:
            f.write('\n'.join(updated_lines))

        logger.info("Generated new .env file with encryption keys")
        return jsonify({
            'success': True,
            'message': 'Environment file generated successfully with new encryption keys!'
        })

    except Exception as e:
        logger.error(f"Error generating .env file: {e}")
        return jsonify({
            'success': False,
            'message': f'Error generating environment file: {str(e)}'
        }), 500

@setup_bp.route('/create-admin', methods=['POST'])
def create_admin():
    """Create the initial admin user"""
    try:
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validation
        if not username:
            return jsonify({
                'success': False,
                'message': 'Username is required'
            }), 400

        if not email:
            return jsonify({
                'success': False,
                'message': 'Email is required'
            }), 400

        if not password:
            return jsonify({
                'success': False,
                'message': 'Password is required'
            }), 400

        if password != confirm_password:
            return jsonify({
                'success': False,
                'message': 'Passwords do not match'
            }), 400

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({
                'success': False,
                'message': f'User {username} already exists'
            }), 400

        # Validate password strength
        is_valid, errors = validate_password_strength(password)
        if not is_valid:
            return jsonify({
                'success': False,
                'message': 'Password does not meet complexity requirements: ' + ', '.join(errors)
            }), 400

        # Create admin user
        admin_user = create_local_user(
            username=username,
            email=email,
            password=password,
            is_admin=True
        )

        logger.info(f"Created initial admin user: {username}")
        return jsonify({
            'success': True,
            'message': f'Admin user {username} created successfully!'
        })

    except Exception as e:
        logger.error(f"Error creating admin user: {e}")
        return jsonify({
            'success': False,
            'message': f'Error creating admin user: {str(e)}'
        }), 500

@setup_bp.route('/complete')
def complete():
    """Complete setup and redirect to login"""
    if not is_setup_complete():
        flash('Setup is not yet complete. Please finish all setup steps.', 'warning')
        return redirect(url_for('setup.index'))

    flash('Setup completed successfully! You can now log in with your admin account.', 'success')
    return redirect(url_for('auth.login'))

@setup_bp.route('/status')
def status():
    """Get current setup status as JSON"""
    setup_status = {
        'env_file_exists': os.path.exists(os.path.join(os.path.dirname(current_app.root_path), '.env')),
        'has_admin_user': User.query.filter_by(is_admin=True, is_active=True).first() is not None,
        'has_encryption_key': False,
        'has_secret_key': False,
        'setup_complete': False
    }

    # Check if .env has required keys
    env_path = os.path.join(os.path.dirname(current_app.root_path), '.env')
    if setup_status['env_file_exists']:
        try:
            with open(env_path, 'r') as f:
                env_content = f.read()
                setup_status['has_secret_key'] = 'SECRET_KEY=' in env_content and len([line for line in env_content.split('\n') if line.startswith('SECRET_KEY=') and '=' in line and line.split('=', 1)[1].strip()]) > 0
                setup_status['has_encryption_key'] = 'ENCRYPTION_KEY=' in env_content and len([line for line in env_content.split('\n') if line.startswith('ENCRYPTION_KEY=') and '=' in line and line.split('=', 1)[1].strip()]) > 0
        except Exception as e:
            logger.error(f"Error reading .env file: {e}")

    setup_status['setup_complete'] = is_setup_complete()

    return jsonify(setup_status)