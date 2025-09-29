from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
from config import config
import logging
from logging.handlers import RotatingFileHandler
import os
from cryptography.fernet import Fernet

# Import db from models to use the same instance
from app.models import db

migrate = Migrate()
login_manager = LoginManager()

def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    
    # Configure login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please login to access this page.'
    
    # Generate encryption key if not exists
    if not app.config.get('ENCRYPTION_KEY'):
        app.config['ENCRYPTION_KEY'] = Fernet.generate_key()
        # In production, save this to environment variable or secure storage
        print(f"Generated encryption key: {app.config['ENCRYPTION_KEY'].decode()}")
        print("Please save this key securely and set it as ENCRYPTION_KEY environment variable")
    elif isinstance(app.config['ENCRYPTION_KEY'], str):
        app.config['ENCRYPTION_KEY'] = app.config['ENCRYPTION_KEY'].encode()
    
    # Setup logging
    setup_logging(app)
    
    # Register blueprints
    from app.routes import auth_bp, device_bp, interface_bp, settings_bp, credential_bp, main_bp, session_logs_bp, setup_bp
    app.register_blueprint(setup_bp, url_prefix='/setup')
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(device_bp, url_prefix='/devices')
    app.register_blueprint(interface_bp, url_prefix='/interfaces')
    app.register_blueprint(settings_bp, url_prefix='/settings')
    app.register_blueprint(credential_bp, url_prefix='/credentials')
    app.register_blueprint(session_logs_bp, url_prefix='/session-logs')
    app.register_blueprint(main_bp)
    
    # User loader for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        from app.models import User
        return User.query.get(int(user_id))

    # Setup check - redirect to setup if not complete
    @app.before_request
    def check_setup():
        from flask import request, redirect, url_for
        from app.routes.setup_routes import is_setup_complete

        # Skip setup check for static files and setup routes
        if (request.endpoint and
            (request.endpoint.startswith('static') or
             request.endpoint.startswith('setup.'))):
            return None

        # Skip setup check for the main index page (IP translator)
        if request.endpoint == 'main.index':
            return None

        # Check if setup is complete
        try:
            if not is_setup_complete():
                return redirect(url_for('setup.index'))
        except Exception:
            # If we can't check setup status, allow normal operation
            pass

        return None

    # Database initialization is handled by init_db.py script

    return app

def setup_logging(app):
    """Setup application logging"""
    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        file_handler = RotatingFileHandler(
            f'logs/{app.config["LOG_FILE"]}',
            maxBytes=10240000,
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        
        log_level = getattr(logging, app.config['LOG_LEVEL'].upper(), logging.INFO)
        file_handler.setLevel(log_level)
        app.logger.addHandler(file_handler)
        
        app.logger.setLevel(log_level)
        app.logger.info('Network Device Manager startup')