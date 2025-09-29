from flask import Blueprint

# Create blueprints
auth_bp = Blueprint('auth', __name__)
device_bp = Blueprint('devices', __name__)
interface_bp = Blueprint('interfaces', __name__)
settings_bp = Blueprint('settings', __name__)
credential_bp = Blueprint('credentials', __name__)
main_bp = Blueprint('main', __name__)
session_logs_bp = Blueprint('session_logs', __name__)

# Import routes to register them
from . import auth_routes, device_routes, interface_routes, settings_routes, credential_routes, main_routes, session_logs_routes

__all__ = ['auth_bp', 'device_bp', 'interface_bp', 'settings_bp', 'credential_bp', 'main_bp', 'session_logs_bp']