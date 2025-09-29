from .local_auth import authenticate_local, create_local_user, update_local_password, validate_password_strength
from .tacacs_auth import authenticate_tacacs, test_tacacs_connection, sync_tacacs_groups

def authenticate_user(username: str, password: str, auth_type: str = 'local'):
    """Main authentication function that routes to appropriate auth method"""
    if auth_type == 'tacacs':
        return authenticate_tacacs(username, password)
    else:
        return authenticate_local(username, password)

__all__ = [
    'authenticate_user',
    'authenticate_local',
    'authenticate_tacacs',
    'create_local_user',
    'update_local_password',
    'validate_password_strength',
    'test_tacacs_connection',
    'sync_tacacs_groups'
]