try:
    from tacacs_plus.client import TACACSClient
    from tacacs_plus.flags import TAC_PLUS_AUTHEN_STATUS_PASS
    TACACS_AVAILABLE = True
except ImportError:
    TACACS_AVAILABLE = False
    TACACSClient = None
    TAC_PLUS_AUTHEN_STATUS_PASS = None

from app.models import db, User, Settings
from datetime import datetime
import logging
from flask import current_app

logger = logging.getLogger(__name__)

def authenticate_tacacs(username: str, password: str) -> User:
    """Authenticate user with TACACS+ server"""
    
    if not TACACS_AVAILABLE:
        logger.error("TACACS+ library not available")
        return None
    
    # Get TACACS configuration from database settings
    tacacs_server = Settings.get_value('tacacs_server', '')
    tacacs_port = Settings.get_value('tacacs_port', 49)
    tacacs_secret = Settings.get_value('tacacs_secret', '')
    tacacs_timeout = Settings.get_value('tacacs_timeout', 10)
    
    if not tacacs_server or not tacacs_secret:
        logger.error("TACACS+ server not configured")
        return None
    
    try:
        # Create TACACS client
        client = TACACSClient(
            tacacs_server,
            tacacs_port,
            tacacs_secret.encode('ascii'),
            timeout=tacacs_timeout
        )
        
        # Attempt authentication
        auth_result = client.authenticate(username, password)
        
        if auth_result.status == TAC_PLUS_AUTHEN_STATUS_PASS:
            logger.info(f"TACACS+ authentication successful for user: {username}")
            
            # Check if user exists in local database
            user = User.query.filter_by(username=username, auth_type='tacacs').first()
            
            if not user:
                # Create user entry for TACACS user
                user = User(
                    username=username,
                    auth_type='tacacs',
                    is_active=True
                )
                db.session.add(user)
            
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            return user
        
        else:
            logger.warning(f"TACACS+ authentication failed for user: {username}")
            return None
            
    except Exception as e:
        logger.error(f"TACACS+ authentication error for user {username}: {str(e)}")
        return None

def test_tacacs_connection() -> bool:
    """Test TACACS+ server connectivity"""
    if not TACACS_AVAILABLE:
        return False
        
    tacacs_server = Settings.get_value('tacacs_server', '')
    tacacs_port = Settings.get_value('tacacs_port', 49)
    tacacs_secret = Settings.get_value('tacacs_secret', '')
    tacacs_timeout = Settings.get_value('tacacs_timeout', 10)
    
    if not tacacs_server or not tacacs_secret:
        return False
    
    try:
        client = TACACSClient(
            tacacs_server,
            tacacs_port,
            tacacs_secret.encode('ascii'),
            timeout=tacacs_timeout
        )
        # Test with dummy credentials to check connectivity
        # This will fail authentication but confirm server is reachable
        client.authenticate('test_connection', 'test')
        return True
    except Exception as e:
        logger.error(f"TACACS+ connection test failed: {str(e)}")
        return False

def sync_tacacs_groups(username: str, groups: list) -> None:
    """Sync TACACS+ user groups with local database"""
    user = User.query.filter_by(username=username, auth_type='tacacs').first()
    if user:
        # Update admin status based on groups
        if 'admin' in groups or 'network-admin' in groups:
            user.is_admin = True
        else:
            user.is_admin = False
        db.session.commit()