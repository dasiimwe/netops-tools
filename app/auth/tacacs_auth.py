try:
    from tacacs_plus.client import TACACSClient
    from tacacs_plus.flags import TAC_PLUS_AUTHEN_STATUS_PASS, TAC_PLUS_AUTHEN_TYPE_ASCII
    TACACS_AVAILABLE = True
except ImportError:
    TACACS_AVAILABLE = False
    TACACSClient = None
    TAC_PLUS_AUTHEN_STATUS_PASS = None
    TAC_PLUS_AUTHEN_TYPE_ASCII = None

from app.models import db, User, Settings
from datetime import datetime
import logging
import socket
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
        # Ensure secret is a string (the library will encode it internally)
        if isinstance(tacacs_secret, bytes):
            tacacs_secret = tacacs_secret.decode('latin-1')

        # Create TACACS client
        client = TACACSClient(
            tacacs_server,
            tacacs_port,
            tacacs_secret,  # Pass as string, not bytes
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

def test_tacacs_connection(username: str = None, password: str = None) -> dict:
    """Test TACACS+ server connectivity with detailed debug information

    Args:
        username: Username for authentication test
        password: Password for authentication test

    Returns:
        dict with keys: success, message, debug_logs (list of debug messages)
    """
    debug_logs = []

    debug_logs.append("Starting TACACS+ connection test...")

    if not TACACS_AVAILABLE:
        debug_logs.append("ERROR: TACACS+ library not available - tacacs-plus package may not be installed")
        return {
            'success': False,
            'message': 'TACACS+ library not available',
            'debug_logs': debug_logs
        }

    debug_logs.append("TACACS+ library loaded successfully")

    # Get TACACS configuration from database settings
    tacacs_server = Settings.get_value('tacacs_server', '')
    tacacs_port = Settings.get_value('tacacs_port', 49)
    tacacs_secret = Settings.get_value('tacacs_secret', '')
    tacacs_timeout = Settings.get_value('tacacs_timeout', 10)

    debug_logs.append(f"Configuration - Server: {tacacs_server}, Port: {tacacs_port}, Timeout: {tacacs_timeout}s")
    debug_logs.append(f"Secret type from DB: {type(tacacs_secret).__name__}, Length: {len(tacacs_secret) if tacacs_secret else 0}")
    debug_logs.append(f"Secret repr: {repr(tacacs_secret)}")
    debug_logs.append(f"Secret first 20 chars: {str(tacacs_secret)[:20] if tacacs_secret else 'empty'}")

    # Check if secret is actually a string representation of bytes (e.g., "b'secret'")
    if isinstance(tacacs_secret, str) and tacacs_secret.startswith("b'") and tacacs_secret.endswith("'"):
        debug_logs.append(f"Secret appears to be stored as string representation of bytes")
        # Remove the b' prefix and ' suffix
        tacacs_secret = tacacs_secret[2:-1]
        debug_logs.append(f"Cleaned secret (removed b'' wrapper)")
    elif isinstance(tacacs_secret, str) and tacacs_secret.startswith('b"') and tacacs_secret.endswith('"'):
        debug_logs.append(f"Secret appears to be stored as string representation of bytes")
        # Remove the b" prefix and " suffix
        tacacs_secret = tacacs_secret[2:-1]
        debug_logs.append(f"Cleaned secret (removed b\"\" wrapper)")

    if not tacacs_server:
        debug_logs.append("ERROR: TACACS+ server not configured")
        return {
            'success': False,
            'message': 'TACACS+ server not configured',
            'debug_logs': debug_logs
        }

    if not tacacs_secret:
        debug_logs.append("ERROR: TACACS+ shared secret not configured")
        return {
            'success': False,
            'message': 'TACACS+ shared secret not configured',
            'debug_logs': debug_logs
        }

    if not username or not password:
        debug_logs.append("ERROR: Username and password required for test")
        return {
            'success': False,
            'message': 'Username and password required for connection test',
            'debug_logs': debug_logs
        }

    debug_logs.append(f"Testing authentication for user: {username}")

    try:
        debug_logs.append(f"Creating TACACS client connection to {tacacs_server}:{tacacs_port}")

        # Ensure secret is a string (the library will encode it internally)
        debug_logs.append(f"Secret type before client creation: {type(tacacs_secret).__name__}")
        if isinstance(tacacs_secret, bytes):
            tacacs_secret = tacacs_secret.decode('latin-1')
            debug_logs.append(f"Secret converted from bytes to str")

        debug_logs.append(f"Secret length: {len(tacacs_secret)}")

        client = TACACSClient(
            tacacs_server,
            tacacs_port,
            tacacs_secret,  # Pass as string, not bytes
            timeout=tacacs_timeout
        )

        debug_logs.append("TACACS client created successfully")
        debug_logs.append("Sending authentication request...")

        # Ensure username and password are strings (not bytes)
        if isinstance(username, bytes):
            username = username.decode('utf-8')
        if isinstance(password, bytes):
            password = password.decode('utf-8')

        debug_logs.append(f"Authenticating with username type: {type(username).__name__}, password type: {type(password).__name__}")

        # Attempt authentication with provided credentials
        try:
            # Explicitly pass parameters to avoid any ambiguity
            auth_result = client.authenticate(
                username=username,
                password=password,
                authen_type=TAC_PLUS_AUTHEN_TYPE_ASCII
            )
            debug_logs.append("Authentication call successful (no AttributeError)")
        except AttributeError as auth_err:
            debug_logs.append(f"ERROR during authenticate call: {str(auth_err)}")
            import traceback
            debug_logs.append(f"Full traceback: {traceback.format_exc()}")
            raise

        debug_logs.append(f"Authentication response received - Status: {auth_result.status}")
        debug_logs.append(f"Server message: {auth_result.server_msg if hasattr(auth_result, 'server_msg') else 'None'}")

        if auth_result.status == TAC_PLUS_AUTHEN_STATUS_PASS:
            debug_logs.append("SUCCESS: Authentication passed")
            logger.info(f"TACACS+ test connection successful for user: {username}")
            return {
                'success': True,
                'message': 'TACACS+ authentication successful',
                'debug_logs': debug_logs
            }
        else:
            debug_logs.append(f"Authentication failed - Status code: {auth_result.status}")
            debug_logs.append("Note: Server is reachable but credentials were rejected")
            logger.warning(f"TACACS+ test authentication failed for user: {username}")
            return {
                'success': False,
                'message': 'Authentication failed - invalid credentials (but server is reachable)',
                'debug_logs': debug_logs
            }

    except ConnectionRefusedError as e:
        debug_logs.append(f"ERROR: Connection refused - Server may not be running on {tacacs_server}:{tacacs_port}")
        logger.error(f"TACACS+ connection test failed: {str(e)}")
        return {
            'success': False,
            'message': 'Connection refused - check server address and port',
            'debug_logs': debug_logs
        }
    except ConnectionResetError as e:
        debug_logs.append(f"ERROR: Connection reset by peer")
        debug_logs.append(f"This usually means:")
        debug_logs.append(f"  - The shared secret is incorrect")
        debug_logs.append(f"  - The server doesn't recognize this client")
        debug_logs.append(f"  - The server rejected the authentication request")
        logger.error(f"TACACS+ connection test failed: {str(e)}")
        return {
            'success': False,
            'message': 'Connection reset by server - check shared secret configuration',
            'debug_logs': debug_logs
        }
    except (TimeoutError, socket.timeout) as e:
        debug_logs.append(f"ERROR: Connection timeout after {tacacs_timeout}s - Server may be unreachable")
        logger.error(f"TACACS+ connection test failed: {str(e)}")
        return {
            'success': False,
            'message': f'Connection timeout after {tacacs_timeout}s',
            'debug_logs': debug_logs
        }
    except AttributeError as e:
        debug_logs.append(f"ERROR: AttributeError: {str(e)}")
        debug_logs.append(f"This usually indicates a type mismatch in the TACACS+ library")
        debug_logs.append(f"tacacs_secret type: {type(tacacs_secret).__name__}")
        debug_logs.append(f"username type: {type(username).__name__}")
        debug_logs.append(f"password type: {type(password).__name__}")
        logger.error(f"TACACS+ connection test failed: {str(e)}")
        return {
            'success': False,
            'message': f'Configuration error: {str(e)}',
            'debug_logs': debug_logs
        }
    except Exception as e:
        import traceback
        debug_logs.append(f"ERROR: {type(e).__name__}: {str(e)}")
        debug_logs.append(f"Traceback: {traceback.format_exc()}")
        logger.error(f"TACACS+ connection test failed: {str(e)}")
        return {
            'success': False,
            'message': f'Connection test failed: {str(e)}',
            'debug_logs': debug_logs
        }

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