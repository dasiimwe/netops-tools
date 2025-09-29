import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'network_devices.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session settings
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Device connection settings
    DEVICE_CONNECTION_TIMEOUT = int(os.environ.get('DEVICE_CONNECTION_TIMEOUT', 30))
    DEVICE_COMMAND_TIMEOUT = int(os.environ.get('DEVICE_COMMAND_TIMEOUT', 30))
    DEVICE_RETRY_ENABLED = os.environ.get('DEVICE_RETRY_ENABLED', 'true').lower() == 'true'
    DEVICE_RETRY_COUNT = int(os.environ.get('DEVICE_RETRY_COUNT', 3))
    DEVICE_RETRY_DELAY = int(os.environ.get('DEVICE_RETRY_DELAY', 5))
    
    # TACACS settings
    TACACS_SERVER = os.environ.get('TACACS_SERVER', '')
    TACACS_PORT = int(os.environ.get('TACACS_PORT', 49))
    TACACS_SECRET = os.environ.get('TACACS_SECRET', '')
    TACACS_TIMEOUT = int(os.environ.get('TACACS_TIMEOUT', 10))
    
    # Encryption key for device credentials
    ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY')
    
    # Bulk operations
    MAX_CONCURRENT_CONNECTIONS = int(os.environ.get('MAX_CONCURRENT_CONNECTIONS', 10))
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'app.log')

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}