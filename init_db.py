#!/usr/bin/env python3
"""
Initialize the database with tables and default data
"""
import os
from app import create_app
from app.auth import create_local_user

def init_database():
    """Initialize the database with tables and default settings"""
    
    # Generate encryption key if not set
    if not os.getenv('ENCRYPTION_KEY'):
        from cryptography.fernet import Fernet
        key = Fernet.generate_key().decode()
        print(f"Generated encryption key: {key}")
        print("Please save this key securely and set it as ENCRYPTION_KEY environment variable")
        print("This key is required for encrypting device credentials.")
        # Set it temporarily for this session
        os.environ['ENCRYPTION_KEY'] = key
    
    # Create Flask app
    app = create_app('development')
    
    with app.app_context():
        # Import db here to get the initialized instance
        from app.models import db, Settings, User
        
        # Create all tables
        print("Creating database tables...")
        db.create_all()
        
        # Create default settings
        print("Setting up default configuration...")
        
        default_settings = [
            ('retry_enabled', 'true', 'bool', 'Enable connection retry on failure'),
            ('retry_count', '3', 'int', 'Number of retry attempts'),
            ('retry_delay', '5', 'int', 'Delay between retries (seconds)'),
            ('connection_timeout', '30', 'int', 'Connection timeout (seconds)'),
            ('command_timeout', '30', 'int', 'Command timeout (seconds)'),
            ('max_concurrent', '10', 'int', 'Maximum concurrent connections for bulk operations'),
            ('tacacs_enabled', 'false', 'bool', 'Enable TACACS+ authentication'),
        ]
        
        for key, value, value_type, description in default_settings:
            existing = Settings.query.filter_by(key=key).first()
            if not existing:
                Settings.set_value(key, value, value_type, description)
                print(f"  - Set {key} = {value}")
        
        # Check if admin user exists
        admin_user = User.query.filter_by(username='admin').first()
        
        if not admin_user:
            print("\nCreating default admin user...")
            try:
                create_local_user(
                    username='admin',
                    password='Admin@123',
                    email='admin@localhost',
                    is_admin=True
                )
                print("  - Username: admin")
                print("  - Password: Admin@123")
                print("  - Please change the default password after first login!")
            except Exception as e:
                print(f"  - Admin user may already exist or error: {e}")
        else:
            print("\nAdmin user already exists.")
        
        print("\nDatabase initialization complete!")

if __name__ == '__main__':
    init_database()