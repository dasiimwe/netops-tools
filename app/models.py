from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import json

# SQLAlchemy instance will be initialized in __init__.py
db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=True)  # Null for TACACS users
    auth_type = db.Column(db.String(20), nullable=False, default='local')  # 'local' or 'tacacs'
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        if self.password_hash:
            return check_password_hash(self.password_hash, password)
        return False
    
    def __repr__(self):
        return f'<User {self.username}>'

class DeviceGroup(db.Model):
    __tablename__ = 'device_groups'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<DeviceGroup {self.name}>'

class Device(db.Model):
    __tablename__ = 'devices'

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), unique=True, nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)  # Supports IPv6
    vendor = db.Column(db.String(50), nullable=False)  # cisco_ios, cisco_nxos, cisco_iosxr, paloalto, fortigate
    is_reachable = db.Column(db.Boolean, default=True)
    last_reachability_check = db.Column(db.DateTime)
    last_successful_connection = db.Column(db.DateTime)
    last_error = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    interfaces = db.relationship('Interface', backref='device', lazy='dynamic', cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='device', lazy='dynamic')

    def __repr__(self):
        return f'<Device {self.hostname}>'

class Interface(db.Model):
    __tablename__ = 'interfaces'

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    ipv4_address = db.Column(db.String(18))  # xxx.xxx.xxx.xxx/xx
    ipv6_address = db.Column(db.String(45))  # Full IPv6 with prefix
    status = db.Column(db.String(20))  # up, down, administratively down
    source = db.Column(db.String(20), default='collected', nullable=False)  # 'collected' or 'manual'
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Create unique constraint on device_id and name
    __table_args__ = (
        db.UniqueConstraint('device_id', 'name', name='_device_interface_uc'),
    )
    
    def __repr__(self):
        return f'<Interface {self.name} on {self.device.hostname}>'

class Settings(db.Model):
    __tablename__ = 'settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    value_type = db.Column(db.String(20))  # string, int, bool, json
    description = db.Column(db.String(255))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @staticmethod
    def get_value(key, default=None):
        setting = Settings.query.filter_by(key=key).first()
        if setting:
            if setting.value_type == 'int':
                return int(setting.value)
            elif setting.value_type == 'bool':
                return setting.value.lower() == 'true'
            elif setting.value_type == 'json':
                return json.loads(setting.value)
            else:
                return setting.value
        return default
    
    @staticmethod
    def set_value(key, value, value_type='string', description=''):
        setting = Settings.query.filter_by(key=key).first()
        if not setting:
            setting = Settings(key=key, description=description)
        
        setting.value_type = value_type
        if value_type == 'json':
            setting.value = json.dumps(value)
        else:
            setting.value = str(value)
        
        db.session.add(setting)
        db.session.commit()
    
    def __repr__(self):
        return f'<Setting {self.key}={self.value}>'

class Credential(db.Model):
    __tablename__ = 'credentials'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255))
    username_encrypted = db.Column(db.Text, nullable=False)
    password_encrypted = db.Column(db.Text, nullable=False)
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Relationships
    creator = db.relationship('User', backref='created_credentials')
    
    def set_credentials(self, username, password, encryption_key):
        """Encrypt and store credentials"""
        if encryption_key:
            f = Fernet(encryption_key)
            self.username_encrypted = f.encrypt(username.encode()).decode()
            self.password_encrypted = f.encrypt(password.encode()).decode()
        else:
            # Fallback to plaintext if no encryption key (not recommended for production)
            self.username_encrypted = username
            self.password_encrypted = password
    
    def get_credentials(self, encryption_key):
        """Decrypt and return credentials"""
        if encryption_key:
            try:
                f = Fernet(encryption_key)
                username = f.decrypt(self.username_encrypted.encode()).decode()
                password = f.decrypt(self.password_encrypted.encode()).decode()
                return username, password
            except:
                # Fallback if decryption fails
                return self.username_encrypted, self.password_encrypted
        else:
            return self.username_encrypted, self.password_encrypted
    
    @staticmethod
    def get_default():
        """Get the default credential"""
        return Credential.query.filter_by(is_default=True).first()
    
    def set_as_default(self):
        """Set this credential as the default, removing default from others"""
        # Remove default flag from all other credentials
        Credential.query.update({Credential.is_default: False})
        # Set this credential as default
        self.is_default = True
        db.session.commit()
    
    def __repr__(self):
        return f'<Credential {self.name}>'

class SessionLog(db.Model):
    __tablename__ = 'session_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(36), nullable=False)  # UUID for grouping session events
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    event_type = db.Column(db.String(50), nullable=False)  # connection_start, connection_success, connection_failed, command_sent, command_response, disconnection
    command = db.Column(db.Text)  # Command sent (for command_sent events)
    response = db.Column(db.Text)  # Response received (for command_response events)
    error_message = db.Column(db.Text)  # Error details (for failed events)
    duration_ms = db.Column(db.Integer)  # Duration in milliseconds (for timed events)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Relationships
    device = db.relationship('Device', backref='session_logs')
    user = db.relationship('User', backref='session_logs')
    
    def __repr__(self):
        return f'<SessionLog {self.session_id} {self.event_type} at {self.timestamp}>'
    
    @staticmethod
    def log_event(session_id, device_id, user_id, event_type, **kwargs):
        """Helper method to create session log entries"""
        log_entry = SessionLog(
            session_id=session_id,
            device_id=device_id,
            user_id=user_id,
            event_type=event_type,
            command=kwargs.get('command'),
            response=kwargs.get('response'),
            error_message=kwargs.get('error_message'),
            duration_ms=kwargs.get('duration_ms')
        )
        db.session.add(log_entry)
        return log_entry

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    device_id = db.Column(db.Integer, db.ForeignKey('devices.id'))
    action = db.Column(db.String(100), nullable=False)  # login, logout, device_access, config_change
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<AuditLog {self.action} at {self.timestamp}>'