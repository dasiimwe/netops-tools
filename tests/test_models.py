import pytest
from app import create_app
from app.models import db, User, Device, Interface, DeviceGroup
from cryptography.fernet import Fernet

@pytest.fixture
def app():
    """Create and configure a test app"""
    app = create_app('testing')
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['ENCRYPTION_KEY'] = Fernet.generate_key()
    
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    """Create a test client"""
    return app.test_client()

class TestUserModel:
    
    def test_create_user(self, app):
        """Test creating a user"""
        with app.app_context():
            user = User(username='testuser', auth_type='local')
            user.set_password('testpassword')
            
            db.session.add(user)
            db.session.commit()
            
            assert user.id is not None
            assert user.username == 'testuser'
            assert user.check_password('testpassword') is True
            assert user.check_password('wrongpassword') is False
    
    def test_password_hashing(self, app):
        """Test password hashing"""
        with app.app_context():
            user = User(username='testuser', auth_type='local')
            user.set_password('testpassword')
            
            # Password should be hashed
            assert user.password_hash is not None
            assert user.password_hash != 'testpassword'
            
            # Should be able to verify
            assert user.check_password('testpassword') is True

class TestDeviceModel:
    
    def test_create_device(self, app):
        """Test creating a device"""
        with app.app_context():
            device = Device(
                hostname='test-router',
                ip_address='192.168.1.1',
                vendor='cisco_ios'
            )

            db.session.add(device)
            db.session.commit()

            assert device.id is not None
            assert device.hostname == 'test-router'
            assert device.ip_address == '192.168.1.1'
            assert device.vendor == 'cisco_ios'
    
    def test_device_group_relationship(self, app):
        """Test device group creation (relationship removed)"""
        with app.app_context():
            # Create group
            group = DeviceGroup(name='Core Routers', description='Core network devices')
            db.session.add(group)
            db.session.commit()

            # Create device (no longer linked to group)
            device = Device(
                hostname='core-router-1',
                ip_address='10.0.0.1',
                vendor='cisco_ios'
            )

            db.session.add(device)
            db.session.commit()

            # Test that both objects exist independently
            assert group.id is not None
            assert device.id is not None
            assert group.name == 'Core Routers'

class TestInterfaceModel:
    
    def test_create_interface(self, app):
        """Test creating an interface"""
        with app.app_context():
            # Create device first
            device = Device(
                hostname='test-switch',
                ip_address='192.168.1.2',
                vendor='cisco_ios'
            )
            db.session.add(device)
            db.session.commit()
            
            # Create interface
            interface = Interface(
                device_id=device.id,
                name='GigabitEthernet0/1',
                description='Server connection',
                ipv4_address='10.1.1.1/24',
                status='up/up'
            )
            
            db.session.add(interface)
            db.session.commit()
            
            assert interface.id is not None
            assert interface.device == device
            assert interface.name == 'GigabitEthernet0/1'
    
    def test_interface_unique_constraint(self, app):
        """Test interface unique constraint"""
        with app.app_context():
            # Create device
            device = Device(
                hostname='test-device',
                ip_address='192.168.1.3',
                vendor='cisco_ios'
            )
            db.session.add(device)
            db.session.commit()
            
            # Create first interface
            interface1 = Interface(
                device_id=device.id,
                name='Gi0/1',
                ipv4_address='10.1.1.1/24'
            )
            db.session.add(interface1)
            db.session.commit()
            
            # Try to create duplicate interface
            interface2 = Interface(
                device_id=device.id,
                name='Gi0/1',  # Same name on same device
                ipv4_address='10.1.1.2/24'
            )
            db.session.add(interface2)
            
            # Should raise integrity error
            with pytest.raises(Exception):
                db.session.commit()