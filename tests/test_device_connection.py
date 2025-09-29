import pytest
import unittest.mock as mock
from app.device_connectors import get_connector, CiscoIOSConnector
from app.device_connectors.base_connector import BaseConnector

class TestDeviceConnectors:
    
    def test_get_connector_cisco_ios(self):
        """Test getting Cisco IOS connector"""
        connector = get_connector('cisco_ios', '192.168.1.1', 'admin', 'password')
        assert isinstance(connector, CiscoIOSConnector)
        assert connector.host == '192.168.1.1'
        assert connector.username == 'admin'
    
    def test_get_connector_invalid_vendor(self):
        """Test getting connector for invalid vendor"""
        with pytest.raises(ValueError) as exc_info:
            get_connector('invalid_vendor', '192.168.1.1', 'admin', 'password')
        assert 'Unsupported vendor' in str(exc_info.value)
    
    @mock.patch('app.device_connectors.base_connector.ConnectHandler')
    def test_cisco_ios_connection(self, mock_connect):
        """Test Cisco IOS connection"""
        # Mock the connection
        mock_connection = mock.MagicMock()
        mock_connect.return_value = mock_connection

        connector = CiscoIOSConnector('192.168.1.1', 'admin', 'password')
        result = connector.connect()

        assert result is True
        assert connector.connection is not None
        mock_connect.assert_called_once()
    
    def test_cisco_ios_interface_commands(self):
        """Test Cisco IOS interface commands"""
        connector = CiscoIOSConnector('192.168.1.1', 'admin', 'password')
        commands = connector.get_interface_commands()
        
        expected_commands = [
            'show interfaces description',
            'show ip interface brief',
            'show ipv6 interface brief'
        ]
        
        assert commands == expected_commands
    
    def test_cisco_ios_parse_interfaces(self):
        """Test Cisco IOS interface parsing"""
        connector = CiscoIOSConnector('192.168.1.1', 'admin', 'password')
        
        # Sample outputs
        desc_output = """Interface                      Status         Protocol Description
Gi0/0                          up             up       WAN Interface
Gi0/1                          down           down     LAN Interface"""
        
        ipv4_output = """Interface                  IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0         192.168.1.1     YES NVRAM  up                    up      
GigabitEthernet0/1         unassigned      YES NVRAM  administratively down down"""
        
        command_outputs = {
            'show interfaces description': desc_output,
            'show ip interface brief': ipv4_output,
            'show ipv6 interface brief': ''
        }
        
        interfaces = connector.parse_interfaces(command_outputs)

        # Parse interfaces returns all interfaces, but we need to filter for ones with IP addresses
        interfaces_with_ip = [
            intf for intf in interfaces
            if intf.get('ipv4_address') or intf.get('ipv6_address')
        ]

        # Should only have one interface with IP address
        assert len(interfaces_with_ip) == 1
        assert interfaces_with_ip[0]['name'] == 'GigabitEthernet0/0'
        assert interfaces_with_ip[0]['ipv4_address'] == '192.168.1.1'

class TestBaseConnector:
    
    def test_abstract_methods(self):
        """Test that BaseConnector cannot be instantiated directly"""
        with pytest.raises(TypeError):
            BaseConnector('192.168.1.1', 'admin', 'password')
    
    @mock.patch('app.device_connectors.base_connector.ConnectHandler')
    def test_retry_logic(self, mock_connect):
        """Test connection retry logic"""
        # First two attempts fail, third succeeds
        mock_connect.side_effect = [
            Exception('Connection failed'),
            Exception('Connection failed'),
            mock.MagicMock()
        ]

        connector = CiscoIOSConnector(
            '192.168.1.1', 'admin', 'password',
            retry_enabled=True, retry_count=3, retry_delay=0.1
        )

        result = connector.connect()
        assert result is True
        assert mock_connect.call_count == 3