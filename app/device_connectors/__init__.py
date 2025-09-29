from .cisco_ios import CiscoIOSConnector
from .cisco_nxos import CiscoNXOSConnector
from .cisco_iosxr import CiscoIOSXRConnector
from .paloalto import PaloAltoConnector
from .fortigate import FortiGateConnector
from .base_connector import BaseConnector

# Vendor mapping for easy lookup
VENDOR_MAPPING = {
    'cisco_ios': CiscoIOSConnector,
    'cisco_nxos': CiscoNXOSConnector,
    'cisco_iosxr': CiscoIOSXRConnector,
    'paloalto': PaloAltoConnector,
    'fortigate': FortiGateConnector,
    # Future vendors can be added here
    # 'arista': AristaConnector,
    # 'juniper': JuniperConnector,
}

def get_connector(vendor: str, host: str, username: str, password: str, **kwargs) -> BaseConnector:
    """Factory function to get the appropriate connector for a vendor"""
    connector_class = VENDOR_MAPPING.get(vendor.lower())
    if not connector_class:
        raise ValueError(f"Unsupported vendor: {vendor}")
    
    return connector_class(host, username, password, **kwargs)

__all__ = [
    'BaseConnector',
    'CiscoIOSConnector',
    'CiscoNXOSConnector', 
    'CiscoIOSXRConnector',
    'PaloAltoConnector',
    'FortiGateConnector',
    'get_connector',
    'VENDOR_MAPPING'
]