from .cisco_ios import CiscoIOSConnector
from .cisco_nxos import CiscoNXOSConnector
from .cisco_iosxr import CiscoIOSXRConnector
from .cisco_asa import CiscoASAConnector
from .arista import AristaConnector
from .juniper import JuniperConnector
from .paloalto import PaloAltoConnector
from .fortigate import FortiGateConnector
from .base_connector import BaseConnector

# Vendor mapping for easy lookup
VENDOR_MAPPING = {
    'cisco_ios': CiscoIOSConnector,
    'cisco_nxos': CiscoNXOSConnector,
    'cisco_iosxr': CiscoIOSXRConnector,
    'cisco_asa': CiscoASAConnector,
    'arista': AristaConnector,
    'juniper': JuniperConnector,
    'paloalto': PaloAltoConnector,
    'fortigate': FortiGateConnector,
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
    'CiscoASAConnector',
    'AristaConnector',
    'JuniperConnector',
    'PaloAltoConnector',
    'FortiGateConnector',
    'get_connector',
    'VENDOR_MAPPING'
]