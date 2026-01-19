from typing import Dict, List
from .base_connector import BaseConnector


class GenericConnector(BaseConnector):
    """
    Generic connector using terminal_server device type.

    This connector is used as a fallback when:
    - The configured device type fails to connect
    - SSHDetect autodetect fails to identify the device type

    It provides basic SSH connectivity without device-specific features.
    Command execution works but interface parsing returns empty results.
    """

    def get_netmiko_device_type(self) -> str:
        return 'terminal_server'

    def get_interface_commands(self) -> List[str]:
        """Generic connector doesn't support interface discovery"""
        return []

    def parse_interfaces(self, command_outputs: Dict[str, str], progress_callback=None) -> List[Dict]:
        """Generic connector returns empty interface list"""
        return []
