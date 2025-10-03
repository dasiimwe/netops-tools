import re
from typing import Dict, List
from .base_connector import BaseConnector
import logging

logger = logging.getLogger(__name__)

class CiscoASAConnector(BaseConnector):
    """Connector for Cisco ASA Firewall devices"""

    def get_netmiko_device_type(self) -> str:
        return 'cisco_asa'

    def get_interface_commands(self) -> List[str]:
        return [
            'show interface description',
            'show interface ip brief',
            'show ipv6 interface brief'
        ]

    def parse_interfaces(self, command_outputs: Dict[str, str], progress_callback=None) -> List[Dict]:
        interfaces = {}

        # Parse interface descriptions
        desc_output = command_outputs.get('show interface description', '')
        desc_pattern = r'^(\S+)\s+(\S+)\s+(\S+)\s+(.*?)$'

        for line in desc_output.split('\n'):
            if line.strip() and not line.startswith('Interface'):
                match = re.match(desc_pattern, line.strip())
                if match:
                    intf_name = match.group(1)
                    status = match.group(2)
                    protocol = match.group(3)
                    description = match.group(4).strip() if match.group(4) else ''

                    interfaces[intf_name] = {
                        'name': intf_name,
                        'description': description,
                        'status': f"{status}/{protocol}",
                        'ipv4_address': None,
                        'ipv6_address': None
                    }

        # Parse IPv4 addresses (ASA uses 'show interface ip brief')
        ipv4_output = command_outputs.get('show interface ip brief', '')
        ipv4_pattern = r'^(\S+)\s+([\d.]+|unassigned)\s+\S+\s+\S+\s+(\S+)'

        for line in ipv4_output.split('\n'):
            match = re.match(ipv4_pattern, line.strip())
            if match:
                intf_name = match.group(1)
                ip_address = match.group(2)
                status = match.group(3)

                if ip_address != 'unassigned':
                    if intf_name not in interfaces:
                        interfaces[intf_name] = {
                            'name': intf_name,
                            'description': '',
                            'status': status
                        }
                    interfaces[intf_name]['ipv4_address'] = ip_address

        # Parse IPv6 addresses
        ipv6_output = command_outputs.get('show ipv6 interface brief', '')
        current_interface = None

        for line in ipv6_output.split('\n'):
            line = line.strip()
            if not line or line.startswith('['):
                continue

            # Check if this is an interface line
            if not line.startswith(' ') and not line.startswith('\t'):
                parts = line.split()
                if parts:
                    current_interface = parts[0]
                    if current_interface not in interfaces:
                        interfaces[current_interface] = {
                            'name': current_interface,
                            'description': '',
                            'status': 'unknown'
                        }

            # Check for IPv6 address
            elif current_interface:
                # Look for IPv6 address pattern
                ipv6_pattern = r'([0-9A-Fa-f:]+(?:/\d+)?)'
                match = re.search(ipv6_pattern, line)
                if match and not line.startswith('FE80'):  # Skip link-local addresses
                    ipv6_addr = match.group(1)
                    if 'ipv6_address' not in interfaces[current_interface] or not interfaces[current_interface].get('ipv6_address'):
                        interfaces[current_interface]['ipv6_address'] = ipv6_addr

        # Get running-config descriptions for each interface
        self._update_interface_descriptions_from_config(interfaces)

        return list(interfaces.values())

    def _update_interface_descriptions_from_config(self, interfaces: Dict[str, Dict]):
        """Update interface descriptions by querying running-config for each interface"""
        if not self.connection:
            logger.warning("No connection available to get running-config descriptions")
            return

        for intf_name, intf_data in interfaces.items():
            try:
                # Execute show running-config interface command
                command = f"show running-config interface {intf_name}"
                self._log_session_event('command_sent', command=command)

                output = self.connection.send_command(command, strip_prompt=False, strip_command=False)

                self._log_session_event('command_received',
                                      command=command,
                                      output=output,
                                      output_length=len(output))

                # Parse description from running config
                config_description = self._parse_description_from_config(output)
                if config_description:
                    intf_data['description'] = config_description
                    logger.debug(f"Updated description for {intf_name}: {config_description}")

            except Exception as e:
                logger.warning(f"Failed to get running-config for interface {intf_name}: {e}")
                # Keep the original description from 'show interface description'
                continue

    def _parse_description_from_config(self, config_output: str) -> str:
        """Parse interface description from running-config output"""
        description_pattern = r'^\s*description\s+(.+)$'

        for line in config_output.split('\n'):
            match = re.match(description_pattern, line, re.IGNORECASE)
            if match:
                return match.group(1).strip()

        return ""
