import re
import time
from typing import Dict, List
from .base_connector import BaseConnector
import logging

logger = logging.getLogger(__name__)

class AristaConnector(BaseConnector):
    """Connector for Arista EOS devices"""

    def get_netmiko_device_type(self) -> str:
        return 'arista_eos'

    def get_interface_commands(self) -> List[str]:
        return [
            'show interfaces description',
            'show ip interface brief',
            'show ipv6 interface brief'
        ]

    def parse_interfaces(self, command_outputs: Dict[str, str], progress_callback=None) -> List[Dict]:
        interfaces = {}

        # Parse interface descriptions
        desc_output = command_outputs.get('show interfaces description', '')
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

        # Parse IPv4 addresses
        ipv4_output = command_outputs.get('show ip interface brief', '')
        # Arista format: Interface         IP Address         Status     Protocol         MTU
        ipv4_pattern = r'^(\S+)\s+([\d.]+/\d+|unassigned)\s+(\S+)\s+(\S+)'

        for line in ipv4_output.split('\n'):
            match = re.match(ipv4_pattern, line.strip())
            if match:
                intf_name = match.group(1)
                ip_address = match.group(2)
                status = match.group(3)
                protocol = match.group(4)

                if ip_address != 'unassigned':
                    if intf_name not in interfaces:
                        interfaces[intf_name] = {
                            'name': intf_name,
                            'description': '',
                            'status': f"{status}/{protocol}"
                        }
                    interfaces[intf_name]['ipv4_address'] = ip_address

        # Parse IPv6 addresses
        ipv6_output = command_outputs.get('show ipv6 interface brief', '')
        # Arista IPv6 format is similar to Cisco
        for line in ipv6_output.split('\n'):
            line = line.strip()
            if not line:
                continue

            # Match lines like: Ethernet1  2001:db8::1/64  up/up
            ipv6_intf_pattern = r'^(\S+)\s+([0-9A-Fa-f:]+/\d+)\s+(\S+/\S+)'
            match = re.match(ipv6_intf_pattern, line)
            if match:
                intf_name = match.group(1)
                ipv6_addr = match.group(2)
                status = match.group(3)

                # Skip link-local addresses
                if not ipv6_addr.upper().startswith('FE80'):
                    if intf_name not in interfaces:
                        interfaces[intf_name] = {
                            'name': intf_name,
                            'description': '',
                            'status': status
                        }
                    interfaces[intf_name]['ipv6_address'] = ipv6_addr

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
                command = f"show running-config interfaces {intf_name}"
                self._log_session_event('command_sent', command=command)

                output = self.connection.send_command(command, strip_prompt=False, strip_command=False)
                time.sleep(1)

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
                # Keep the original description from 'show interfaces description'
                continue

    def _parse_description_from_config(self, config_output: str) -> str:
        """Parse interface description from running-config output"""
        description_pattern = r'^\s*description\s+(.+)$'

        for line in config_output.split('\n'):
            match = re.match(description_pattern, line, re.IGNORECASE)
            if match:
                return match.group(1).strip()

        return ""
