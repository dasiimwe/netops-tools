import re
import time
from typing import Dict, List
from .base_connector import BaseConnector
import logging

logger = logging.getLogger(__name__)

class JuniperConnector(BaseConnector):
    """Connector for Juniper JunOS devices"""

    def get_netmiko_device_type(self) -> str:
        return 'juniper_junos'

    def get_interface_commands(self) -> List[str]:
        return [
            'show interfaces descriptions',
            'show interfaces terse'
        ]

    def parse_interfaces(self, command_outputs: Dict[str, str], progress_callback=None) -> List[Dict]:
        interfaces = {}

        # Parse interface descriptions
        desc_output = command_outputs.get('show interfaces descriptions', '')
        # Juniper format: Interface       Admin Link Description
        desc_pattern = r'^(\S+)\s+(\S+)\s+(\S+)\s*(.*?)$'

        for line in desc_output.split('\n'):
            if line.strip() and not line.startswith('Interface'):
                match = re.match(desc_pattern, line.strip())
                if match:
                    intf_name = match.group(1)
                    admin_status = match.group(2)
                    link_status = match.group(3)
                    description = match.group(4).strip() if len(match.groups()) >= 4 and match.group(4) else ''

                    interfaces[intf_name] = {
                        'name': intf_name,
                        'description': description,
                        'status': f"{admin_status}/{link_status}",
                        'ipv4_address': None,
                        'ipv6_address': None
                    }

        # Parse interface IP addresses from 'show interfaces terse'
        terse_output = command_outputs.get('show interfaces terse', '')
        # Juniper terse format shows interface, admin, link, and protocol/address info
        # Example: ge-0/0/0.0    up    up   inet     192.168.1.1/24

        current_interface = None
        for line in terse_output.split('\n'):
            line = line.strip()
            if not line or line.startswith('Interface'):
                continue

            # Split line into parts
            parts = line.split()
            if not parts:
                continue

            # Check if this is a new interface line (starts with interface name)
            if not line.startswith(' ') and not line.startswith('\t'):
                if len(parts) >= 4:
                    intf_name = parts[0]
                    current_interface = intf_name

                    # Get admin and link status
                    admin_status = parts[1] if len(parts) > 1 else 'unknown'
                    link_status = parts[2] if len(parts) > 2 else 'unknown'

                    if intf_name not in interfaces:
                        interfaces[intf_name] = {
                            'name': intf_name,
                            'description': '',
                            'status': f"{admin_status}/{link_status}",
                            'ipv4_address': None,
                            'ipv6_address': None
                        }

                    # Check for IP address in the same line
                    if len(parts) >= 5:
                        protocol = parts[3]
                        address = parts[4]

                        if protocol == 'inet' and '.' in address:
                            interfaces[intf_name]['ipv4_address'] = address
                        elif protocol == 'inet6' and ':' in address:
                            # Skip link-local addresses
                            if not address.upper().startswith('FE80'):
                                interfaces[intf_name]['ipv6_address'] = address

        # Get detailed descriptions from configuration if available
        self._update_interface_descriptions_from_config(interfaces)

        return list(interfaces.values())

    def _update_interface_descriptions_from_config(self, interfaces: Dict[str, Dict]):
        """Update interface descriptions by querying configuration for each interface"""
        if not self.connection:
            logger.warning("No connection available to get configuration descriptions")
            return

        for intf_name, intf_data in interfaces.items():
            try:
                # Juniper uses a different command format
                # Extract base interface name (remove .0, .1 etc for logical units)
                base_intf = intf_name.split('.')[0]

                command = f"show configuration interfaces {base_intf} | display set | match description"
                self._log_session_event('command_sent', command=command)

                output = self.connection.send_command(command, strip_prompt=False, strip_command=False)
                time.sleep(1)

                self._log_session_event('command_received',
                                      command=command,
                                      output=output,
                                      output_length=len(output))

                # Parse description from config output
                config_description = self._parse_description_from_config(output, intf_name)
                if config_description:
                    intf_data['description'] = config_description
                    logger.debug(f"Updated description for {intf_name}: {config_description}")

            except Exception as e:
                logger.warning(f"Failed to get configuration for interface {intf_name}: {e}")
                continue

    def _parse_description_from_config(self, config_output: str, intf_name: str) -> str:
        """Parse interface description from Juniper configuration output"""
        # Juniper format: set interfaces ge-0/0/0 description "Interface Description"
        # or: set interfaces ge-0/0/0 unit 0 description "Description"

        # Try to match the specific interface with or without unit
        for line in config_output.split('\n'):
            if 'description' in line.lower():
                # Extract description from set command
                match = re.search(r'description\s+"?([^"]+)"?', line)
                if match:
                    return match.group(1).strip().strip('"')
                # Try without quotes
                match = re.search(r'description\s+(\S+)', line)
                if match:
                    return match.group(1).strip()

        return ""
