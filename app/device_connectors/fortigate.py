import re
from typing import Dict, List
from .base_connector import BaseConnector
import logging

logger = logging.getLogger(__name__)

class FortiGateConnector(BaseConnector):
    """Connector for FortiGate devices"""
    
    def get_netmiko_device_type(self) -> str:
        return 'fortinet'
    
    def get_interface_commands(self) -> List[str]:
        return [
            'get system interface',
            'diagnose ip address list'
        ]
    
    def parse_interfaces(self, command_outputs: Dict[str, str]) -> List[Dict]:
        interfaces = {}

        # Parse system interfaces output in the format: == [ interface_name ] followed by parameters
        interface_output = command_outputs.get('get system interface', '')

        current_interface = None
        current_data = {}

        for line in interface_output.split('\n'):
            line = line.strip()

            # Interface section starts with == [ interface_name ]
            if line.startswith('== [') and line.endswith(']'):
                # Save previous interface if it has data
                if current_interface and (current_data.get('ipv4_address') or current_data.get('ipv6_address')):
                    interfaces[current_interface] = current_data

                # Extract interface name from == [ wan1 ]
                current_interface = line.split('[')[1].split(']')[0].strip()
                current_data = {
                    'name': current_interface,
                    'description': '',
                    'status': 'unknown',
                    'ipv4_address': None,
                    'ipv6_address': None
                }

            elif current_interface and line:
                # Parse interface parameters in format: name: value
                # Example: name: wan1   mode: dhcp    ip: 192.168.10.100 255.255.255.0   status: up

                # Extract IP address and netmask
                ip_match = re.search(r'ip:\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    netmask = ip_match.group(2)
                    # Skip interfaces with 0.0.0.0 (unconfigured)
                    if ip != '0.0.0.0':
                        # Convert netmask to CIDR
                        cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
                        current_data['ipv4_address'] = f"{ip}/{cidr}"

                # Extract status
                if 'status:' in line:
                    status_match = re.search(r'status:\s+(\w+)', line)
                    if status_match:
                        current_data['status'] = status_match.group(1)

                # Extract type for description
                if 'type:' in line:
                    type_match = re.search(r'type:\s+(\w+)', line)
                    if type_match:
                        current_data['description'] = f"Type: {type_match.group(1)}"

        # Save last interface
        if current_interface and (current_data.get('ipv4_address') or current_data.get('ipv6_address')):
            interfaces[current_interface] = current_data

        # Parse IP address list for additional/missing interfaces
        # Format: IP=192.168.10.100->192.168.10.100/255.255.255.0 index=4 devname=wan1
        ip_list_output = command_outputs.get('diagnose ip address list', '')

        for line in ip_list_output.split('\n'):
            line = line.strip()
            if not line or not line.startswith('IP='):
                continue

            # Parse IP=ip->ip/mask format
            ip_match = re.search(r'IP=([^-]+)->[^/]+/([^\s]+)', line)
            devname_match = re.search(r'devname=(\S+)', line)

            if ip_match and devname_match:
                ip_addr = ip_match.group(1)
                netmask = ip_match.group(2)
                intf_name = devname_match.group(1)

                # Skip loopback and other non-physical interfaces
                if intf_name in ['root', 'lo', 'loopback']:
                    continue

                # Convert netmask to CIDR if it's in dotted format
                if '.' in netmask:
                    try:
                        cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
                        ip_with_cidr = f"{ip_addr}/{cidr}"
                    except:
                        ip_with_cidr = f"{ip_addr}/24"  # fallback
                else:
                    ip_with_cidr = f"{ip_addr}/{netmask}"

                # Add or update interface
                if intf_name not in interfaces:
                    interfaces[intf_name] = {
                        'name': intf_name,
                        'description': 'Detected from IP list',
                        'status': 'up',
                        'ipv4_address': None,
                        'ipv6_address': None
                    }

                # Skip 0.0.0.0 addresses and loopback
                if '.' in ip_addr and not ip_addr.startswith('127.') and ip_addr != '0.0.0.0':
                    interfaces[intf_name]['ipv4_address'] = ip_with_cidr
                elif ':' in ip_addr and not ip_addr.upper().startswith('FE80'):
                    interfaces[intf_name]['ipv6_address'] = ip_with_cidr

        # Get detailed interface configurations from config mode
        self._update_interface_details_from_config(interfaces)

        return list(interfaces.values())

    def _update_interface_details_from_config(self, interfaces: Dict[str, Dict]):
        """Update interface details by querying system interface config"""
        if not self.connection:
            logger.warning("No connection available to get interface config details")
            return

        try:
            # Enter global config context
            self._log_session_event('command_sent', command='config global')
            self.connection.send_command('config global', expect_string=r'#', strip_prompt=False, strip_command=False)

            # Get all interface configurations
            command = 'show system interface'
            self._log_session_event('command_sent', command=command)

            output = self.connection.send_command(command, expect_string=r'#', strip_prompt=False, strip_command=False)

            self._log_session_event('command_received',
                                  command=command,
                                  output=output,
                                  output_length=len(output))

            # Exit config mode
            self._log_session_event('command_sent', command='end')
            self.connection.send_command('end', expect_string=r'#', strip_prompt=False, strip_command=False)

            # Parse the configuration output
            self._parse_interface_config(output, interfaces)

        except Exception as e:
            logger.warning(f"Failed to get interface configurations: {e}")
            # Try to ensure we're out of config mode
            try:
                self.connection.send_command('end', expect_string=r'#', strip_prompt=False, strip_command=False)
            except:
                pass

    def _parse_interface_config(self, config_output: str, interfaces: Dict[str, Dict]):
        """Parse interface configuration from 'show system interface' output"""
        current_interface = None
        in_interface_block = False

        for line in config_output.split('\n'):
            line = line.strip()

            # Check for interface configuration block
            # Format: config system interface
            #         edit "interface_name"
            if line.startswith('edit "') and line.endswith('"'):
                interface_name = line.split('"')[1]
                if interface_name in interfaces:
                    current_interface = interface_name
                    in_interface_block = True
                else:
                    # Create new interface entry if not exists
                    current_interface = interface_name
                    interfaces[interface_name] = {
                        'name': interface_name,
                        'description': '',
                        'status': 'unknown',
                        'ipv4_address': None,
                        'ipv6_address': None
                    }
                    in_interface_block = True

            # End of interface block
            elif line == 'next' and in_interface_block:
                current_interface = None
                in_interface_block = False

            # Parse interface parameters within the block
            elif current_interface and in_interface_block:
                # Parse alias (description)
                if line.startswith('set alias'):
                    alias_match = re.search(r'set alias\s+"?([^"]+)"?', line)
                    if alias_match:
                        interfaces[current_interface]['description'] = alias_match.group(1).strip('"')
                        logger.debug(f"Updated description for {current_interface}: {interfaces[current_interface]['description']}")

                # Parse IPv6 address BEFORE IPv4 (to avoid "set ip" matching "set ip6-address")
                elif line.startswith('set ip6-address'):
                    # Match IPv6 address with prefix: set ip6-address 2001:db8::1/64
                    ipv6_match = re.search(r'set ip6-address\s+([0-9a-fA-F:]+(?::[0-9a-fA-F:]*)?)/(\d+)', line)
                    if ipv6_match:
                        ipv6_addr = ipv6_match.group(1)
                        prefix = ipv6_match.group(2)
                        if not ipv6_addr.upper().startswith('FE80'):
                            interfaces[current_interface]['ipv6_address'] = f"{ipv6_addr}/{prefix}"
                            logger.debug(f"Updated IPv6 for {current_interface}: {interfaces[current_interface]['ipv6_address']}")

                # Parse IP address (IPv4)
                elif line.startswith('set ip '):  # Note the space to not match ip6-address
                    ip_match = re.search(r'set ip\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        netmask = ip_match.group(2)
                        # Skip interfaces with 0.0.0.0 (unconfigured)
                        if ip != '0.0.0.0':
                            # Convert netmask to CIDR
                            try:
                                cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
                                interfaces[current_interface]['ipv4_address'] = f"{ip}/{cidr}"
                            except:
                                interfaces[current_interface]['ipv4_address'] = f"{ip}/24"

                # Parse status
                elif line.startswith('set status'):
                    if 'down' in line:
                        interfaces[current_interface]['status'] = 'down'
                    elif 'up' in line:
                        interfaces[current_interface]['status'] = 'up'

                # Parse type
                elif line.startswith('set type') and not interfaces[current_interface]['description']:
                    type_match = re.search(r'set type\s+(\S+)', line)
                    if type_match:
                        interfaces[current_interface]['description'] = f"Type: {type_match.group(1)}"