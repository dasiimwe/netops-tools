import re
from typing import Dict, List
from .base_connector import BaseConnector
import logging
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

class PaloAltoConnector(BaseConnector):
    """Connector for Palo Alto Networks devices"""

    def get_netmiko_device_type(self) -> str:
        return 'paloalto_panos'

    def get_interface_commands(self) -> List[str]:
        return [
            'show interface all',
            'show interface logical'
        ]

    def execute_command(self, command: str) -> str:
        """Execute command on Palo Alto device with optimized prompt detection"""
        if not self.connection:
            raise RuntimeError(f"Not connected to {self.host}")

        from datetime import datetime
        start_time = datetime.now()
        self._log_session_event('command_sent', command=command)

        try:
            # Palo Alto devices use '>' or '#' prompts
            # Use send_command_timing for faster, more reliable execution
            output = self.connection.send_command_timing(
                command,
                delay_factor=0.5,  # Reduced delay for faster response
                max_loops=150
            )

            # Clean up output - remove command echo and prompt
            if output:
                lines = output.split('\n')
                cleaned_lines = []
                for i, line in enumerate(lines):
                    # Skip first line if it's the command echo
                    if i == 0 and command.strip() in line:
                        continue
                    # Skip lines that are just prompts
                    stripped = line.strip()
                    if stripped and not (stripped.endswith('>') or stripped.endswith('#')) or ' ' in stripped:
                        cleaned_lines.append(line.rstrip())

                output = '\n'.join(cleaned_lines)

            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_session_event('command_response', command=command, response=output, duration_ms=duration_ms)
            logger.info(f"Command '{command}' completed on {self.host} in {duration_ms}ms")
            return output

        except Exception as e:
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_session_event('command_failed', command=command, error_message=str(e), duration_ms=duration_ms)
            logger.error(f"Error executing command '{command}' on {self.host}: {str(e)}")
            raise
    
    def parse_interfaces(self, command_outputs: Dict[str, str], progress_callback=None) -> List[Dict]:
        interfaces = {}
        
        # Parse physical interfaces
        physical_output = command_outputs.get('show interface all', '')
        
        # Parse each interface block
        current_interface = None
        current_data = {}
        
        for line in physical_output.split('\n'):
            line = line.strip()
            
            # New interface starts with "name:"
            if line.startswith('name:'):
                # Save previous interface if exists
                if current_interface and (current_data.get('ipv4_address') or current_data.get('ipv6_address')):
                    interfaces[current_interface] = current_data
                
                # Start new interface
                current_interface = line.split(':', 1)[1].strip()
                current_data = {
                    'name': current_interface,
                    'description': '',
                    'status': 'unknown',
                    'ipv4_address': None,
                    'ipv6_address': None
                }
            
            elif current_interface:
                if line.startswith('comment:'):
                    current_data['description'] = line.split(':', 1)[1].strip()
                elif line.startswith('ip address:'):
                    ip_info = line.split(':', 1)[1].strip()
                    if ip_info and ip_info != 'none':
                        # Extract IPv4 address
                        ipv4_match = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', ip_info)
                        if ipv4_match:
                            current_data['ipv4_address'] = ipv4_match.group(1)
                elif line.startswith('ipv6 address:'):
                    ipv6_info = line.split(':', 1)[1].strip()
                    if ipv6_info and ipv6_info != 'none':
                        # Extract IPv6 address (first non-link-local)
                        ipv6_pattern = r'([0-9A-Fa-f:]+/\d+)'
                        for match in re.finditer(ipv6_pattern, ipv6_info):
                            addr = match.group(1)
                            if not addr.upper().startswith('FE80'):
                                current_data['ipv6_address'] = addr
                                break
                elif line.startswith('link state:'):
                    current_data['status'] = line.split(':', 1)[1].strip()
        
        # Save last interface
        if current_interface and (current_data.get('ipv4_address') or current_data.get('ipv6_address')):
            interfaces[current_interface] = current_data
        
        # Parse logical interfaces (VLAN interfaces, etc.)
        logical_output = command_outputs.get('show interface logical', '')
        
        for line in logical_output.split('\n'):
            line = line.strip()
            if not line or line.startswith('total'):
                continue
            
            # Parse logical interface line
            # Format: name id vsys zone forwarding tag address
            parts = line.split()
            if len(parts) >= 7:
                intf_name = parts[0]
                # Skip if already have this interface
                if intf_name in interfaces:
                    continue
                
                # Get the IP address (last column or near last)
                for i in range(len(parts)-1, 5, -1):
                    potential_ip = parts[i]
                    # Check if it's an IP address
                    if '.' in potential_ip or ':' in potential_ip:
                        interface_data = {
                            'name': intf_name,
                            'description': f"VSYS: {parts[2]}, Zone: {parts[3]}",
                            'status': 'up',
                            'ipv4_address': None,
                            'ipv6_address': None
                        }
                        
                        if '.' in potential_ip:
                            interface_data['ipv4_address'] = potential_ip
                        elif ':' in potential_ip and not potential_ip.upper().startswith('FE80'):
                            interface_data['ipv6_address'] = potential_ip
                        
                        if interface_data['ipv4_address'] or interface_data['ipv6_address']:
                            interfaces[intf_name] = interface_data
                        break
        
        return list(interfaces.values())