import re
from typing import Dict, List
from .base_connector import BaseConnector
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class CiscoNXOSConnector(BaseConnector):
    """Connector for Cisco NXOS devices"""

    def get_netmiko_device_type(self) -> str:
        return 'cisco_nxos'

    def execute_command(self, command: str) -> str:
        """Execute command with NXOS-specific optimizations"""
        if not self.connection:
            raise RuntimeError(f"Not connected to {self.host}")

        start_time = datetime.now()
        self._log_session_event('command_sent', command=command)

        try:
            # For NXOS, try with explicit expect string first
            output = self.connection.send_command(
                command,
                expect_string=r'[\#\>]',
                read_timeout=60,
                strip_prompt=True,
                strip_command=True
            )
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_session_event('command_response', command=command, response=output, duration_ms=duration_ms)
            return output
        except Exception as e:
            # Fall back to parent class robust method
            logger.warning(f"NXOS-specific method failed for '{command}' on {self.host}, falling back to base method")
            return super().execute_command(command)

    def connect(self) -> bool:
        """Connect to NXOS device with specific settings"""
        if not super().connect():
            return False

        try:
            # Set terminal length to 0 for NXOS devices
            logger.info(f"Setting terminal length 0 for NXOS device {self.host}")
            self.connection.send_command('terminal length 0', expect_string=r'[\#\>]')
            logger.info(f"Successfully set terminal length 0 for {self.host}")
            return True
        except Exception as e:
            logger.warning(f"Failed to set terminal length 0 for {self.host}: {str(e)}")
            # Continue anyway, as some commands might still work
            return True

    def get_interfaces(self) -> List[Dict]:
        """Get interface information from NXOS device with enhanced error handling"""
        session_start_time = datetime.now()
        self._log_session_event('interface_collection_start')

        if not self.connection:
            if not self.connect():
                self._log_session_event('interface_collection_failed', error_message=f"Failed to connect to {self.host}")
                raise RuntimeError(f"Failed to connect to {self.host}")

        try:
            # Ensure terminal length is set
            try:
                self.connection.send_command('terminal length 0', expect_string=r'[\#\>]')
                logger.debug(f"Set terminal length 0 for {self.host}")
            except Exception as e:
                logger.warning(f"Could not set terminal length for {self.host}: {str(e)}")

            command_outputs = {}
            commands = self.get_interface_commands()

            # Log the commands we plan to execute
            self._log_session_event('interface_commands_planned',
                                   command=f"Commands to execute: {', '.join(commands)}")

            for command in commands:
                logger.debug(f"Executing: {command}")
                try:
                    output = self.execute_command(command)
                    command_outputs[command] = output
                    logger.debug(f"Command '{command}' returned {len(output)} characters")
                except Exception as e:
                    logger.error(f"Command '{command}' failed: {str(e)}")
                    command_outputs[command] = ''

            # Parse the interface data
            parse_start_time = datetime.now()
            interfaces = self.parse_interfaces(command_outputs)

            # Filter interfaces with IP addresses
            interfaces_with_ip = [
                intf for intf in interfaces
                if intf.get('ipv4_address') or intf.get('ipv6_address')
            ]

            # Log the results
            session_duration_ms = int((datetime.now() - session_start_time).total_seconds() * 1000)
            result_summary = {
                'total_interfaces_found': len(interfaces),
                'interfaces_with_ip': len(interfaces_with_ip),
                'interface_names': [intf['name'] for intf in interfaces_with_ip]
            }

            self._log_session_event('interface_collection_success',
                                   response=f"Found {len(interfaces_with_ip)} interfaces with IP addresses: {', '.join(result_summary['interface_names'])}",
                                   duration_ms=session_duration_ms)

            logger.info(f"Found {len(interfaces_with_ip)} interfaces with IP addresses on {self.host}")
            return interfaces_with_ip

        except Exception as e:
            session_duration_ms = int((datetime.now() - session_start_time).total_seconds() * 1000)
            self._log_session_event('interface_collection_failed',
                                   error_message=str(e),
                                   duration_ms=session_duration_ms)
            logger.error(f"Error getting interfaces from {self.host}: {str(e)}")
            raise
        finally:
            self.disconnect()

    def get_interface_commands(self) -> List[str]:
        return [
            'show interface description',
            'show ip interface brief',
            'show ipv6 interface brief'
        ]
    
    def parse_interfaces(self, command_outputs: Dict[str, str]) -> List[Dict]:
        interfaces = {}
        
        # Parse interface descriptions
        desc_output = command_outputs.get('show interface description', '')
        
        for line in desc_output.split('\n'):
            line = line.strip()
            if not line or line.startswith('-') or line.startswith('Interface') or line.startswith('Port'):
                continue
            
            parts = line.split(None, 3)
            if len(parts) >= 2:
                intf_name = parts[0]
                # Type is parts[1]
                status = parts[2] if len(parts) > 2 else 'unknown'
                description = parts[3] if len(parts) > 3 else ''
                
                interfaces[intf_name] = {
                    'name': intf_name,
                    'description': description,
                    'status': status,
                    'ipv4_address': None,
                    'ipv6_address': None
                }
        
        # Parse IPv4 addresses
        ipv4_output = command_outputs.get('show ip interface brief', '')
        ipv4_pattern = r'^(\S+)\s+([\d.]+|unassigned|--)\s+\S+\s+\S+\s+(\S+)\s+(\S+)'
        
        for line in ipv4_output.split('\n'):
            match = re.match(ipv4_pattern, line.strip())
            if match:
                intf_name = match.group(1)
                ip_address = match.group(2)
                status = match.group(3)
                protocol = match.group(4)
                
                if ip_address not in ['unassigned', '--'] and '.' in ip_address:
                    if intf_name not in interfaces:
                        interfaces[intf_name] = {
                            'name': intf_name,
                            'description': '',
                            'status': f"{status}/{protocol}"
                        }
                    interfaces[intf_name]['ipv4_address'] = ip_address
        
        # Parse IPv6 addresses
        ipv6_output = command_outputs.get('show ipv6 interface brief', '')
        current_interface = None
        
        for line in ipv6_output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # NXOS IPv6 output format
            if not line.startswith(' '):
                parts = line.split()
                if parts and parts[0] not in ['IPv6', 'Interface', 'VRF']:
                    current_interface = parts[0]
                    if current_interface not in interfaces:
                        interfaces[current_interface] = {
                            'name': current_interface,
                            'description': '',
                            'status': 'unknown'
                        }
            elif current_interface and '::' in line:
                # Look for IPv6 address
                ipv6_pattern = r'([0-9A-Fa-f:]+(?:/\d+)?)'
                match = re.search(ipv6_pattern, line)
                if match:
                    ipv6_addr = match.group(1)
                    # Skip link-local addresses
                    if not ipv6_addr.upper().startswith('FE80'):
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