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

    def get_interfaces(self, progress_callback=None) -> List[Dict]:
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
            interfaces = self.parse_interfaces(command_outputs, progress_callback)

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
            'show ip interface brief vrf all',
            'show ipv6 interface brief'
        ]
    
    def parse_interfaces(self, command_outputs: Dict[str, str], progress_callback=None) -> List[Dict]:
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
        ipv4_output = command_outputs.get('show ip interface brief vrf all', '')

        # NXOS 'show ip interface brief vrf all' has different format than regular IOS
        # Format: interface_name   ip_address   combined_status
        ipv4_pattern = r'^(\S+)\s+([\d.]+|unassigned|--)\s+(.+)$'

        for line in ipv4_output.split('\n'):
            line = line.strip()
            if not line or line.startswith('IP Interface Status') or line.startswith('Interface'):
                continue

            match = re.match(ipv4_pattern, line)
            if match:
                intf_name = match.group(1)
                ip_address = match.group(2)
                combined_status = match.group(3).strip()

                if ip_address not in ['unassigned', '--'] and '.' in ip_address:
                    if intf_name not in interfaces:
                        interfaces[intf_name] = {
                            'name': intf_name,
                            'description': '',
                            'status': combined_status
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
        self._update_interface_descriptions_from_config(interfaces, progress_callback)

        return list(interfaces.values())

    def _update_interface_descriptions_from_config(self, interfaces: Dict[str, Dict], progress_callback=None):
        """Update interface descriptions by querying running-config for each interface"""
        if not self.connection:
            logger.warning("No connection available to get running-config descriptions")
            return

        total_interfaces = len(interfaces)
        for idx, (intf_name, intf_data) in enumerate(interfaces.items()):
            try:
                # Skip if we already have a good description from 'show interface description'
                existing_desc = intf_data.get('description', '').strip()
                if existing_desc and existing_desc not in ['', '--', 'N/A']:
                    logger.debug(f"Interface {intf_name} already has description: {existing_desc}")
                    continue

                # For management interfaces on NXOS, try different command formats
                if intf_name.lower().startswith('mgmt'):
                    # Management interfaces might need different handling
                    commands_to_try = [
                        f"show running-config interface {intf_name}",
                        f"show running-config | section interface {intf_name}",
                        f"show interface {intf_name}"
                    ]
                else:
                    commands_to_try = [f"show running-config interface {intf_name}"]

                config_description = None
                for command in commands_to_try:
                    try:
                        # Update progress if callback provided
                        if progress_callback:
                            progress_callback({
                                'command': command,
                                'status': 'executing',
                                'interface': intf_name,
                                'progress': f"Interface {idx + 1}/{total_interfaces}"
                            })

                        self._log_session_event('command_sent', command=command)

                        # Use execute_command method which has better error handling
                        output = self.execute_command(command)

                        self._log_session_event('command_received',
                                              command=command,
                                              output=output,
                                              output_length=len(output))

                        # Update progress on success
                        if progress_callback:
                            progress_callback({
                                'command': command,
                                'status': 'completed',
                                'interface': intf_name,
                                'output_length': len(output),
                                'progress': f"Interface {idx + 1}/{total_interfaces}"
                            })

                        # Parse description from running config
                        config_description = self._parse_description_from_config(output)
                        if config_description:
                            intf_data['description'] = config_description
                            logger.debug(f"Updated description for {intf_name} using '{command}': {config_description}")
                            break  # Success, stop trying other commands
                        else:
                            logger.debug(f"No description found in output from '{command}' for {intf_name}")

                    except Exception as e:
                        logger.debug(f"Command '{command}' failed for interface {intf_name}: {e}")
                        # Update progress on failure
                        if progress_callback:
                            progress_callback({
                                'command': command,
                                'status': 'failed',
                                'interface': intf_name,
                                'error': str(e),
                                'progress': f"Interface {idx + 1}/{total_interfaces}"
                            })
                        continue  # Try next command

                if not config_description:
                    logger.debug(f"No config description found for interface {intf_name}, keeping original: {existing_desc}")

            except Exception as e:
                logger.warning(f"Failed to get running-config for interface {intf_name}: {e}")
                # Keep the original description from 'show interface description'
                continue

    def _parse_description_from_config(self, config_output: str) -> str:
        """Parse interface description from running-config output"""
        if not config_output or config_output.strip() == '':
            return ""

        # Try multiple patterns to handle different command outputs
        patterns = [
            r'^\s*description\s+(.+)$',  # Standard description line
            r'^\s*Description:\s*(.+)$',  # From show interface output
            r'^\s*Description\s*:\s*(.+)$'  # Alternative format
        ]

        for line in config_output.split('\n'):
            line = line.strip()
            if not line:
                continue

            for pattern in patterns:
                match = re.match(pattern, line, re.IGNORECASE)
                if match:
                    desc = match.group(1).strip()
                    # Filter out common "no description" indicators
                    if desc and desc.lower() not in ['--', 'n/a', 'none', 'not set', '']:
                        return desc

        return ""