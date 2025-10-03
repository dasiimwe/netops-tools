from abc import ABC, abstractmethod
import logging
from typing import Dict, List, Optional, Tuple
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
import time
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)

class BaseConnector(ABC):
    """Abstract base class for device connectors"""
    
    def __init__(self, host: str, username: str, password: str, port: int = 22,
                 timeout: int = 30, retry_enabled: bool = True,
                 retry_count: int = 3, retry_delay: int = 5, device_id: int = None,
                 user_id: int = None, enable_session_logging: bool = True):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.retry_enabled = retry_enabled
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.connection = None
        self.device_type = self.get_netmiko_device_type()

        # Session logging
        self.device_id = device_id
        self.user_id = user_id
        self.enable_session_logging = enable_session_logging
        self.session_id = str(uuid.uuid4()) if enable_session_logging else None
    
    @abstractmethod
    def get_netmiko_device_type(self) -> str:
        """Return the netmiko device type string"""
        pass
    
    @abstractmethod
    def get_interface_commands(self) -> List[str]:
        """Return list of commands to get interface information"""
        pass
    
    @abstractmethod
    def parse_interfaces(self, command_outputs: Dict[str, str], progress_callback=None) -> List[Dict]:
        """Parse command outputs and return list of interface dictionaries"""
        pass

    def _log_session_event(self, event_type: str, **kwargs):
        """Log session events to database if session logging is enabled"""
        if not self.enable_session_logging or not self.session_id:
            return

        try:
            from app.models import SessionLog, db
            SessionLog.log_event(
                session_id=self.session_id,
                device_id=self.device_id,
                user_id=self.user_id,
                event_type=event_type,
                **kwargs
            )
            db.session.commit()
        except Exception as e:
            logger.error(f"Failed to log session event: {e}")
            # Don't let logging failures interrupt the main flow
    
    def connect(self) -> bool:
        """Establish SSH connection to device"""
        start_time = datetime.now()
        self._log_session_event('connection_start')

        device = {
            'device_type': self.device_type,
            'host': self.host,
            'username': self.username,
            'password': self.password,
            'port': self.port,
            'timeout': self.timeout,
            'conn_timeout': self.timeout
        }

        attempts = self.retry_count if self.retry_enabled else 1
        last_exception = None

        for attempt in range(1, attempts + 1):
            try:
                logger.info(f"Connecting to {self.host} (attempt {attempt}/{attempts})")
                self.connection = ConnectHandler(**device)
                logger.info(f"Successfully connected to {self.host}")

                # Log successful connection
                duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
                self._log_session_event('connection_success', duration_ms=duration_ms)
                return True

            except NetmikoAuthenticationException as e:
                logger.error(f"Authentication failed for {self.host}: {str(e)}")
                last_exception = e
                self._log_session_event('connection_failed', error_message=f"Authentication failed: {str(e)}")
                break  # Don't retry auth failures

            except NetmikoTimeoutException as e:
                logger.warning(f"Connection timeout for {self.host} (attempt {attempt}/{attempts}): {str(e)}")
                last_exception = e
                if attempt == attempts:  # Log only on final attempt
                    self._log_session_event('connection_failed', error_message=f"Connection timeout: {str(e)}")

            except Exception as e:
                logger.error(f"Connection error for {self.host} (attempt {attempt}/{attempts}): {str(e)}")
                last_exception = e
                if attempt == attempts:  # Log only on final attempt
                    self._log_session_event('connection_failed', error_message=str(e))

            if attempt < attempts and self.retry_enabled:
                logger.info(f"Retrying in {self.retry_delay} seconds...")
                time.sleep(self.retry_delay)

        if last_exception:
            raise last_exception
        return False
    
    def disconnect(self):
        """Close SSH connection"""
        if self.connection:
            try:
                self.connection.disconnect()
                logger.info(f"Disconnected from {self.host}")
                self._log_session_event('disconnection')
            except Exception as e:
                logger.warning(f"Error disconnecting from {self.host}: {str(e)}")
                self._log_session_event('disconnection', error_message=str(e))
            finally:
                self.connection = None
    
    def execute_command(self, command: str) -> str:
        """Execute a command on the device with robust error handling"""
        if not self.connection:
            raise RuntimeError(f"Not connected to {self.host}")

        start_time = datetime.now()
        self._log_session_event('command_sent', command=command)

        try:
            # First attempt with standard send_command
            output = self.connection.send_command(command, read_timeout=30)
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            self._log_session_event('command_response', command=command, response=output, duration_ms=duration_ms)
            return output
        except Exception as e:
            error_msg = str(e).lower()

            # Handle "pattern not detected" errors for Cisco devices
            if "pattern" in error_msg and "not" in error_msg:
                logger.warning(f"Pattern detection failed for '{command}' on {self.host}, trying alternative method")

                try:
                    # Try with extended timeout and different parameters
                    output = self.connection.send_command(
                        command,
                        expect_string=r'#',
                        read_timeout=60,
                        strip_prompt=False,
                        strip_command=False
                    )

                    # Clean up the output
                    if output:
                        lines = output.split('\n')
                        # Remove the command echo (first line) and prompt (last line)
                        if len(lines) > 2:
                            output = '\n'.join(lines[1:-1])
                        elif len(lines) > 1:
                            output = '\n'.join(lines[1:])

                    duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
                    self._log_session_event('command_response', command=command, response=output, duration_ms=duration_ms)
                    logger.info(f"Alternative method succeeded for '{command}' on {self.host}")
                    return output

                except Exception as e2:
                    # Try one more time with send_command_timing (no prompt detection)
                    try:
                        logger.warning(f"Trying timing-based method for '{command}' on {self.host}")
                        output = self.connection.send_command_timing(command, delay_factor=2)

                        # Clean up output
                        if output:
                            lines = output.split('\n')
                            # Remove command echo and trailing prompt
                            cleaned_lines = []
                            for line in lines:
                                line = line.strip()
                                if line and not line.endswith('#') and not line.endswith('>') and line != command.strip():
                                    cleaned_lines.append(line)
                            output = '\n'.join(cleaned_lines)

                        duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
                        self._log_session_event('command_response', command=command, response=output, duration_ms=duration_ms)
                        logger.info(f"Timing-based method succeeded for '{command}' on {self.host}")
                        return output

                    except Exception as e3:
                        duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
                        error_details = f"All methods failed - Original: {str(e)}, Alternative: {str(e2)}, Timing: {str(e3)}"
                        self._log_session_event('command_failed', command=command, error_message=error_details, duration_ms=duration_ms)
                        logger.error(f"Error executing command '{command}' on {self.host}: {error_details}")
                        raise Exception(f"Command execution failed: {error_details}")
            else:
                duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
                self._log_session_event('command_failed', command=command, error_message=str(e), duration_ms=duration_ms)
                logger.error(f"Error executing command '{command}' on {self.host}: {str(e)}")
                raise
    
    def get_interfaces(self, progress_callback=None) -> List[Dict]:
        """Get interface information from device"""
        session_start_time = datetime.now()
        self._log_session_event('interface_collection_start')

        if not self.connection:
            if not self.connect():
                self._log_session_event('interface_collection_failed', error_message=f"Failed to connect to {self.host}")
                raise RuntimeError(f"Failed to connect to {self.host}")

        try:
            command_outputs = {}
            commands = self.get_interface_commands()

            # Log the commands we plan to execute
            self._log_session_event('interface_commands_planned',
                                   command=f"Commands to execute: {', '.join(commands)}")

            for command in commands:
                logger.debug(f"Executing: {command}")
                output = self.execute_command(command)
                command_outputs[command] = output
                time.sleep(1)  # 1 second pause between commands

            # Parse the interface data
            parse_start_time = datetime.now()
            interfaces = self.parse_interfaces(command_outputs, progress_callback)

            # Filter interfaces with IP addresses (exclude empty strings and None values)
            interfaces_with_ip = [
                intf for intf in interfaces
                if (intf.get('ipv4_address') and intf.get('ipv4_address').strip()) or
                   (intf.get('ipv6_address') and intf.get('ipv6_address').strip())
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
    
    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()