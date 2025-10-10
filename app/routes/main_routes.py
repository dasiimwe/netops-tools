from flask import render_template, redirect, url_for, request, jsonify, send_file, current_app, Response, stream_with_context
from flask_login import login_required, current_user
from app.routes import main_bp
from app.models import db, Device, Interface, User, AuditLog, Settings
from sqlalchemy import func, or_
from datetime import datetime, timedelta
import re
import io
import zipfile
import json
from concurrent.futures import ThreadPoolExecutor
import socket
import dns.resolver
import dns.reversename
import dns.exception
import subprocess
import platform
import time

@main_bp.route('/')
def index():
    """Index page with IP translator - no login required"""
    tooltip_theme = Settings.get_value('tooltip_theme', 'light')

    # Get tool visibility settings
    tool_visibility = {
        'ip_translator': Settings.get_value('tool_ip_translator', True),
        'command_runner': Settings.get_value('tool_command_runner', True),
        'dns_lookup': Settings.get_value('tool_dns_lookup', True),
        'bgp_looking_glass': Settings.get_value('tool_bgp_looking_glass', True),
        'traceroute': Settings.get_value('tool_traceroute', True),
        'url_insights': Settings.get_value('tool_url_insights', True),
        'tcp_handshake': Settings.get_value('tool_tcp_handshake', True),
        'whoami': Settings.get_value('tool_whoami', True)
    }

    # Check if user is authenticated (for database save/load features)
    user_authenticated = current_user.is_authenticated if current_user else False

    # Get command runner settings
    show_connector_dropdown = Settings.get_value('show_connector_dropdown', True)

    return render_template('index.html',
                         tooltip_theme=tooltip_theme,
                         tool_visibility=tool_visibility,
                         user_authenticated=user_authenticated,
                         show_connector_dropdown=show_connector_dropdown)

@main_bp.route('/api/whoami')
def whoami():
    """API endpoint to return user's IP address"""
    # Get client IP address, handling proxies
    if request.headers.get('X-Forwarded-For'):
        client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        client_ip = request.headers.get('X-Real-IP')
    else:
        client_ip = request.remote_addr

    response_data = {
        'ip': client_ip
    }

    # Try to get reverse DNS
    try:
        reverse_dns = socket.gethostbyaddr(client_ip)[0]
        response_data['reverse_dns'] = reverse_dns
    except (socket.herror, socket.gaierror):
        # Reverse DNS lookup failed
        pass

    return jsonify(response_data)

@main_bp.route('/api/resolve-hostname', methods=['POST'])
def resolve_hostname():
    """API endpoint to resolve hostname to IP address or perform reverse DNS for IP"""
    try:
        data = request.get_json()
        hostname = data.get('hostname', '').strip()

        if not hostname:
            return jsonify({
                'success': False,
                'error': 'Hostname is required'
            }), 400

        # Check if it's already an IP address
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.match(ip_pattern, hostname):
            # It's an IP address - perform reverse DNS lookup
            ip_address = hostname
            resolved_hostname = None

            # Try reverse DNS lookup
            try:
                resolved_hostname = socket.gethostbyaddr(ip_address)[0]
            except (socket.herror, socket.gaierror):
                # Reverse DNS failed, check database
                from app.models import Device
                device = Device.query.filter_by(ip_address=ip_address).first()
                if device and device.hostname:
                    resolved_hostname = device.hostname

            # Return with hostname if found, otherwise just IP
            if resolved_hostname:
                return jsonify({
                    'success': True,
                    'hostname': resolved_hostname,
                    'ip': ip_address,
                    'display': f'{resolved_hostname} | {ip_address}'
                })
            else:
                return jsonify({
                    'success': True,
                    'hostname': ip_address,
                    'ip': ip_address,
                    'display': ip_address
                })

        # It's a hostname - perform forward DNS lookup
        try:
            ip_address = socket.gethostbyname(hostname)
            return jsonify({
                'success': True,
                'hostname': hostname,
                'ip': ip_address,
                'display': f'{hostname} | {ip_address}'
            })
        except socket.gaierror as e:
            return jsonify({
                'success': False,
                'error': f'Unable to resolve hostname: {hostname}',
                'details': str(e)
            }), 404

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@main_bp.route('/admin')
@main_bp.route('/admin/')
@login_required
def admin():
    # Get statistics
    total_devices = Device.query.count()
    reachable_devices = Device.query.filter_by(is_reachable=True).count()
    unreachable_devices = Device.query.filter_by(is_reachable=False).count()
    
    total_interfaces = Interface.query.count()
    ipv4_interfaces = Interface.query.filter(Interface.ipv4_address.isnot(None)).count()
    ipv6_interfaces = Interface.query.filter(Interface.ipv6_address.isnot(None)).count()
    
    # Get recent activity
    recent_activity = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).limit(10).all()
    
    # Get devices by vendor
    vendor_stats = db.session.query(
        Device.vendor,
        func.count(Device.id)
    ).group_by(Device.vendor).all()
    
    # Get recently updated devices
    recent_devices = Device.query.order_by(
        Device.updated_at.desc()
    ).limit(5).all()
    
    stats = {
        'total_devices': total_devices,
        'reachable_devices': reachable_devices,
        'unreachable_devices': unreachable_devices,
        'total_interfaces': total_interfaces,
        'ipv4_interfaces': ipv4_interfaces,
        'ipv6_interfaces': ipv6_interfaces,
        'vendor_distribution': dict(vendor_stats)
    }
    
    return render_template('dashboard.html',
                         stats=stats,
                         recent_activity=recent_activity,
                         recent_devices=recent_devices)

@main_bp.route('/api/translate-ip')
def translate_ip():
    """API endpoint to translate IP addresses to hostname and interface info"""
    text = request.args.get('text', '')

    if not text.strip():
        return jsonify({'translated_text': text})

    # Find all IP addresses in the text using regex
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ip_addresses = re.findall(ip_pattern, text)

    if not ip_addresses:
        return jsonify({'translated_text': text})

    translated_text = text

    # Process unique IPs to avoid nested replacements
    unique_ips = list(set(ip_addresses))
    ip_replacements = {}

    for ip in unique_ips:
        # Look for interface with this IP
        interface = Interface.query.join(Device).filter(
            or_(
                Interface.ipv4_address.like(f'{ip}/%'),
                Interface.ipv4_address == ip
            )
        ).first()

        if interface:
            device = interface.device

            # Shorten interface name: first 2 letters + digits at end (e.g., GigabitEthernet1/0/1 -> gi1/0/1)
            interface_short = interface.name.lower()
            # Extract first 2 letters and any digits/slashes at the end
            match = re.match(r'^([a-zA-Z]{2})[a-zA-Z]*(.*)$', interface.name)
            if match:
                interface_short = match.group(1).lower() + match.group(2)
            else:
                # Fallback: just take first 2 chars if no match
                interface_short = interface.name[:2].lower()

            # Create display format with blue hostname: ip(hostname-interface)
            short_name = f"<span style=\"color: blue;\">{device.hostname}</span>-{interface_short}"

            display_text = f"{ip}({short_name})"

            # Create detailed tooltip info
            tooltip_data = {
                'ip': ip,
                'hostname': device.hostname,
                'interface_name': interface.name,
                'interface_description': interface.description or 'No description',
                'management_ip': device.ip_address,
                'device_vendor': device.vendor.replace('_', ' ').title(),
                'interface_status': interface.status or 'Unknown'
            }

            # Store replacement for this IP
            import json
            tooltip_json = json.dumps(tooltip_data).replace('"', '&quot;')
            enhanced_ip = f'<span class="ip-enhanced" data-ip="{ip}" data-tooltip="{tooltip_json}" data-mgmt-ip="{device.ip_address}" style="cursor: pointer;">{display_text}</span>'
            ip_replacements[ip] = enhanced_ip

    # Apply replacements in order of longest IP first to avoid partial matches
    for ip in sorted(ip_replacements.keys(), key=len, reverse=True):
        translated_text = translated_text.replace(ip, ip_replacements[ip])

    # Convert newlines to HTML line breaks to preserve formatting
    translated_text = translated_text.replace('\n', '<br>')

    return jsonify({'translated_text': translated_text})

def validate_command_safety(command):
    """
    Validate that a command is safe for execution (non-intrusive troubleshooting only).
    Returns (is_safe, error_message)
    """
    if not command or not isinstance(command, str):
        return False, "Invalid command format"

    command = command.strip().lower()

    # Load command rules from database or use defaults
    try:
        rules_json = Settings.get_value('command_validation_rules', None)
        if rules_json:
            rules = json.loads(rules_json)
            safe_prefixes = [prefix.lower() for prefix in rules.get('safePrefixes', [])]
            dangerous_patterns = [pattern.lower() for pattern in rules.get('dangerousPatterns', [])]
            standalone_commands = [cmd.lower() for cmd in rules.get('standaloneCommands', [])]
        else:
            # Use default rules if none are configured
            safe_prefixes = [
                'show ',
                'execute ping ',
                'execute traceroute ',
                'ping ',
                'traceroute ',
                'trace ',
                'get system ',
                'diagnose '
            ]
            dangerous_patterns = [
                'delete',
                'remove',
                'erase',
                'format',
                'reload',
                'reboot',
                'shutdown',
                'clear',
                'reset',
                'write',
                'copy',
                'configure',
                'config',
                'exit',
                'quit',
                'end',
                'commit',
                'save'
            ]
            standalone_commands = [
                'uptime',
                'version',
                'date',
                'clock',
                'whoami',
                'pwd'
            ]
    except Exception as e:
        # Fall back to basic safe defaults if there's an error
        safe_prefixes = ['show ']
        dangerous_patterns = ['configure', 'config', 'delete', 'remove', 'write', 'copy']
        standalone_commands = ['uptime', 'version']

    # Step 1: Check for dangerous patterns first (blocklist approach)
    for pattern in dangerous_patterns:
        if pattern in command:
            return False, f"Dangerous command pattern detected: '{pattern}'. Only read-only troubleshooting commands are allowed."

    # Step 2: Check for safe prefixes (allowlist approach)
    for prefix in safe_prefixes:
        if command.startswith(prefix):
            return True, None

    # Step 3: Check standalone commands
    if command in standalone_commands:
        return True, None

    return False, f"Command '{command}' is not in the list of allowed safe commands. Use the Settings page to manage allowed commands."

def get_device_connector(device_ip, username, password, preferred_connector=None):
    """Get appropriate device connector based on device type detection

    Args:
        device_ip: IP address or hostname of the device
        username: Username for authentication
        password: Password for authentication
        preferred_connector: Optional connector type to try first (e.g., 'cisco_ios', 'paloalto_panos')
    """
    from app.device_connectors.cisco_ios import CiscoIOSConnector
    from app.device_connectors.cisco_nxos import CiscoNXOSConnector
    from app.device_connectors.cisco_iosxr import CiscoIOSXRConnector
    from app.device_connectors.paloalto import PaloAltoConnector
    from app.device_connectors.fortigate import FortiGateConnector

    # Mapping of connector names to classes
    connector_map = {
        'cisco_ios': CiscoIOSConnector,
        'cisco_nxos': CiscoNXOSConnector,
        'cisco_iosxr': CiscoIOSXRConnector,
        'cisco_asa': CiscoIOSConnector,  # ASA uses same connector as IOS
        'paloalto_panos': PaloAltoConnector,
        'fortinet': FortiGateConnector,
        'arista_eos': CiscoIOSConnector,  # Arista typically uses similar commands
        'juniper_junos': CiscoIOSConnector  # Placeholder - would need specific connector
    }

    # Default order to try connectors
    connectors_to_try = [
        CiscoIOSConnector,
        CiscoNXOSConnector,
        CiscoIOSXRConnector,
        PaloAltoConnector,
        FortiGateConnector
    ]

    # If preferred connector is specified, try it first
    if preferred_connector and preferred_connector in connector_map:
        preferred_class = connector_map[preferred_connector]
        # Move preferred connector to front of list
        if preferred_class in connectors_to_try:
            connectors_to_try.remove(preferred_class)
        connectors_to_try.insert(0, preferred_class)

    for connector_class in connectors_to_try:
        try:
            connector = connector_class(
                host=device_ip,
                username=username,
                password=password,
                timeout=10,
                retry_enabled=False,
                enable_session_logging=False
            )
            if connector.connect():
                return connector
        except Exception:
            continue

    return None

def execute_commands_on_device_with_context(app, device_ip, commands, username, password, preferred_connector=None):
    """Execute commands on a single device within Flask app context"""
    with app.app_context():
        return execute_commands_on_device(device_ip, commands, username, password, preferred_connector)

def execute_commands_on_device(device_ip, commands, username, password, preferred_connector=None):
    """Execute commands on a single device"""
    try:
        print(f"DEBUG: Attempting to connect to device: {device_ip}")
        connector = get_device_connector(device_ip, username, password, preferred_connector)
        if not connector:
            print(f"DEBUG: Failed to get connector for device: {device_ip}")
            return {
                'status': 'failed',
                'error': 'Could not connect to device or unsupported device type'
            }

        device_result = {
            'status': 'success',
            'commands': {}
        }

        try:
            for command in commands:
                try:
                    output = connector.execute_command(command)

                    # Debug logging
                    print(f"DEBUG: Command '{command}' output length: {len(output)}")
                    print(f"DEBUG: Command '{command}' raw output: {repr(output[:200])}")

                    # Apply IP translation to the output
                    translated_output = translate_output_ips(output)

                    print(f"DEBUG: Command '{command}' translated output length: {len(translated_output)}")
                    print(f"DEBUG: Command '{command}' translated output: {repr(translated_output[:200])}")
                    print(f"DEBUG: About to store in device_result: output={bool(output)}, translated={bool(translated_output)}")

                    device_result['commands'][command] = {
                        'output': output,
                        'translated_output': translated_output,
                        'status': 'success'
                    }
                except Exception as cmd_error:
                    print(f"DEBUG: Command '{command}' failed with error: {str(cmd_error)}")
                    device_result['commands'][command] = {
                        'output': '',
                        'translated_output': '',
                        'status': 'failed',
                        'error': str(cmd_error)
                    }
        finally:
            connector.disconnect()

        return device_result

    except Exception as e:
        return {
            'status': 'failed',
            'error': str(e)
        }

def translate_output_ips(text):
    """Apply IP translation like the IP translator tool"""
    if not text.strip():
        return text

    # Find all IP addresses in the text using regex
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ip_addresses = re.findall(ip_pattern, text)

    if not ip_addresses:
        return text

    translated_text = text
    unique_ips = list(set(ip_addresses))
    ip_replacements = {}

    for ip in unique_ips:
        # Look for interface with this IP
        interface = Interface.query.join(Device).filter(
            or_(
                Interface.ipv4_address.like(f'{ip}/%'),
                Interface.ipv4_address == ip
            )
        ).first()

        if interface:
            device = interface.device

            # Shorten interface name
            interface_short = interface.name.lower()
            match = re.match(r'^([a-zA-Z]{2})[a-zA-Z]*(.*)$', interface.name)
            if match:
                interface_short = match.group(1).lower() + match.group(2)
            else:
                interface_short = interface.name[:2].lower()

            # Create simple text replacement (no HTML for command output)
            short_name = f"{device.hostname}-{interface_short}"
            display_text = f"{ip}({short_name})"
            ip_replacements[ip] = display_text

    # Apply replacements
    for ip in sorted(ip_replacements.keys(), key=len, reverse=True):
        translated_text = translated_text.replace(ip, ip_replacements[ip])

    return translated_text

@main_bp.route('/api/run-commands', methods=['POST'])
def run_commands():
    """API endpoint to run commands on multiple devices"""
    try:
        data = request.get_json()
        devices = data.get('devices', [])
        commands = data.get('commands', [])
        username = data.get('username', '')
        password = data.get('password', '')
        preferred_connector = data.get('preferred_connector', '')

        # Extract IP addresses from 'hostname | IP' format
        device_ips = [extract_device_ip(device) for device in devices]

        if not devices or not commands or not username or not password:
            return jsonify({
                'success': False,
                'error': 'Missing required parameters'
            })

        # Validate command safety
        for command in commands:
            is_safe, error_message = validate_command_safety(command)
            if not is_safe:
                # Log blocked command attempt
                audit_log = AuditLog(
                    user_id=current_user.id if current_user.is_authenticated else None,
                    action='command_execution_blocked',
                    details=f'Blocked unsafe command: "{command}" - {error_message}',
                    ip_address=request.remote_addr
                )
                db.session.add(audit_log)
                db.session.commit()

                return jsonify({
                    'success': False,
                    'error': f'Unsafe command rejected: {error_message}'
                })

        # Log successful command execution attempt
        audit_log = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action='command_execution_started',
            details=f'Starting command execution on {len(devices)} device(s): {", ".join(commands)}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        # For testing, let's return sample data if device is 'test'
        if 'test' in device_ips:
            sample_output = """Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0     192.168.1.1     YES NVRAM  up                    up
GigabitEthernet0/1     10.0.0.1        YES NVRAM  up                    up
GigabitEthernet0/2     unassigned      YES NVRAM  administratively down down
Loopback0              172.16.1.1      YES NVRAM  up                    up      """

            results = {}
            for i, device_ip in enumerate(device_ips):
                original_display = devices[i]
                if device_ip == 'test':
                    results[original_display] = {
                        'status': 'success',
                        'commands': {
                            cmd: {
                                'output': sample_output,
                                'translated_output': translate_output_ips(sample_output),
                                'status': 'success'
                            } for cmd in commands
                        }
                    }
                else:
                    # Continue with normal processing for non-test devices
                    result = execute_commands_on_device(device_ip, commands, username, password, preferred_connector)
                    results[original_display] = result

            return jsonify({
                'success': True,
                'results': results
            })

        results = {}

        # Use ThreadPoolExecutor for parallel execution
        app = current_app._get_current_object()  # Get the actual app instance
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_device = {
                executor.submit(execute_commands_on_device_with_context, app, device_ips[i], commands, username, password, preferred_connector): devices[i]
                for i in range(len(devices))
            }

            for future in future_to_device:
                original_display = future_to_device[future]
                try:
                    result = future.result(timeout=60)  # 60 second timeout per device
                    results[original_display] = result
                except Exception as e:
                    results[original_display] = {
                        'status': 'failed',
                        'error': f'Execution timeout or error: {str(e)}'
                    }

        # Debug: Print what we're about to send
        print("DEBUG: Final results being sent to frontend:")
        for device, device_data in results.items():
            print(f"  Device: {device}, Status: {device_data.get('status')}")
            if device_data.get('status') == 'success':
                for cmd, cmd_data in device_data.get('commands', {}).items():
                    print(f"    Command: {cmd}")
                    print(f"      Output length: {len(cmd_data.get('output', ''))}")
                    print(f"      Translated length: {len(cmd_data.get('translated_output', ''))}")

        return jsonify({
            'success': True,
            'results': results
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

def extract_device_ip(device_string):
    """Extract IP address from 'hostname | IP' format or return as-is if already IP"""
    if ' | ' in device_string:
        # Format is 'hostname | IP', extract the IP part
        parts = device_string.split(' | ')
        return parts[1].strip() if len(parts) > 1 else parts[0].strip()
    # Already just an IP or hostname
    return device_string.strip()

@main_bp.route('/api/run-commands-stream', methods=['POST'])
def run_commands_stream():
    """API endpoint to run commands on multiple devices with Server-Sent Events streaming"""
    from flask import Response
    import json
    import queue
    import threading

    try:
        data = request.get_json()
        devices = data.get('devices', [])
        commands = data.get('commands', [])
        username = data.get('username', '')
        password = data.get('password', '')
        preferred_connector = data.get('preferred_connector', '')

        # Extract IP addresses from 'hostname | IP' format
        device_ips = [extract_device_ip(device) for device in devices]

        if not devices or not commands or not username or not password:
            return jsonify({
                'success': False,
                'error': 'Missing required parameters'
            })

        # Validate command safety
        for command in commands:
            is_safe, error_message = validate_command_safety(command)
            if not is_safe:
                audit_log = AuditLog(
                    user_id=current_user.id if current_user.is_authenticated else None,
                    action='command_execution_blocked',
                    details=f'Blocked unsafe command: "{command}" - {error_message}',
                    ip_address=request.remote_addr
                )
                db.session.add(audit_log)
                db.session.commit()

                return jsonify({
                    'success': False,
                    'error': f'Unsafe command rejected: {error_message}'
                })

        # Log command execution
        audit_log = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action='command_execution_started',
            details=f'Starting streaming command execution on {len(devices)} device(s): {", ".join(commands)}',
            ip_address=request.remote_addr
        )
        db.session.add(audit_log)
        db.session.commit()

        # Create a queue for results
        result_queue = queue.Queue()

        # Create mapping from IP to original display format
        ip_to_display = {}
        for i, device in enumerate(devices):
            ip_to_display[device_ips[i]] = device

        # Get app context before starting threads
        app = current_app._get_current_object()

        def execute_device_and_queue(device_ip, original_display, app_instance, pref_connector):
            """Execute commands on a device and put results in queue"""
            try:
                # Use app context for database operations
                with app_instance.app_context():
                    result = execute_commands_on_device(device_ip, commands, username, password, pref_connector)
                result_queue.put({
                    'type': 'device_complete',
                    'device': original_display,  # Use original display format
                    'data': result
                })
            except Exception as e:
                result_queue.put({
                    'type': 'device_complete',
                    'device': original_display,  # Use original display format
                    'data': {
                        'status': 'failed',
                        'error': f'Execution error: {str(e)}'
                    }
                })

        def generate():
            """Generator function for SSE"""
            # Start all device executions in parallel
            threads = []

            for i, device_ip in enumerate(device_ips):
                original_display = devices[i]
                thread = threading.Thread(target=execute_device_and_queue, args=(device_ip, original_display, app, preferred_connector))
                thread.start()
                threads.append(thread)

            # Send initial status
            yield f"data: {json.dumps({'type': 'started', 'total_devices': len(devices)})}\n\n"

            # Collect results as they come in
            devices_completed = 0
            while devices_completed < len(devices):
                try:
                    result = result_queue.get(timeout=120)  # 2 minute timeout
                    yield f"data: {json.dumps(result)}\n\n"
                    devices_completed += 1
                except queue.Empty:
                    # Timeout - send error for remaining devices
                    yield f"data: {json.dumps({'type': 'error', 'message': 'Timeout waiting for device responses'})}\n\n"
                    break

            # Wait for all threads to complete
            for thread in threads:
                thread.join(timeout=5)

            # Send completion message
            yield f"data: {json.dumps({'type': 'complete'})}\n\n"

        return Response(generate(), mimetype='text/event-stream')

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@main_bp.route('/api/download-results', methods=['POST'])
def download_results():
    """API endpoint to download command results as ZIP file"""
    import os
    try:
        data = request.get_json()
        results = data.get('results', {})
        session_name = data.get('session_name', '').strip()
        filename = data.get('filename', '')

        if not results:
            return jsonify({'error': 'No results to download'}), 400

        # Create output directory if it doesn't exist
        # Use Flask's root_path to get the project root directory
        project_root = os.path.dirname(current_app.root_path)
        output_dir = os.path.join(project_root, 'command-run-tool-output')
        os.makedirs(output_dir, exist_ok=True)

        # Debug logging
        print(f"DEBUG: Saving results to: {output_dir}")
        print(f"DEBUG: Project root: {project_root}")
        print(f"DEBUG: Flask root_path: {current_app.root_path}")

        # Create ZIP file in memory
        zip_buffer = io.BytesIO()

        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            for device, device_data in results.items():
                if device_data.get('status') == 'success':
                    # Create a file for each device
                    device_content = []
                    device_content.append(f"Device: {device}")
                    device_content.append(f"Timestamp: {datetime.now().isoformat()}")
                    device_content.append("=" * 50)
                    device_content.append("")

                    for command, command_data in device_data.get('commands', {}).items():
                        device_content.append(f"Command: {command}")
                        device_content.append("-" * 30)
                        device_content.append("")

                        # Use translated output if available, otherwise raw output
                        output = command_data.get('translated_output') or command_data.get('output', '')
                        device_content.append(output)
                        device_content.append("")
                        device_content.append("=" * 50)
                        device_content.append("")

                    # Clean device name for filename
                    safe_device_name = re.sub(r'[<>:"/\\|?*]', '_', device)
                    device_filename = f"{safe_device_name}_{timestamp}.txt"

                    zip_file.writestr(device_filename, '\n'.join(device_content))

                else:
                    # Create error file for failed devices
                    error_content = [
                        f"Device: {device}",
                        f"Timestamp: {datetime.now().isoformat()}",
                        f"Status: FAILED",
                        f"Error: {device_data.get('error', 'Unknown error')}"
                    ]

                    safe_device_name = re.sub(r'[<>:"/\\|?*]', '_', device)
                    error_filename = f"{safe_device_name}_{timestamp}_ERROR.txt"

                    zip_file.writestr(error_filename, '\n'.join(error_content))

        zip_buffer.seek(0)

        # Save a copy to the server
        if not filename:
            filename = f'command_results_{timestamp}.zip'

        server_filepath = os.path.join(output_dir, filename)
        with open(server_filepath, 'wb') as f:
            f.write(zip_buffer.getvalue())

        # Debug logging
        print(f"DEBUG: Saved file to: {server_filepath}")
        print(f"DEBUG: File exists: {os.path.exists(server_filepath)}")
        print(f"DEBUG: File size: {os.path.getsize(server_filepath) if os.path.exists(server_filepath) else 'N/A'}")

        # Reset buffer for download
        zip_buffer.seek(0)

        return send_file(
            zip_buffer,
            mimetype='application/zip',
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main_bp.route('/api/save-results', methods=['POST'])
def save_results():
    """API endpoint to save command results as ZIP file without downloading"""
    import os
    try:
        data = request.get_json()
        results = data.get('results', {})
        session_name = data.get('session_name', '').strip()
        filename = data.get('filename', '')

        if not results:
            return jsonify({'error': 'No results to save'}), 400

        # Create output directory if it doesn't exist
        project_root = os.path.dirname(current_app.root_path)
        output_dir = os.path.join(project_root, 'command-run-tool-output')
        os.makedirs(output_dir, exist_ok=True)

        # Create ZIP file in memory
        zip_buffer = io.BytesIO()

        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            for device, device_data in results.items():
                if device_data.get('status') == 'success':
                    # Create a file for each device
                    device_content = []
                    device_content.append(f"Device: {device}")
                    device_content.append(f"Timestamp: {datetime.now().isoformat()}")
                    device_content.append("=" * 50)
                    device_content.append("")

                    for command, command_data in device_data.get('commands', {}).items():
                        device_content.append(f"Command: {command}")
                        device_content.append("-" * 30)
                        device_content.append("")

                        # Use translated output if available, otherwise raw output
                        output = command_data.get('translated_output') or command_data.get('output', '')
                        device_content.append(output)
                        device_content.append("")
                        device_content.append("=" * 50)
                        device_content.append("")

                    # Clean device name for filename
                    safe_device_name = re.sub(r'[<>:"/\\|?*]', '_', device)
                    device_filename = f"{safe_device_name}_{timestamp}.txt"

                    zip_file.writestr(device_filename, '\n'.join(device_content))

                else:
                    # Create error file for failed devices
                    error_content = [
                        f"Device: {device}",
                        f"Timestamp: {datetime.now().isoformat()}",
                        f"Status: FAILED",
                        f"Error: {device_data.get('error', 'Unknown error')}"
                    ]

                    safe_device_name = re.sub(r'[<>:"/\\|?*]', '_', device)
                    error_filename = f"{safe_device_name}_{timestamp}_ERROR.txt"

                    zip_file.writestr(error_filename, '\n'.join(error_content))

        # Determine filename
        if not filename:
            filename = f'command_results_{timestamp}.zip'

        # Save to server
        server_filepath = os.path.join(output_dir, filename)
        with open(server_filepath, 'wb') as f:
            f.write(zip_buffer.getvalue())

        print(f"DEBUG: Saved file to: {server_filepath}")
        print(f"DEBUG: File exists: {os.path.exists(server_filepath)}")
        print(f"DEBUG: File size: {os.path.getsize(server_filepath) if os.path.exists(server_filepath) else 'N/A'}")

        return jsonify({
            'success': True,
            'filename': filename,
            'filepath': server_filepath
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main_bp.route('/api/saved-results', methods=['GET'])
def list_saved_results():
    """API endpoint to list all saved command results"""
    import os
    try:
        project_root = os.path.dirname(current_app.root_path)
        output_dir = os.path.join(project_root, 'command-run-tool-output')

        if not os.path.exists(output_dir):
            return jsonify([])

        results = []
        for filename in os.listdir(output_dir):
            if filename.endswith('.zip'):
                filepath = os.path.join(output_dir, filename)
                file_stats = os.stat(filepath)

                results.append({
                    'filename': filename,
                    'size': file_stats.st_size,
                    'created': datetime.fromtimestamp(file_stats.st_ctime).isoformat(),
                    'modified': datetime.fromtimestamp(file_stats.st_mtime).isoformat()
                })

        return jsonify(results)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main_bp.route('/api/saved-results/<filename>', methods=['GET'])
def download_saved_result(filename):
    """API endpoint to download a specific saved result file"""
    import os
    try:
        # Security: prevent directory traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return jsonify({'error': 'Invalid filename'}), 400

        project_root = os.path.dirname(current_app.root_path)
        output_dir = os.path.join(project_root, 'command-run-tool-output')
        filepath = os.path.join(output_dir, filename)

        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404

        return send_file(
            filepath,
            mimetype='application/zip',
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main_bp.route('/api/saved-results/<filename>', methods=['DELETE'])
def delete_saved_result(filename):
    """API endpoint to delete a specific saved result file"""
    import os
    try:
        # Security: prevent directory traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return jsonify({'error': 'Invalid filename'}), 400

        project_root = os.path.dirname(current_app.root_path)
        output_dir = os.path.join(project_root, 'command-run-tool-output')
        filepath = os.path.join(output_dir, filename)

        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404

        os.remove(filepath)
        return jsonify({'success': True, 'message': f'Deleted {filename}'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def perform_dns_lookup(target, dns_server=None, lookup_type='A'):
    """Perform DNS lookup for a single target"""
    try:
        resolver = dns.resolver.Resolver()

        # Set custom DNS server if provided
        if dns_server:
            resolver.nameservers = [dns_server]

        records = []

        # Always perform reverse DNS lookup for IP addresses
        if is_ip_address(target):
            try:
                reversed_dns = dns.reversename.from_address(target)
                answers = resolver.resolve(reversed_dns, 'PTR')
                for rdata in answers:
                    records.append({
                        'type': 'PTR',
                        'value': str(rdata).rstrip('.'),  # Remove trailing dot
                        'ttl': answers.ttl
                    })
            except Exception as e:
                records.append({
                    'type': 'PTR',
                    'value': f'No PTR record found',
                    'ttl': None
                })

        # Handle forward DNS lookups for domains
        elif not is_ip_address(target):
            # Skip PTR lookups for domain names
            if lookup_type == 'PTR':
                return {'error': 'PTR lookups are only valid for IP addresses'}

            lookup_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'] if lookup_type == 'ALL' else [lookup_type]

            for ltype in lookup_types:
                try:
                    answers = resolver.resolve(target, ltype)
                    for rdata in answers:
                        record_value = str(rdata)

                        # Format MX records nicely
                        if ltype == 'MX':
                            record_value = f"{rdata.preference} {rdata.exchange}"

                        # Remove trailing dots from domain names
                        if ltype in ['CNAME', 'NS']:
                            record_value = record_value.rstrip('.')

                        records.append({
                            'type': ltype,
                            'value': record_value,
                            'ttl': answers.ttl
                        })
                except dns.resolver.NoAnswer:
                    # No records of this type, continue
                    continue
                except Exception as e:
                    if lookup_type != 'ALL':  # Only show error if not doing ALL lookup
                        records.append({
                            'type': ltype,
                            'value': f'Error: {str(e)}',
                            'ttl': None
                        })

        if not records:
            return {'error': 'No records found'}

        return {'records': records}

    except Exception as e:
        return {'error': str(e)}

def is_ip_address(target):
    """Check if target is an IP address"""
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, target)
            return True
        except socket.error:
            return False

def validate_traceroute_target(target):
    """Validate a traceroute target for security and format compliance"""
    if not target or not isinstance(target, str):
        return False, "Target must be a non-empty string"

    target = target.strip()

    # Check for spaces or control characters
    if ' ' in target or any(ord(c) < 32 for c in target):
        return False, "Target contains invalid characters (spaces or control characters)"

    # Check length limits
    if len(target) > 253:
        return False, "Target too long (max 253 characters)"

    # IPv4 pattern validation
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, target):
        octets = target.split('.')
        for octet in octets:
            if int(octet) > 255:
                return False, "Invalid IPv4 address (octet > 255)"
        return True, "Valid IPv4 address"

    # IPv6 pattern validation (basic)
    if ':' in target:
        if re.match(r'^[0-9a-fA-F:]+$', target):
            return True, "Valid IPv6 address"
        return False, "Invalid IPv6 address format"

    # Hostname validation - only alphanumeric, dots, and hyphens allowed
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    if re.match(hostname_pattern, target):
        # Additional checks for hostname labels
        labels = target.split('.')
        for label in labels:
            if len(label) > 63:
                return False, "Hostname label too long (max 63 characters)"
            if label.startswith('-') or label.endswith('-'):
                return False, "Hostname labels cannot start or end with hyphens"
        return True, "Valid hostname"

    return False, "Invalid target format"

def validate_dns_target(target, lookup_type=None):
    """Validate a DNS lookup target for security and format compliance"""
    if not target or not isinstance(target, str):
        return False, "Target must be a non-empty string"

    target = target.strip()

    # Check for spaces or control characters
    if ' ' in target or any(ord(c) < 32 for c in target):
        return False, "Target contains invalid characters (spaces or control characters)"

    # Check length limits
    if len(target) > 253:
        return False, "Target too long (max 253 characters)"

    # IPv4 pattern validation
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, target):
        octets = target.split('.')
        for octet in octets:
            if int(octet) > 255:
                return False, "Invalid IPv4 address (octet > 255)"

        # IP addresses are valid for all lookup types
        return True, "Valid IPv4 address"

    # IPv6 pattern validation (basic)
    if ':' in target:
        if re.match(r'^[0-9a-fA-F:]+$', target):
            # IPv6 addresses are valid for all lookup types
            return True, "Valid IPv6 address"
        return False, "Invalid IPv6 address format"

    # Hostname validation - only alphanumeric, dots, and hyphens allowed
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    if re.match(hostname_pattern, target):
        # Additional checks for hostname labels
        labels = target.split('.')
        for label in labels:
            if len(label) > 63:
                return False, "Hostname label too long (max 63 characters)"
            if label.startswith('-') or label.endswith('-'):
                return False, "Hostname labels cannot start or end with hyphens"

        # Hostnames are valid for all lookup types
        return True, "Valid hostname"

    return False, "Invalid target format"

def validate_dns_server(server):
    """Validate a DNS server address"""
    if not server or not isinstance(server, str):
        return False, "DNS server must be a non-empty string"

    server = server.strip()

    # Check for spaces or control characters
    if ' ' in server or any(ord(c) < 32 for c in server):
        return False, "DNS server contains invalid characters"

    # IPv4 pattern validation
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, server):
        octets = server.split('.')
        for octet in octets:
            if int(octet) > 255:
                return False, "Invalid IPv4 address (octet > 255)"
        return True, "Valid IPv4 DNS server"

    # IPv6 pattern validation (basic)
    if ':' in server:
        if re.match(r'^[0-9a-fA-F:]+$', server):
            return True, "Valid IPv6 DNS server"
        return False, "Invalid IPv6 address format"

    return False, "DNS servers must be valid IP addresses"

@main_bp.route('/api/dns-lookup', methods=['POST'])
def dns_lookup():
    """API endpoint for DNS lookups"""
    try:
        data = request.get_json()
        targets = data.get('targets', [])
        servers = data.get('servers', [])
        lookup_type = data.get('lookup_type', 'A')

        if not targets:
            return jsonify({
                'success': False,
                'error': 'No targets provided'
            })

        # Validate all targets
        invalid_targets = []
        for target in targets:
            is_valid, message = validate_dns_target(target, lookup_type)
            if not is_valid:
                invalid_targets.append(f"{target}: {message}")

        # Validate all DNS servers
        invalid_servers = []
        for server in servers:
            is_valid, message = validate_dns_server(server)
            if not is_valid:
                invalid_servers.append(f"{server}: {message}")

        # Check for validation errors
        all_errors = invalid_targets + invalid_servers
        if all_errors:
            return jsonify({
                'success': False,
                'error': 'Invalid input(s) detected',
                'invalid_inputs': all_errors
            })

        results = {}

        # If no custom DNS servers specified, use system default
        if not servers:
            servers = [None]  # None means use system default

        for target in targets:
            target_results = {'servers': {}}

            for server in servers:
                server_key = server if server else 'system_default'

                try:
                    lookup_result = perform_dns_lookup(target, server, lookup_type)
                    target_results['servers'][server_key] = lookup_result
                except Exception as e:
                    target_results['servers'][server_key] = {'error': str(e)}

            results[target] = target_results

        return jsonify({
            'success': True,
            'results': results
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

def perform_traceroute(target, max_hops=30, timeout=3, probes_per_hop=3, packet_size=60, resolve_hostnames=True):
    """Perform traceroute to a single target"""
    try:
        system = platform.system()

        # Resolve hostname to IP if needed
        resolved_ip = None
        display_target = target
        if not is_ip_address(target):
            try:
                # Resolve hostname to IP
                resolved_ip = socket.gethostbyname(target)
                display_target = f"{target} ({resolved_ip})"
            except socket.gaierror:
                # If resolution fails, just use the original target
                display_target = target

        # Build the traceroute command based on OS
        if system == "Windows":
            # Windows tracert command
            cmd = ["tracert", "-h", str(max_hops), "-w", str(timeout * 1000), target]
        elif system == "Darwin":  # macOS
            # macOS traceroute command
            cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout), "-q", str(probes_per_hop)]
            if not resolve_hostnames:
                cmd.append("-n")
            cmd.append(target)
        else:  # Linux
            # Linux traceroute command
            cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout), "-q", str(probes_per_hop)]
            if packet_size != 60:
                cmd.extend(["-s", str(packet_size)])
            if not resolve_hostnames:
                cmd.append("-n")
            cmd.append(target)

        # Execute traceroute command
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )

        stdout, stderr = process.communicate(timeout=max_hops * timeout + 10)

        if process.returncode != 0 and stderr:
            return {'error': f'Traceroute failed: {stderr}'}

        # Parse the traceroute output
        hops = parse_traceroute_output(stdout, system)

        return {
            'hops': hops,
            'resolved_ip': resolved_ip,
            'display_target': display_target
        }

    except subprocess.TimeoutExpired:
        return {'error': 'Traceroute timeout exceeded'}
    except Exception as e:
        return {'error': str(e)}

def perform_streaming_traceroute(target, max_hops=30, timeout=3, probes_per_hop=3, packet_size=60, resolve_hostnames=True, translate_ips=True, app=None):
    """Perform traceroute and yield results hop by hop"""
    try:
        system = platform.system()

        # Resolve hostname to IP if needed
        resolved_ip = None
        display_target = target
        if not is_ip_address(target):
            try:
                # Resolve hostname to IP
                resolved_ip = socket.gethostbyname(target)
                display_target = f"{target} ({resolved_ip})"
            except socket.gaierror:
                # If resolution fails, just use the original target
                display_target = target

        # Build the traceroute command based on OS
        if system == "Windows":
            cmd = ["tracert", "-h", str(max_hops), "-w", str(timeout * 1000), target]
        elif system == "Darwin":  # macOS
            cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout), "-q", str(probes_per_hop)]
            if not resolve_hostnames:
                cmd.append("-n")
            cmd.append(target)
        else:  # Linux
            cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout), "-q", str(probes_per_hop)]
            if packet_size != 60:
                cmd.extend(["-s", str(packet_size)])
            if not resolve_hostnames:
                cmd.append("-n")
            cmd.append(target)

        # Execute traceroute with real-time output
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1  # Line buffered
        )

        # Yield initial message with resolved IP if available
        yield json.dumps({
            'type': 'start',
            'target': target,
            'resolved_ip': resolved_ip,
            'display_target': display_target,
            'message': f'Starting traceroute to {display_target}'
        }) + '\n'

        # Read output line by line
        for line in iter(process.stdout.readline, ''):
            if not line:
                break

            line = line.strip()
            if not line:
                continue

            # Skip header lines
            if 'traceroute to' in line.lower() or 'tracing route' in line.lower():
                continue
            if 'over a maximum' in line.lower() or 'hops max' in line.lower():
                continue

            # Parse hop line
            hop_data = parse_hop_line(line, system)
            if hop_data:
                # Add IP translation if requested
                if translate_ips:
                    for probe in hop_data.get('probes', []):
                        if probe.get('success') and probe.get('ip'):
                            translated = translate_traceroute_ip(probe['ip'], app)
                            if translated:
                                probe['translated_info'] = translated

                # Yield hop data
                yield json.dumps({
                    'type': 'hop',
                    'target': target,
                    'hop': hop_data
                }) + '\n'
            else:
                # Yield parse failure info for fallback display
                yield json.dumps({
                    'type': 'parse_fail',
                    'target': target,
                    'line': line
                }) + '\n'

        # Wait for process to complete
        process.wait()

        # Yield completion message
        yield json.dumps({
            'type': 'complete',
            'target': target,
            'message': f'Traceroute to {target} completed'
        }) + '\n'

    except Exception as e:
        yield json.dumps({
            'type': 'error',
            'target': target,
            'error': str(e)
        }) + '\n'

def parse_traceroute_output(output, system):
    """Parse traceroute output based on system type"""
    hops = []
    lines = output.strip().split('\n')

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Skip header lines
        if 'traceroute to' in line.lower() or 'tracing route' in line.lower():
            continue
        if 'over a maximum' in line.lower() or 'hops max' in line.lower():
            continue

        # Parse hop lines
        hop_data = parse_hop_line(line, system)
        if hop_data:
            hops.append(hop_data)

    return hops

def parse_hop_line(line, system):
    """Parse a single hop line from traceroute output"""
    import re

    # Try to extract hop number
    hop_match = re.match(r'^\s*(\d+)', line)
    if not hop_match:
        return None

    hop_num = int(hop_match.group(1))
    hop_data = {'hop_num': hop_num, 'probes': []}

    # Remove hop number from line
    line = line[hop_match.end():].strip()

    # Pattern for IP addresses
    ip_pattern = r'(?:\d{1,3}\.){3}\d{1,3}'

    # Pattern for RTT (round trip time)
    rtt_pattern = r'(\d+\.?\d*)\s*ms'

    # Pattern for hostnames
    hostname_pattern = r'([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})'

    # Find all RTTs in the line
    rtts = re.findall(rtt_pattern, line)

    # Find IP addresses
    ips = re.findall(ip_pattern, line)

    # Find hostnames
    hostnames = re.findall(hostname_pattern, line)

    if ips:
        # We have at least one response
        main_ip = ips[0]
        main_hostname = hostnames[0] if hostnames else None

        # Create probe entries for each RTT
        for rtt in rtts:
            probe = {
                'success': True,
                'ip': main_ip,
                'hostname': main_hostname,
                'rtt': rtt
            }
            hop_data['probes'].append(probe)
    else:
        # Check for timeouts (usually represented by *)
        stars = line.count('*')
        for _ in range(stars):
            hop_data['probes'].append({'success': False})

    return hop_data if hop_data['probes'] else None

def translate_traceroute_ip(ip_address, app=None):
    """Translate IP to hostname and interface info from database"""
    try:
        # If app context is provided, use it (for threaded execution)
        if app:
            with app.app_context():
                # Look for interface with this IP
                interface = Interface.query.join(Device).filter(
                    or_(
                        Interface.ipv4_address.like(f'{ip_address}/%'),
                        Interface.ipv4_address == ip_address
                    )
                ).first()

                if interface:
                    device = interface.device
                    # Shorten interface name
                    interface_short = interface.name.lower()
                    match = re.match(r'^([a-zA-Z]{2})[a-zA-Z]*(.*)$', interface.name)
                    if match:
                        interface_short = match.group(1).lower() + match.group(2)
                    else:
                        interface_short = interface.name[:2].lower()

                    return f"{device.hostname}-{interface_short}"
        else:
            # Look for interface with this IP (when already in app context)
            interface = Interface.query.join(Device).filter(
                or_(
                    Interface.ipv4_address.like(f'{ip_address}/%'),
                    Interface.ipv4_address == ip_address
                )
            ).first()

            if interface:
                device = interface.device
                # Shorten interface name
                interface_short = interface.name.lower()
                match = re.match(r'^([a-zA-Z]{2})[a-zA-Z]*(.*)$', interface.name)
                if match:
                    interface_short = match.group(1).lower() + match.group(2)
                else:
                    interface_short = interface.name[:2].lower()

                return f"{device.hostname}-{interface_short}"
    except Exception:
        pass

    return None

@main_bp.route('/api/traceroute-stream')
def traceroute_stream():
    """SSE endpoint for streaming traceroute results"""
    targets = request.args.get('targets', '').split(',')
    max_hops = int(request.args.get('max_hops', 30))
    timeout = int(request.args.get('timeout', 3))
    probes_per_hop = int(request.args.get('probes_per_hop', 3))
    packet_size = int(request.args.get('packet_size', 60))
    translate_ips = request.args.get('translate_ips', 'true').lower() == 'true'
    resolve_hostnames = request.args.get('resolve_hostnames', 'true').lower() == 'true'

    def generate():
        import queue
        import threading

        # Get Flask app instance for threaded DB access
        app = current_app._get_current_object()

        # Set SSE headers and send target list
        valid_targets = [t.strip() for t in targets if t.strip()]

        # Validate all targets
        invalid_targets = []
        validated_targets = []
        for target in valid_targets:
            is_valid, message = validate_traceroute_target(target)
            if not is_valid:
                invalid_targets.append(f"{target}: {message}")
            else:
                validated_targets.append(target)

        if invalid_targets:
            yield 'data: ' + json.dumps({
                'type': 'error',
                'message': 'Invalid targets detected',
                'invalid_targets': invalid_targets
            }) + '\n\n'
            return

        yield 'data: ' + json.dumps({'type': 'init', 'message': 'Initializing traceroutes', 'targets': validated_targets}) + '\n\n'

        if not validated_targets:
            yield 'data: ' + json.dumps({'type': 'all_complete', 'message': 'No valid targets'}) + '\n\n'
            return

        valid_targets = validated_targets

        # Create a shared queue for all traceroute results
        result_queue = queue.Queue()
        completed_targets = set()

        def target_worker(target):
            """Worker function to run traceroute for a single target"""
            try:
                for result in perform_streaming_traceroute(
                    target, max_hops, timeout, probes_per_hop,
                    packet_size, resolve_hostnames, translate_ips, app
                ):
                    result_queue.put(result)
                completed_targets.add(target)
            except Exception as e:
                error_message = json.dumps({
                    'type': 'error',
                    'target': target,
                    'error': str(e)
                })
                result_queue.put(error_message)
                completed_targets.add(target)

        # Start threads for each target
        threads = []
        for target in valid_targets:
            thread = threading.Thread(target=target_worker, args=(target,))
            thread.daemon = True
            thread.start()
            threads.append(thread)

        # Stream results as they come in from all threads
        while len(completed_targets) < len(valid_targets):
            try:
                # Wait for results from any thread
                result = result_queue.get(timeout=1.0)
                yield f'data: {result}\n'
            except queue.Empty:
                # Check if all threads are still alive
                alive_threads = [t for t in threads if t.is_alive()]
                if not alive_threads:
                    break
                continue

        # Drain any remaining results
        try:
            while True:
                result = result_queue.get_nowait()
                yield f'data: {result}\n'
        except queue.Empty:
            pass

        yield 'data: ' + json.dumps({'type': 'all_complete', 'message': 'All traceroutes completed'}) + '\n\n'

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

@main_bp.route('/api/traceroute', methods=['POST'])
def traceroute():
    """API endpoint for parallel traceroute operations"""
    try:
        data = request.get_json()
        targets = data.get('targets', [])
        max_hops = data.get('max_hops', 30)
        timeout = data.get('timeout', 3)
        probes_per_hop = data.get('probes_per_hop', 3)
        packet_size = data.get('packet_size', 60)
        translate_ips = data.get('translate_ips', True)
        resolve_hostnames = data.get('resolve_hostnames', True)

        if not targets:
            return jsonify({
                'success': False,
                'error': 'No targets provided'
            })

        # Validate all targets
        invalid_targets = []
        for target in targets:
            is_valid, message = validate_traceroute_target(target)
            if not is_valid:
                invalid_targets.append(f"{target}: {message}")

        if invalid_targets:
            return jsonify({
                'success': False,
                'error': 'Invalid targets detected',
                'invalid_targets': invalid_targets
            })

        results = {}

        # Use ThreadPoolExecutor for parallel traceroute execution
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_target = {
                executor.submit(
                    perform_traceroute,
                    target, max_hops, timeout, probes_per_hop, packet_size, resolve_hostnames
                ): target
                for target in targets
            }

            for future in future_to_target:
                target = future_to_target[future]
                try:
                    result = future.result(timeout=max_hops * timeout + 30)

                    # Add IP translation if requested
                    if translate_ips and 'hops' in result:
                        for hop in result['hops']:
                            for probe in hop.get('probes', []):
                                if probe.get('success') and probe.get('ip'):
                                    translated = translate_traceroute_ip(probe['ip'])
                                    if translated:
                                        probe['translated_info'] = translated

                    results[target] = result
                except Exception as e:
                    results[target] = {'error': f'Traceroute failed: {str(e)}'}

        return jsonify({
            'success': True,
            'results': results
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@main_bp.route('/api/curl-url', methods=['POST'])
def curl_url():
    """Execute curl command server-side and stream output via SSE"""
    import re
    from urllib.parse import urlparse

    data = request.get_json()
    url = data.get('url', '').strip()

    # Curl options
    follow_redirects = data.get('follow_redirects', False)
    include_headers = data.get('include_headers', False)
    headers_only = data.get('headers_only', False)
    verbose = data.get('verbose', False)
    user_agent = data.get('user_agent', '').strip()
    max_time = data.get('max_time', 30)
    request_method = data.get('request_method', 'GET').upper()
    custom_headers = data.get('custom_headers', [])

    # Validate URL
    if not url:
        return jsonify({'success': False, 'error': 'URL is required'})

    # Add http:// if no protocol specified
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # Validate URL format
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return jsonify({'success': False, 'error': 'Invalid URL format'})
    except Exception:
        return jsonify({'success': False, 'error': 'Invalid URL format'})

    # Build curl command
    curl_cmd = ['curl', '-s', '-w', '\\n--- Stats ---\\nHTTP Code: %{http_code}\\nTotal Time: %{time_total}s\\nSize: %{size_download} bytes\\n']

    if follow_redirects:
        curl_cmd.append('-L')

    if headers_only:
        curl_cmd.append('-I')
    elif include_headers:
        curl_cmd.append('-i')

    if verbose:
        curl_cmd.append('-v')

    if user_agent:
        curl_cmd.extend(['-A', user_agent])

    if max_time:
        curl_cmd.extend(['--max-time', str(max_time)])

    if request_method and request_method != 'GET' and not headers_only:
        curl_cmd.extend(['-X', request_method])

    # Add custom headers
    for header in custom_headers:
        if header.get('key') and header.get('value'):
            curl_cmd.extend(['-H', f"{header['key']}: {header['value']}"])

    curl_cmd.append(url)

    def generate():
        """Generator function to stream curl output"""
        try:
            import json

            # Send initial status
            yield f"data: {json.dumps({'type': 'status', 'message': 'Executing curl request...', 'command': ' '.join(curl_cmd)})}\n\n"

            # Execute curl command
            process = subprocess.Popen(
                curl_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            # Stream stdout
            for line in process.stdout:
                yield f"data: {json.dumps({'type': 'output', 'line': line.rstrip()})}\n\n"

            # Get stderr (for verbose mode)
            stderr_output = process.stderr.read()
            if stderr_output:
                for line in stderr_output.split('\n'):
                    if line.strip():
                        yield f"data: {json.dumps({'type': 'stderr', 'line': line.rstrip()})}\n\n"

            # Wait for process to complete
            return_code = process.wait()

            if return_code == 0:
                yield f"data: {json.dumps({'type': 'complete', 'message': 'Request completed successfully'})}\n\n"
            else:
                yield f"data: {json.dumps({'type': 'error', 'message': f'Curl exited with code {return_code}'})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

@main_bp.route('/api/tcp-handshake', methods=['POST'])
def tcp_handshake():
    """Capture and display TCP handshake packets using tcpdump"""
    import socket
    import re
    from urllib.parse import urlparse

    data = request.get_json()
    target = data.get('target', '').strip()
    port = data.get('port', 80)

    # Validate target
    if not target:
        return jsonify({'success': False, 'error': 'Target IP or domain is required'})

    # Validate port
    try:
        port = int(port)
        if port < 1 or port > 65535:
            return jsonify({'success': False, 'error': 'Port must be between 1 and 65535'})
    except (ValueError, TypeError):
        return jsonify({'success': False, 'error': 'Invalid port number'})

    # Resolve domain to IP if needed
    target_ip = target
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            return jsonify({'success': False, 'error': f'Could not resolve hostname: {target}'})

    def generate():
        """Generator function to stream TCP handshake capture"""
        try:
            import json
            import time
            import signal

            # Send initial status
            yield f"data: {json.dumps({'type': 'status', 'message': f'Resolving {target}...', 'resolved_ip': target_ip})}\n\n"

            # Use tcpdump to capture TCP handshake (SYN, SYN-ACK, ACK)
            # -i any: capture on any interface
            # -n: don't resolve hostnames
            # -S: print absolute sequence numbers
            # -c 10: capture up to 10 packets (handshake + extras)
            # tcp[tcpflags] & (tcp-syn|tcp-ack) != 0: capture SYN and ACK packets
            tcpdump_cmd = [
                'tcpdump',
                '-i', 'any',
                '-n',
                '-S',
                '-c', '10',
                f'host {target_ip} and port {port} and tcp'
            ]

            yield f"data: {json.dumps({'type': 'command', 'command': ' '.join(tcpdump_cmd)})}\n\n"
            yield f"data: {json.dumps({'type': 'status', 'message': f'Starting packet capture for {target_ip}:{port}...'})}\n\n"

            # Start tcpdump in background
            tcpdump_process = subprocess.Popen(
                tcpdump_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN)
            )

            # Give tcpdump time to start
            time.sleep(0.5)

            # Initiate TCP connection to trigger handshake
            yield f"data: {json.dumps({'type': 'status', 'message': f'Initiating TCP connection to {target_ip}:{port}...'})}\n\n"

            connection_thread_error = None
            def connect_to_target():
                nonlocal connection_thread_error
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((target_ip, port))
                    time.sleep(0.2)
                    sock.close()
                except Exception as e:
                    connection_thread_error = str(e)

            # Run connection in thread to not block tcpdump reading
            from threading import Thread
            connect_thread = Thread(target=connect_to_target)
            connect_thread.start()

            # Read tcpdump output
            packet_count = 0
            start_time = time.time()
            stderr_lines = []

            # Read stderr first (tcpdump info)
            while time.time() - start_time < 0.5:
                line = tcpdump_process.stderr.readline()
                if line:
                    stderr_lines.append(line.strip())

            # Read stdout (packet capture)
            for line in tcpdump_process.stdout:
                if line.strip():
                    packet_count += 1
                    yield f"data: {json.dumps({'type': 'packet', 'line': line.rstrip(), 'packet_num': packet_count})}\n\n"

                # Stop after reasonable number of packets or timeout
                if packet_count >= 10 or time.time() - start_time > 10:
                    break

            # Wait for connection thread
            connect_thread.join(timeout=2)

            # Terminate tcpdump
            tcpdump_process.terminate()
            tcpdump_process.wait(timeout=2)

            # Send tcpdump info
            if stderr_lines:
                yield f"data: {json.dumps({'type': 'info', 'lines': stderr_lines})}\n\n"

            if connection_thread_error:
                yield f"data: {json.dumps({'type': 'warning', 'message': f'Connection note: {connection_thread_error}'})}\n\n"

            if packet_count > 0:
                yield f"data: {json.dumps({'type': 'complete', 'message': f'Captured {packet_count} packets', 'packet_count': packet_count})}\n\n"
            else:
                yield f"data: {json.dumps({'type': 'error', 'message': 'No packets captured. Make sure you have sufficient permissions (may require sudo/root).'})}\n\n"

        except PermissionError:
            yield f"data: {json.dumps({'type': 'error', 'message': 'Permission denied. TCP packet capture requires elevated privileges (sudo/root).'})}\n\n"
        except FileNotFoundError:
            yield f"data: {json.dumps({'type': 'error', 'message': 'tcpdump not found. Please install tcpdump: brew install tcpdump (macOS) or apt-get install tcpdump (Linux)'})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': f'Error: {str(e)}'})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

# ==================== BGP Looking Glass API Endpoints ====================

@main_bp.route('/api/bgp-looking-glass/devices', methods=['GET'])
def get_bgp_looking_glass_devices():
    """Get list of devices configured for BGP Looking Glass"""
    try:
        from app.models import BgpLookingGlassDevice

        bgp_devices = BgpLookingGlassDevice.query.filter_by(enabled=True).all()

        devices_list = []
        for bgp_device in bgp_devices:
            device = bgp_device.device
            devices_list.append({
                'id': device.id,
                'hostname': device.hostname,
                'ip_address': device.ip_address,
                'vendor': device.vendor
            })

        return jsonify(devices_list)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@main_bp.route('/api/bgp-looking-glass/lookup', methods=['POST'])
def bgp_looking_glass_lookup():
    """Perform BGP Looking Glass lookup on selected devices with streaming output"""
    from flask import current_app, stream_with_context

    # Get request data from form or JSON
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form.to_dict()
        # Convert string values to proper types
        data['show_ip_route'] = data.get('show_ip_route') == 'true'
        data['show_ip_bgp'] = data.get('show_ip_bgp') == 'true'
        data['device_ids'] = json.loads(data.get('device_ids', '[]'))

    username = data.get('username')
    password = data.get('password')
    prefix = data.get('prefix', '').strip()
    show_ip_route = data.get('show_ip_route', False)
    show_ip_bgp = data.get('show_ip_bgp', False)
    device_ids = data.get('device_ids', [])

    # Validation
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if not prefix:
        return jsonify({'error': 'Prefix required'}), 400
    if not device_ids:
        return jsonify({'error': 'At least one device must be selected'}), 400

    @stream_with_context
    def generate():
        """Generator function to stream results as they become available"""
        from app.device_connectors.cisco_ios import CiscoIOSConnector
        from app.device_connectors.cisco_nxos import CiscoNXOSConnector
        from app.device_connectors.cisco_iosxr import CiscoIOSXRConnector
        from app.device_connectors.paloalto import PaloAltoConnector
        from app.device_connectors.fortigate import FortiGateConnector

        # Get devices from database
        devices = Device.query.filter(Device.id.in_(device_ids)).all()

        for device in devices:
            # Send device header
            yield f"data: {json.dumps({'type': 'device_start', 'hostname': device.hostname})}\n\n"

            try:
                # Determine connector based on device type
                connector_class = None
                if device.vendor == 'cisco_ios':
                    connector_class = CiscoIOSConnector
                elif device.vendor == 'cisco_nxos':
                    connector_class = CiscoNXOSConnector
                elif device.vendor == 'cisco_iosxr':
                    connector_class = CiscoIOSXRConnector
                elif device.vendor in ['paloalto', 'paloalto_panos']:
                    connector_class = PaloAltoConnector
                elif device.vendor in ['fortigate', 'fortinet']:
                    connector_class = FortiGateConnector
                else:
                    yield f"data: {json.dumps({'type': 'error', 'hostname': device.hostname, 'message': f'Unsupported device type: {device.vendor}'})}\n\n"
                    continue

                # Connect to device
                yield f"data: {json.dumps({'type': 'status', 'hostname': device.hostname, 'message': 'Connecting...'})}\n\n"
                connector = connector_class(device.ip_address, username, password)
                connector.connect()
                yield f"data: {json.dumps({'type': 'status', 'hostname': device.hostname, 'message': 'Connected'})}\n\n"

                # Build commands based on device type
                commands_to_run = []

                if show_ip_route:
                    if device.vendor in ['cisco_ios', 'cisco_nxos', 'cisco_iosxr']:
                        commands_to_run.append(f'show ip route {prefix}')
                    elif device.vendor in ['paloalto', 'paloalto_panos']:
                        commands_to_run.append(f'show routing route destination {prefix}')
                    elif device.vendor in ['fortigate', 'fortinet']:
                        commands_to_run.append(f'get router info routing-table details {prefix}')

                if show_ip_bgp:
                    if device.vendor in ['cisco_ios', 'cisco_nxos']:
                        commands_to_run.append(f'show ip bgp {prefix}')
                    elif device.vendor == 'cisco_iosxr':
                        commands_to_run.append(f'show bgp {prefix}')
                    elif device.vendor in ['paloalto', 'paloalto_panos']:
                        commands_to_run.append(f'show routing protocol bgp loc-rib prefix {prefix}')
                    elif device.vendor in ['fortigate', 'fortinet']:
                        commands_to_run.append(f'get router info bgp network {prefix}')

                # Execute commands and stream output
                for command in commands_to_run:
                    yield f"data: {json.dumps({'type': 'command', 'hostname': device.hostname, 'command': command})}\n\n"
                    output = connector.execute_command(command)
                    yield f"data: {json.dumps({'type': 'output', 'hostname': device.hostname, 'command': command, 'output': output})}\n\n"

                connector.disconnect()
                yield f"data: {json.dumps({'type': 'device_complete', 'hostname': device.hostname})}\n\n"

            except Exception as e:
                yield f"data: {json.dumps({'type': 'error', 'hostname': device.hostname, 'message': str(e)})}\n\n"

        # Send completion event
        yield f"data: {json.dumps({'type': 'complete'})}\n\n"

    return Response(generate(), mimetype='text/event-stream')
