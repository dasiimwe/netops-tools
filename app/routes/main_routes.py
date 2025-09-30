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
    return render_template('index.html')

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

def get_device_connector(device_ip, username, password):
    """Get appropriate device connector based on device type detection"""
    from app.device_connectors.cisco_ios import CiscoIOSConnector
    from app.device_connectors.cisco_nxos import CiscoNXOSConnector
    from app.device_connectors.cisco_iosxr import CiscoIOSXRConnector
    from app.device_connectors.paloalto import PaloAltoConnector
    from app.device_connectors.fortigate import FortiGateConnector

    # Try to detect device type by attempting connections
    # Start with Cisco IOS as most common
    connectors_to_try = [
        CiscoIOSConnector,
        CiscoNXOSConnector,
        CiscoIOSXRConnector,
        PaloAltoConnector,
        FortiGateConnector
    ]

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

def execute_commands_on_device_with_context(app, device_ip, commands, username, password):
    """Execute commands on a single device within Flask app context"""
    with app.app_context():
        return execute_commands_on_device(device_ip, commands, username, password)

def execute_commands_on_device(device_ip, commands, username, password):
    """Execute commands on a single device"""
    try:
        print(f"DEBUG: Attempting to connect to device: {device_ip}")
        connector = get_device_connector(device_ip, username, password)
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
        if 'test' in devices:
            sample_output = """Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0     192.168.1.1     YES NVRAM  up                    up
GigabitEthernet0/1     10.0.0.1        YES NVRAM  up                    up
GigabitEthernet0/2     unassigned      YES NVRAM  administratively down down
Loopback0              172.16.1.1      YES NVRAM  up                    up      """

            results = {}
            for device in devices:
                if device == 'test':
                    results[device] = {
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
                    result = execute_commands_on_device(device, commands, username, password)
                    results[device] = result

            return jsonify({
                'success': True,
                'results': results
            })

        results = {}

        # Use ThreadPoolExecutor for parallel execution
        app = current_app._get_current_object()  # Get the actual app instance
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_device = {
                executor.submit(execute_commands_on_device_with_context, app, device, commands, username, password): device
                for device in devices
            }

            for future in future_to_device:
                device = future_to_device[future]
                try:
                    result = future.result(timeout=60)  # 60 second timeout per device
                    results[device] = result
                except Exception as e:
                    results[device] = {
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

@main_bp.route('/api/download-results', methods=['POST'])
def download_results():
    """API endpoint to download command results as ZIP file"""
    try:
        data = request.get_json()
        results = data.get('results', {})

        if not results:
            return jsonify({'error': 'No results to download'}), 400

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
                    filename = f"{safe_device_name}_{timestamp}.txt"

                    zip_file.writestr(filename, '\n'.join(device_content))

                else:
                    # Create error file for failed devices
                    error_content = [
                        f"Device: {device}",
                        f"Timestamp: {datetime.now().isoformat()}",
                        f"Status: FAILED",
                        f"Error: {device_data.get('error', 'Unknown error')}"
                    ]

                    safe_device_name = re.sub(r'[<>:"/\\|?*]', '_', device)
                    filename = f"{safe_device_name}_{timestamp}_ERROR.txt"

                    zip_file.writestr(filename, '\n'.join(error_content))

        zip_buffer.seek(0)

        return send_file(
            zip_buffer,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'command_results_{timestamp}.zip'
        )

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

        return {'hops': hops}

    except subprocess.TimeoutExpired:
        return {'error': 'Traceroute timeout exceeded'}
    except Exception as e:
        return {'error': str(e)}

def perform_streaming_traceroute(target, max_hops=30, timeout=3, probes_per_hop=3, packet_size=60, resolve_hostnames=True, translate_ips=True):
    """Perform traceroute and yield results hop by hop"""
    try:
        system = platform.system()

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

        # Yield initial message
        yield json.dumps({
            'type': 'start',
            'target': target,
            'message': f'Starting traceroute to {target}'
        }) + '\n'

        # Read output line by line
        for line in iter(process.stdout.readline, ''):
            if not line:
                break

            line = line.strip()
            if not line:
                continue

            # Debug: yield raw line for debugging
            yield json.dumps({
                'type': 'debug',
                'target': target,
                'raw_line': line
            }) + '\n'

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
                            translated = translate_traceroute_ip(probe['ip'])
                            if translated:
                                probe['translated_info'] = translated

                # Yield hop data
                yield json.dumps({
                    'type': 'hop',
                    'target': target,
                    'hop': hop_data
                }) + '\n'
            else:
                # Debug: yield parse failure info
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

def translate_traceroute_ip(ip_address):
    """Translate IP to hostname and interface info from database"""
    try:
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

        # Set SSE headers and send target list
        valid_targets = [t.strip() for t in targets if t.strip()]
        yield 'data: ' + json.dumps({'type': 'init', 'message': 'Initializing traceroutes', 'targets': valid_targets}) + '\n\n'

        if not valid_targets:
            yield 'data: ' + json.dumps({'type': 'all_complete', 'message': 'No valid targets'}) + '\n\n'
            return

        # Create a shared queue for all traceroute results
        result_queue = queue.Queue()
        completed_targets = set()

        def target_worker(target):
            """Worker function to run traceroute for a single target"""
            try:
                for result in perform_streaming_traceroute(
                    target, max_hops, timeout, probes_per_hop,
                    packet_size, resolve_hostnames, translate_ips
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
