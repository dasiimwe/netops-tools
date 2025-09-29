from flask import render_template, redirect, url_for, request, jsonify, send_file, current_app
from flask_login import login_required, current_user
from app.routes import main_bp
from app.models import db, Device, Interface, User, AuditLog
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

@main_bp.route('/')
def index():
    """Index page with IP translator - no login required"""
    return render_template('index.html')

@main_bp.route('/dashboard')
@login_required
def dashboard():
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