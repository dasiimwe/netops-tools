from flask import render_template, redirect, url_for, request, jsonify
from flask_login import login_required, current_user
from app.routes import main_bp
from app.models import db, Device, Interface, User, AuditLog
from sqlalchemy import func, or_
from datetime import datetime, timedelta
import re

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

            # Create display format with bold blue hostname: ip(<b style="color: blue;">hostname</b>-interface)
            short_name = f"<b style=\"color: blue;\">{device.hostname}</b>-{interface.name}"
            if len(device.hostname) > 10:
                # Shorten hostname if too long
                short_name = f"<b style=\"color: blue;\">{device.hostname[:10]}...</b>-{interface.name}"

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
            enhanced_ip = f'<span class="ip-enhanced" data-ip="{ip}" data-tooltip="{tooltip_json}" data-mgmt-ip="{device.ip_address}">{display_text}</span>'
            ip_replacements[ip] = enhanced_ip

    # Apply replacements in order of longest IP first to avoid partial matches
    for ip in sorted(ip_replacements.keys(), key=len, reverse=True):
        translated_text = translated_text.replace(ip, ip_replacements[ip])

    return jsonify({'translated_text': translated_text})