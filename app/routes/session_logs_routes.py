from flask import render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from app.models import SessionLog, Device, User, db
from app.routes import session_logs_bp
from datetime import datetime, timedelta
from sqlalchemy import func, desc, and_, or_


@session_logs_bp.route('/')
@login_required
def index():
    """Session logs main page"""
    # Get filter parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    session_id = request.args.get('session_id', '').strip()
    device_id = request.args.get('device_id', type=int)
    user_id = request.args.get('user_id', type=int)
    event_type = request.args.get('event_type', '').strip()
    hours_back = request.args.get('hours_back', 24, type=int)
    search = request.args.get('search', '').strip()

    # Build query
    query = SessionLog.query

    # Time filter
    if hours_back > 0:
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        query = query.filter(SessionLog.timestamp >= cutoff_time)

    # Session ID filter
    if session_id:
        query = query.filter(SessionLog.session_id.like(f'%{session_id}%'))

    # Device filter
    if device_id:
        query = query.filter(SessionLog.device_id == device_id)

    # User filter
    if user_id:
        query = query.filter(SessionLog.user_id == user_id)

    # Event type filter
    if event_type:
        query = query.filter(SessionLog.event_type == event_type)

    # Search filter (command, response, error_message)
    if search:
        search_filter = or_(
            SessionLog.command.like(f'%{search}%'),
            SessionLog.response.like(f'%{search}%'),
            SessionLog.error_message.like(f'%{search}%')
        )
        query = query.filter(search_filter)

    # Order by timestamp descending
    query = query.order_by(desc(SessionLog.timestamp))

    # Paginate
    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )
    logs = pagination.items

    # Get filter options for dropdowns
    devices = Device.query.order_by(Device.hostname).all()
    users = User.query.order_by(User.username).all()

    # Get unique event types from last 7 days
    week_ago = datetime.now() - timedelta(days=7)
    event_types = db.session.query(SessionLog.event_type).filter(
        SessionLog.timestamp >= week_ago
    ).distinct().order_by(SessionLog.event_type).all()
    event_types = [et[0] for et in event_types]

    return render_template('session_logs/index.html',
                         logs=logs,
                         pagination=pagination,
                         devices=devices,
                         users=users,
                         event_types=event_types,
                         filters={
                             'session_id': session_id,
                             'device_id': device_id,
                             'user_id': user_id,
                             'event_type': event_type,
                             'hours_back': hours_back,
                             'search': search,
                             'per_page': per_page
                         })


@session_logs_bp.route('/session/<session_id>')
@login_required
def view_session(session_id):
    """View all logs for a specific session"""
    logs = SessionLog.query.filter_by(session_id=session_id).order_by(SessionLog.timestamp).all()

    if not logs:
        flash(f'No logs found for session ID: {session_id}', 'warning')
        return redirect(url_for('session_logs.index'))

    # Get session metadata from first log
    first_log = logs[0]
    device = first_log.device
    user = first_log.user

    # Calculate session duration
    if len(logs) > 1:
        session_duration = (logs[-1].timestamp - logs[0].timestamp).total_seconds() * 1000
    else:
        session_duration = 0

    # Group logs by type for summary
    summary = {}
    for log in logs:
        if log.event_type not in summary:
            summary[log.event_type] = {'count': 0, 'total_duration': 0, 'errors': 0}
        summary[log.event_type]['count'] += 1
        if log.duration_ms:
            summary[log.event_type]['total_duration'] += log.duration_ms
        if log.error_message:
            summary[log.event_type]['errors'] += 1

    return render_template('session_logs/session_detail.html',
                         logs=logs,
                         session_id=session_id,
                         device=device,
                         user=user,
                         session_duration=session_duration,
                         summary=summary)


@session_logs_bp.route('/api/sessions')
@login_required
def api_sessions():
    """API endpoint to get recent session summaries"""
    hours_back = request.args.get('hours_back', 24, type=int)
    cutoff_time = datetime.now() - timedelta(hours=hours_back)

    # Get unique sessions with summary info
    sessions_query = db.session.query(
        SessionLog.session_id,
        func.min(SessionLog.timestamp).label('start_time'),
        func.max(SessionLog.timestamp).label('end_time'),
        func.count(SessionLog.id).label('event_count'),
        SessionLog.device_id,
        SessionLog.user_id
    ).filter(
        SessionLog.timestamp >= cutoff_time
    ).group_by(SessionLog.session_id).order_by(desc('start_time')).limit(100)

    sessions = []
    for session in sessions_query.all():
        # Get device and user info
        device = Device.query.get(session.device_id) if session.device_id else None
        user = User.query.get(session.user_id) if session.user_id else None

        # Check if session had errors
        has_errors = SessionLog.query.filter(
            SessionLog.session_id == session.session_id,
            SessionLog.error_message.isnot(None)
        ).first() is not None

        # Calculate duration
        duration_seconds = (session.end_time - session.start_time).total_seconds()

        sessions.append({
            'session_id': session.session_id,
            'start_time': session.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': session.end_time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration_seconds': round(duration_seconds, 2),
            'event_count': session.event_count,
            'device_name': device.hostname if device else 'Unknown',
            'user_name': user.username if user else 'Unknown',
            'has_errors': has_errors
        })

    return jsonify({'sessions': sessions})


@session_logs_bp.route('/api/stats')
@login_required
def api_stats():
    """API endpoint to get session log statistics"""
    hours_back = request.args.get('hours_back', 24, type=int)
    cutoff_time = datetime.now() - timedelta(hours=hours_back)

    # Total events
    total_events = SessionLog.query.filter(SessionLog.timestamp >= cutoff_time).count()

    # Events by type
    events_by_type = db.session.query(
        SessionLog.event_type,
        func.count(SessionLog.id).label('count')
    ).filter(
        SessionLog.timestamp >= cutoff_time
    ).group_by(SessionLog.event_type).all()

    # Error events
    error_events = SessionLog.query.filter(
        and_(
            SessionLog.timestamp >= cutoff_time,
            SessionLog.error_message.isnot(None)
        )
    ).count()

    # Unique sessions
    unique_sessions = db.session.query(SessionLog.session_id).filter(
        SessionLog.timestamp >= cutoff_time
    ).distinct().count()

    # Average command duration
    avg_command_duration = db.session.query(
        func.avg(SessionLog.duration_ms)
    ).filter(
        and_(
            SessionLog.timestamp >= cutoff_time,
            SessionLog.event_type == 'command_response',
            SessionLog.duration_ms.isnot(None)
        )
    ).scalar()

    return jsonify({
        'total_events': total_events,
        'events_by_type': [{'type': et[0], 'count': et[1]} for et in events_by_type],
        'error_events': error_events,
        'unique_sessions': unique_sessions,
        'avg_command_duration_ms': round(avg_command_duration or 0, 2),
        'time_period_hours': hours_back
    })


@session_logs_bp.route('/cleanup', methods=['POST'])
@login_required
def cleanup_logs():
    """Clean up old session logs"""
    if not current_user.is_admin:
        flash('Admin access required', 'error')
        return redirect(url_for('session_logs.index'))

    days_to_keep = request.form.get('days_to_keep', 30, type=int)

    if days_to_keep < 1:
        flash('Days to keep must be at least 1', 'error')
        return redirect(url_for('session_logs.index'))

    cutoff_date = datetime.now() - timedelta(days=days_to_keep)

    # Count logs to be deleted
    logs_to_delete = SessionLog.query.filter(SessionLog.timestamp < cutoff_date).count()

    if logs_to_delete == 0:
        flash(f'No logs older than {days_to_keep} days found', 'info')
        return redirect(url_for('session_logs.index'))

    # Delete old logs
    deleted_count = SessionLog.query.filter(SessionLog.timestamp < cutoff_date).delete()
    db.session.commit()

    flash(f'Successfully deleted {deleted_count} log entries older than {days_to_keep} days', 'success')
    return redirect(url_for('session_logs.index'))