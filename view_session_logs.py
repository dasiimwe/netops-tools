#!/usr/bin/env python3
"""
View session logs from the database
Usage: python view_session_logs.py [session_id]
"""
import sys
from app import create_app
from app.models import SessionLog, Device, User

def view_session_logs(session_id=None):
    """View session logs, optionally filtered by session_id"""
    app = create_app('development')

    with app.app_context():
        if session_id:
            logs = SessionLog.query.filter_by(session_id=session_id).order_by(SessionLog.timestamp).all()
            print(f"Session logs for session ID: {session_id}")
        else:
            logs = SessionLog.query.order_by(SessionLog.timestamp.desc()).limit(50).all()
            print("Latest 50 session log entries:")

        if not logs:
            print("No session logs found.")
            return

        print(f"\nFound {len(logs)} log entries:\n")

        current_session = None
        for log in logs:
            # Print session header when session changes
            if current_session != log.session_id:
                current_session = log.session_id
                device_name = log.device.hostname if log.device else "Unknown Device"
                user_name = log.user.username if log.user else "Unknown User"
                print(f"{'='*80}")
                print(f"Session: {log.session_id}")
                print(f"Device: {device_name} | User: {user_name}")
                print(f"{'='*80}")

            # Format timestamp
            timestamp = log.timestamp.strftime("%H:%M:%S.%f")[:-3]  # Remove last 3 digits from microseconds

            # Print log entry
            print(f"[{timestamp}] {log.event_type.upper()}")

            if log.command:
                # Truncate long commands for readability
                command_display = log.command[:100] + "..." if len(log.command) > 100 else log.command
                print(f"  Command: {command_display}")

            if log.response:
                # Show first few lines of response
                newline = '\n'
                response_lines = log.response.split(newline)[:3]
                response_display = newline.join(response_lines)
                num_response_lines = len(log.response.split(newline))
                if num_response_lines > 3:
                    response_display += f"\n  ... ({num_response_lines - 3} more lines)"
                indented_response = response_display.replace(newline, f'{newline}    ')
                print(f"  Response:\n    {indented_response}")

            if log.error_message:
                print(f"  Error: {log.error_message}")

            if log.duration_ms is not None:
                print(f"  Duration: {log.duration_ms}ms")

            print()

def list_recent_sessions():
    """List recent unique session IDs"""
    app = create_app('development')

    with app.app_context():
        # Get unique session IDs from last 24 hours
        from datetime import datetime, timedelta
        yesterday = datetime.now() - timedelta(days=1)

        sessions = SessionLog.query.filter(
            SessionLog.timestamp >= yesterday
        ).with_entities(
            SessionLog.session_id,
            SessionLog.timestamp
        ).distinct().order_by(SessionLog.timestamp.desc()).limit(10).all()

        if not sessions:
            print("No recent sessions found.")
            return

        print("Recent session IDs (last 24 hours):")
        for session_id, timestamp in sessions:
            print(f"  {session_id} - {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == '__main__':
    if len(sys.argv) == 2:
        if sys.argv[1] == '--list':
            list_recent_sessions()
        else:
            view_session_logs(sys.argv[1])
    else:
        print("Usage:")
        print("  python view_session_logs.py [session_id]  # View specific session")
        print("  python view_session_logs.py --list        # List recent sessions")
        print("  python view_session_logs.py               # View latest 50 entries")
        print()
        view_session_logs()