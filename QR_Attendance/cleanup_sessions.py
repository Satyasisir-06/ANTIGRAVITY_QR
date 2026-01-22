#!/usr/bin/env python3
"""
Session Cleanup Utility for QR Attendance System

This utility helps administrators manage and cleanup sessions that may not
have finalized properly. It can list active sessions and force finalization.

Usage:
    python cleanup_sessions.py --list              # List all active sessions
    python cleanup_sessions.py --finalize-all      # Finalize all expired sessions
    python cleanup_sessions.py --finalize <id>     # Finalize specific session
"""

import sqlite3
import argparse
from datetime import datetime
import sys
import os

# Ensure we can import from app.py
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

DB_NAME = "attendance.db"

def get_db_connection():
    """Get database connection with row factory"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def list_active_sessions():
    """List all active (unfinalized) sessions"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    sessions = cursor.execute(
        'SELECT * FROM sessions WHERE is_finalized = 0 ORDER BY date DESC, start_time DESC'
    ).fetchall()
    
    if not sessions:
        print("\n✓ No active sessions found. All sessions are finalized.\n")
        conn.close()
        return []
    
    print(f"\n📋 Found {len(sessions)} active session(s):\n")
    print("-" * 100)
    
    now = datetime.now()
    
    for s in sessions:
        session_id = s['id']
        subject = s['subject']
        branch = s['branch']
        class_type = s['class_type']
        date = s['date']
        start_time = s['start_time']
        end_time = s['end_time']
        
        # Check if expired
        end_dt_str = f"{date} {end_time}"
        try:
            end_dt = datetime.strptime(end_dt_str, "%Y-%m-%d %H:%M:%S")
            is_expired = now > end_dt
            status = "⚠️  EXPIRED" if is_expired else "✅ ACTIVE"
        except:
            status = "❓ UNKNOWN"
            
        print(f"ID: {session_id} | {subject} | {branch} | {class_type}")
        print(f"  Date: {date} | Start: {start_time} | End: {end_time}")
        print(f"  Status: {status}")
        print("-" * 100)
    
    conn.close()
    return sessions

def finalize_session(session_id):
    """Finalize a specific session using the app's finalization logic"""
    try:
        from app import finalize_session_logic
        
        print(f"\n🔄 Finalizing session {session_id}...")
        result = finalize_session_logic(session_id)
        
        if result['success']:
            if result.get('already_done'):
                print(f"✓ Session {session_id} was already finalized.")
            else:
                print(f"✓ Session {session_id} finalized successfully!")
                if 'absent_count' in result:
                    print(f"  {result['absent_count']} student(s) marked ABSENT")
        else:
            print(f"✗ Failed to finalize session {session_id}: {result.get('message', 'Unknown error')}")
            
        return result['success']
        
    except ImportError as e:
        print(f"✗ Error importing finalization logic: {e}")
        print("  Make sure app.py is in the same directory.")
        return False
    except Exception as e:
        print(f"✗ Error during finalization: {e}")
        return False

def finalize_all_expired():
    """Finalize all expired sessions"""
    sessions = list_active_sessions()
    
    if not sessions:
        return
    
    now = datetime.now()
    expired_sessions = []
    
    for s in sessions:
        end_dt_str = f"{s['date']} {s['end_time']}"
        try:
            end_dt = datetime.strptime(end_dt_str, "%Y-%m-%d %H:%M:%S")
            if now > end_dt:
                expired_sessions.append(s['id'])
        except:
            continue
    
    if not expired_sessions:
        print("\n✓ No expired sessions to finalize.\n")
        return
    
    print(f"\n🔄 Finalizing {len(expired_sessions)} expired session(s)...\n")
    
    success_count = 0
    for session_id in expired_sessions:
        if finalize_session(session_id):
            success_count += 1
    
    print(f"\n📊 Summary: {success_count}/{len(expired_sessions)} sessions finalized successfully.\n")

def main():
    parser = argparse.ArgumentParser(
        description='QR Attendance Session Cleanup Utility',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument('--list', action='store_true',
                       help='List all active (unfinalized) sessions')
    parser.add_argument('--finalize-all', action='store_true',
                       help='Finalize all expired sessions')
    parser.add_argument('--finalize', type=int, metavar='ID',
                       help='Finalize a specific session by ID')
    
    args = parser.parse_args()
    
    # If no arguments, show help
    if not any([args.list, args.finalize_all, args.finalize]):
        parser.print_help()
        return
    
    # Check if database exists
    if not os.path.exists(DB_NAME):
        print(f"✗ Error: Database '{DB_NAME}' not found.")
        print(f"  Please run this script from the QR_Attendance directory.")
        return
    
    # Execute requested action
    if args.list:
        list_active_sessions()
    
    if args.finalize:
        finalize_session(args.finalize)
    
    if args.finalize_all:
        finalize_all_expired()

if __name__ == '__main__':
    main()
