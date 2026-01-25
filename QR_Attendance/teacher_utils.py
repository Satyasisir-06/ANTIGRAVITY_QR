"""
Teacher Role System - Backend Routes and Utilities
Handles teacher authentication and timetable CSV parsing
Now updated to be Stateless / Firebase-compatible
"""

from flask import request, session, flash, redirect, url_for
from functools import wraps
import csv
import io
import re

# ==================== ROLE-BASED ACCESS DECORATORS ====================

def login_required(f):
    """Require user to be logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    """Require teacher role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        if session.get('role') != 'teacher':
            flash('Teacher access required', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def admin_or_teacher_required(f):
    """Require admin or teacher role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        if session.get('role') not in ['admin', 'teacher']:
            flash('Teacher or Admin access required', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== TIMETABLE CSV UPLOAD ====================

def parse_timetable_csv(file_stream):
    """
    Parse timetable CSV and return structured data
    
    Expected CSV format:
    Teacher_ID,Teacher_Name,Email,Subject,Branch,Day,Time_Slot,Semester
    
    Returns:
        (success: bool, data: list or error_message: str)
    """
    try:
        # Read CSV
        stream = io.StringIO(file_stream.read().decode('utf-8'))
        reader = csv.DictReader(stream)
        
        teachers = {}
        subjects = []
        
        # Normalize header keys to handle potential whitespace
        if reader.fieldnames:
            reader.fieldnames = [name.strip() for name in reader.fieldnames]

        for row_num, row in enumerate(reader, start=2):  # Start at 2 because of header
            try:
                # Validate required fields
                required_fields = ['Teacher_ID', 'Teacher_Name', 'Email', 'Subject', 'Branch', 'Day', 'Time_Slot', 'Semester']
                
                # Check mapping (handle potential casing or key errors)
                normalized_row = {k.strip(): v.strip() for k, v in row.items() if k}
                
                missing = []
                for field in required_fields:
                    if field not in normalized_row or not normalized_row[field]:
                        missing.append(field)
                
                if missing:
                    return (False, f"Row {row_num}: Missing fields: {', '.join(missing)}")
                
                teacher_id = normalized_row['Teacher_ID']
                teacher_name = normalized_row['Teacher_Name']
                email = normalized_row['Email']
                subject = normalized_row['Subject']
                branch = normalized_row['Branch'].upper()
                day = normalized_row['Day']
                time_slot = normalized_row['Time_Slot']
                semester = normalized_row['Semester']
                
                # Validate day
                valid_days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                if day not in valid_days:
                    return (False, f"Row {row_num}: Invalid day '{day}'. Must be one of {valid_days}")
                
                # Validate time slot format (HH:MM-HH:MM)
                if not validate_time_slot(time_slot):
                    return (False, f"Row {row_num}: Invalid time slot '{time_slot}'. Expected format: HH:MM-HH:MM")
                
                # Store teacher info
                if teacher_id not in teachers:
                    teachers[teacher_id] = {
                        'teacher_id': teacher_id,
                        'name': teacher_name,
                        'email': email,
                        'phone': normalized_row.get('Phone', '') or None
                    }
                
                # Store subject assignment
                subjects.append({
                    'teacher_id': teacher_id,
                    'subject': subject,
                    'branch': branch,
                    'day_of_week': day,
                    'time_slot': time_slot,
                    'semester': semester
                })
                
            except Exception as e:
                return (False, f"Row {row_num}: Error parsing - {str(e)}")
        
        return (True, {'teachers': list(teachers.values()), 'subjects': subjects})
        
    except Exception as e:
        return (False, f"CSV parsing error: {str(e)}")

def validate_time_slot(time_slot):
    """Validate time slot format HH:MM-HH:MM"""
    try:
        parts = time_slot.split('-')
        if len(parts) != 2:
            return False
        
        for time_str in parts:
            time_parts = time_str.strip().split(':')
            if len(time_parts) != 2:
                return False
            hour, minute = int(time_parts[0]), int(time_parts[1])
            if not (0 <= hour <= 23 and 0 <= minute <= 59):
                return False
        
        return True
    except:
        return False
