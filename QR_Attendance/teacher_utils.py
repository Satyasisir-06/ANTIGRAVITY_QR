"""
Teacher Role System - Backend Routes and Utilities
Handles teacher authentication, timetable uploads, and teacher-specific operations
"""

from flask import request, session, jsonify, flash, redirect, url_for, render_template
from functools import wraps
import csv
import io
from datetime import datetime
import sqlite3

def get_db_connection(db_name='attendance.db'):
    """Get database connection"""
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row
    return conn

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
        
        for row_num, row in enumerate(reader, start=2):  # Start at 2 because of header
            try:
                # Validate required fields
                required_fields = ['Teacher_ID', 'Teacher_Name', 'Email', 'Subject', 'Branch', 'Day', 'Time_Slot', 'Semester']
                for field in required_fields:
                    if field not in row or not row[field].strip():
                        return (False, f"Row {row_num}: Missing or empty field '{field}'")
                
                teacher_id = row['Teacher_ID'].strip()
                teacher_name = row['Teacher_Name'].strip()
                email = row['Email'].strip()
                subject = row['Subject'].strip()
                branch = row['Branch'].strip().upper()
                day = row['Day'].strip()
                time_slot = row['Time_Slot'].strip()
                semester = row['Semester'].strip()
                
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
                        'phone': row.get('Phone', '').strip() or None
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

# ==================== TEACHER DATA QUERIES ====================

def get_teacher_by_user_id(user_id):
    """Get teacher record by user_id"""
    conn = get_db_connection()
    teacher = conn.execute(
        "SELECT * FROM teachers WHERE user_id = ?",
        (user_id,)
    ).fetchone()
    conn.close()
    return teacher

def get_teacher_subjects(teacher_id, day=None):
    """Get subjects assigned to a teacher, optionally filtered by day"""
    conn = get_db_connection()
    
    if day:
        subjects = conn.execute("""
            SELECT * FROM teacher_subjects 
            WHERE teacher_id = ? AND day_of_week = ?
            ORDER BY time_slot
        """, (teacher_id, day)).fetchall()
    else:
        subjects = conn.execute("""
            SELECT * FROM teacher_subjects 
            WHERE teacher_id = ?
            ORDER BY day_of_week, time_slot
        """, (teacher_id,)).fetchall()
    
    conn.close()
    return subjects

def get_teacher_unique_subjects(teacher_id):
    """Get unique subject-branch combinations for a teacher"""
    conn = get_db_connection()
    subjects = conn.execute("""
        SELECT DISTINCT subject, branch 
        FROM teacher_subjects 
        WHERE teacher_id = ?
        ORDER BY subject, branch
    """, (teacher_id,)).fetchall()
    conn.close()
    return subjects

def can_teacher_create_session(teacher_id, subject, branch):
    """Check if teacher is assigned to teach this subject-branch combination"""
    conn = get_db_connection()
    result = conn.execute("""
        SELECT COUNT(*) as count FROM teacher_subjects
        WHERE teacher_id = ? AND subject = ? AND branch = ?
    """, (teacher_id, subject, branch)).fetchone()
    conn.close()
    return result['count'] > 0

# ==================== DATABASE OPERATIONS ====================

def insert_teachers_and_subjects(teachers_data, subjects_data):
    """
    Insert teachers and their subject assignments from timetable upload
    
    Returns:
        (success: bool, message: str, details: dict)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        teachers_added = 0
        teachers_updated = 0
        subjects_added = 0
        
        # Process each teacher
        for teacher_data in teachers_data:
            # Check if teacher exists
            existing = cursor.execute(
                "SELECT id FROM teachers WHERE teacher_id = ?",
                (teacher_data['teacher_id'],)
            ).fetchone()
            
            if existing:
                # Update existing teacher
                cursor.execute("""
                    UPDATE teachers 
                    SET name = ?, email = ?, phone = ?
                    WHERE teacher_id = ?
                """, (teacher_data['name'], teacher_data['email'], 
                      teacher_data['phone'], teacher_data['teacher_id']))
                teachers_updated += 1
                teacher_db_id = existing['id']
            else:
                # Insert new teacher
                cursor.execute("""
                    INSERT INTO teachers (teacher_id, name, email, phone)
                    VALUES (?, ?, ?, ?)
                """, (teacher_data['teacher_id'], teacher_data['name'], 
                      teacher_data['email'], teacher_data['phone']))
                teachers_added += 1
                teacher_db_id = cursor.lastrowid
        
        # Process subject assignments
        for subject_data in subjects_data:
            # Get teacher database ID
            teacher = cursor.execute(
                "SELECT id FROM teachers WHERE teacher_id = ?",
                (subject_data['teacher_id'],)
            ).fetchone()
            
            if not teacher:
                continue
            
            teacher_db_id = teacher['id']
            
            # Insert or replace subject assignment
            try:
                cursor.execute("""
                    INSERT INTO teacher_subjects 
                    (teacher_id, subject, branch, day_of_week, time_slot, semester)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (teacher_db_id, subject_data['subject'], subject_data['branch'],
                      subject_data['day_of_week'], subject_data['time_slot'], 
                      subject_data['semester']))
                subjects_added += 1
            except sqlite3.IntegrityError:
                # Update existing assignment
                cursor.execute("""
                    UPDATE teacher_subjects
                    SET semester = ?
                    WHERE teacher_id = ? AND subject = ? AND branch = ? 
                      AND day_of_week = ? AND time_slot = ?
                """, (subject_data['semester'], teacher_db_id, subject_data['subject'],
                      subject_data['branch'], subject_data['day_of_week'], 
                      subject_data['time_slot']))
        
        conn.commit()
        
        details = {
            'teachers_added': teachers_added,
            'teachers_updated': teachers_updated,
            'subjects_added': subjects_added
        }
        
        message = f"Success! Added {teachers_added} teachers, updated {teachers_updated}, assigned {subjects_added} subjects."
        
        return (True, message, details)
        
    except Exception as e:
        conn.rollback()
        return (False, f"Database error: {str(e)}", {})
    finally:
        conn.close()
