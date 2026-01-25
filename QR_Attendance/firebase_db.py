"""
Firebase Configuration and Database Operations
This replaces the SQLite/PostgreSQL database layer with Firebase Firestore
"""
import os
import json
import firebase_admin
from firebase_admin import credentials, firestore, auth
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Firebase
def initialize_firebase():
    """Initialize Firebase Admin SDK"""
    try:
        # Check if already initialized
        firebase_admin.get_app()
        print("[FIREBASE] Already initialized")
    except ValueError:
        # Initialize from environment variable or service account file
        firebase_config = os.getenv('FIREBASE_CONFIG')
        
        if firebase_config:
            # Parse JSON config from environment variable
            cred_dict = json.loads(firebase_config)
            cred = credentials.Certificate(cred_dict)
        elif os.path.exists('firebase-credentials.json'):
            # Use service account file if exists
            cred = credentials.Certificate('firebase-credentials.json')
        else:
            # For local development, use default credentials
            print("[FIREBASE] No credentials found, using default")
            firebase_admin.initialize_app()
            return firestore.client()
        
        firebase_admin.initialize_app(cred)
        print("[FIREBASE] Initialized successfully")
    
    return firestore.client()

# Global Firestore client
db = None

def get_db():
    """Get Firestore database client"""
    global db
    if db is None:
        db = initialize_firebase()
    return db

# ==================== USER OPERATIONS ====================

def create_user(username, password, role='student', email=None):
    """Create a new user"""
    db = get_db()
    
    # Hash password
    hashed_password = generate_password_hash(password)
    
    # Create user document
    user_data = {
        'username': username,
        'password': hashed_password,
        'role': role,
        'email': email,
        'created_at': firestore.SERVER_TIMESTAMP
    }
    
    # Use username as document ID for easy lookup
    user_ref = db.collection('users').document(username)
    user_ref.set(user_data)
    
    return user_ref.id

def get_user_by_username(username):
    """Get user by username"""
    db = get_db()
    user_ref = db.collection('users').document(username)
    user = user_ref.get()
    
    if user.exists:
        data = user.to_dict()
        data['id'] = user.id
        return data
    return None

def verify_user_password(username, password):
    """Verify user credentials"""
    user = get_user_by_username(username)
    if user and check_password_hash(user['password'], password):
        return user
    return None

# ==================== TEACHER OPERATIONS ====================

def create_teacher(teacher_id, name, email=None, phone=None, username=None):
    """Create teacher profile"""
    db = get_db()
    
    teacher_data = {
        'teacher_id': teacher_id,
        'name': name,
        'email': email,
        'phone': phone,
        'username': username or teacher_id,
        'created_at': firestore.SERVER_TIMESTAMP
    }
    
    teacher_ref = db.collection('teachers').document(teacher_id)
    teacher_ref.set(teacher_data)
    
    return teacher_ref.id

def get_teacher_by_username(username):
    """Get teacher by username"""
    db = get_db()
    
    # Query teachers where username matches
    teachers = db.collection('teachers').where('username', '==', username).limit(1).stream()
    
    for teacher in teachers:
        data = teacher.to_dict()
        data['id'] = teacher.id
        return data
    
    return None

def get_teacher_subjects(teacher_id):
    """Get all subjects for a teacher"""
    db = get_db()
    
    subjects = []
    subjects_ref = db.collection('teacher_subjects').where('teacher_id', '==', teacher_id).stream()
    
    for subject in subjects_ref:
        data = subject.to_dict()
        data['id'] = subject.id
        subjects.append(data)
    
    return subjects

def add_teacher_subject(teacher_id, subject, branch, day_of_week, time_slot, semester='2025-Spring'):
    """Add a subject to teacher's schedule"""
    db = get_db()
    
    subject_data = {
        'teacher_id': teacher_id,
        'subject': subject,
        'branch': branch,
        'day_of_week': day_of_week,
        'time_slot': time_slot,
        'semester': semester,
        'created_at': firestore.SERVER_TIMESTAMP
    }
    
    subject_ref = db.collection('teacher_subjects').document()
    subject_ref.set(subject_data)
    
    return subject_ref.id

def delete_teacher_subject(subject_id):
    """Delete a teacher subject"""
    db = get_db()
    db.collection('teacher_subjects').document(subject_id).delete()

# ==================== SESSION OPERATIONS ====================

def create_session(teacher_id, subject, branch, class_type, duration_hours=1):
    """Create an attendance session"""
    db = get_db()
    
    now = datetime.now()
    end_time = now.timestamp() + (duration_hours * 3600)
    
    session_data = {
        'teacher_id': teacher_id,
        'subject': subject,
        'branch': branch,
        'class_type': class_type,
        'start_time': now.timestamp(),
        'end_time': end_time,
        'is_finalized': False,
        'created_at': firestore.SERVER_TIMESTAMP
    }
    
    session_ref = db.collection('sessions').document()
    session_ref.set(session_data)
    
    return session_ref.id

def get_active_sessions(teacher_id=None):
    """Get active (non-finalized) sessions"""
    db = get_db()
    
    query = db.collection('sessions').where('is_finalized', '==', False)
    
    if teacher_id:
        query = query.where('teacher_id', '==', teacher_id)
    
    sessions = []
    for session in query.stream():
        data = session.to_dict()
        data['id'] = session.id
        sessions.append(data)
    
    return sessions

def finalize_session(session_id):
    """Finalize a session"""
    db = get_db()
    session_ref = db.collection('sessions').document(session_id)
    session_ref.update({'is_finalized': True})

# ==================== ATTENDANCE OPERATIONS ====================

def mark_attendance(session_id, student_roll_no):
    """Mark student attendance"""
    db = get_db()
    
    attendance_data = {
        'session_id': session_id,
        'student_roll_no': student_roll_no,
        'timestamp': firestore.SERVER_TIMESTAMP,
        'marked_at': datetime.now().isoformat()
    }
    
    attendance_ref = db.collection('attendance').document()
    attendance_ref.set(attendance_data)
    
    return attendance_ref.id

def get_session_attendance(session_id):
    """Get all attendance records for a session"""
    db = get_db()
    
    attendance_records = []
    records = db.collection('attendance').where('session_id', '==', session_id).stream()
    
    for record in records:
        data = record.to_dict()
        data['id'] = record.id
        attendance_records.append(data)
    
    return attendance_records

# ==================== STUDENT OPERATIONS ====================

def get_student_by_roll_no(roll_no):
    """Get student by roll number"""
    db = get_db()
    
    # First check if student exists in students collection
    student_ref = db.collection('students').document(roll_no)
    student = student_ref.get()
    
    if student.exists:
        data = student.to_dict()
        data['id'] = student.id
        return data
    
    # If not, check users collection
    user = get_user_by_username(roll_no)
    if user and user.get('role') == 'student':
        return {
            'id': roll_no,
            'roll_no': roll_no,
            'name': user.get('name', f'Student {roll_no}'),
            'branch': user.get('branch', 'Unknown')
        }
    
    return None
