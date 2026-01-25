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
        if not firebase_admin._apps:
            # Initialize from environment variable or service account file
            firebase_config = os.getenv('FIREBASE_CONFIG')
            
            if firebase_config:
                # Parse JSON config from environment variable
                try:
                    cred_dict = json.loads(firebase_config)
                    cred = credentials.Certificate(cred_dict)
                    print("[FIREBASE] Loading credentials from FIREBASE_CONFIG env")
                except json.JSONDecodeError as e:
                    print(f"[FIREBASE ERROR] Invalid JSON in FIREBASE_CONFIG: {e}")
                    raise e
            elif os.path.exists('QR_Attendance/firebase-credentials.json'):
                # Use service account file if exists (check QR_Attendance folder)
                print("[FIREBASE] Loading credentials from QR_Attendance/firebase-credentials.json")
                cred = credentials.Certificate('QR_Attendance/firebase-credentials.json')
            elif os.path.exists('firebase-credentials.json'):
                # Use service account file if exists (local path)
                print("[FIREBASE] Loading credentials from local file")
                cred = credentials.Certificate('firebase-credentials.json')
            else:
                # For Vercel/production, try GOOGLE_APPLICATION_CREDENTIALS env var
                google_creds = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
                if google_creds:
                    print("[FIREBASE] Loading credentials from GOOGLE_APPLICATION_CREDENTIALS env")
                    cred = credentials.Certificate(google_creds)
                else:
                    print("[FIREBASE] ERROR - No credentials found!")
                    print("[FIREBASE] Please set FIREBASE_CONFIG or GOOGLE_APPLICATION_CREDENTIALS env variable")
                    raise ValueError("Firebase credentials not configured. Set FIREBASE_CONFIG environment variable.")
            
            firebase_admin.initialize_app(cred)
            print("[FIREBASE] Initialized successfully")
        else:
            print("[FIREBASE] Already initialized")
    
    except Exception as e:
        print(f"[FIREBASE CRITICAL INIT ERROR] {e}")
        import traceback
        traceback.print_exc()
        raise e
    
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

# ==================== SYSTEM SUBJECTS ====================

def get_all_subjects():
    """Get all subjects for the dropdowns"""
    db = get_db()
    subjects = []
    for doc in db.collection('subjects').stream():
        data = doc.to_dict()
        data['id'] = doc.id
        subjects.append(data)
    return subjects

def add_system_subject(name):
    """Add a new subject to the system list"""
    db = get_db()
    # Check if exists
    existing = db.collection('subjects').where('name', '==', name).limit(1).get()
    if existing:
        return False, "Subject already exists"
    
    doc_ref = db.collection('subjects').document()
    doc_ref.set({'name': name})
    return True, doc_ref.id

def delete_system_subject(subject_id):
    """Delete a system subject"""
    db = get_db()
    db.collection('subjects').document(subject_id).delete()

# ==================== SEMESTER & HOLIDAYS ====================

def get_semester_config():
    """Get the semester configuration"""
    db = get_db()
    config = db.collection('settings').document('semester_config').get()
    if config.exists:
        return config.to_dict()
    # Default config
    return {
        'start_date': '2025-01-01',
        'end_date': '2025-06-30',
        'geo_enabled': False,
        'college_lat': 17.7816,
        'college_lng': 83.3768,
        'geo_radius': 200
    }

def update_semester_config(data):
    """Update semester configuration"""
    db = get_db()
    db.collection('settings').document('semester_config').set(data, merge=True)

def get_holidays():
    """Get list of holidays"""
    db = get_db()
    holidays = []
    for doc in db.collection('holidays').stream():
        data = doc.to_dict()
        data['id'] = doc.id
        holidays.append(data)
    # Sort by date
    holidays.sort(key=lambda x: x.get('date', ''))
    return holidays

def add_holiday(date, description):
    """Add a new holiday"""
    db = get_db()
    db.collection('holidays').add({
        'date': date,
        'description': description
    })

def delete_holiday(holiday_id):
    """Delete a holiday"""
    db = get_db()
    db.collection('holidays').document(holiday_id).delete()

# ==================== SESSION OPERATIONS ====================

def get_active_sessions(finalized=False):
    """Get sessions filtered by finalized status"""
    db = get_db()
    query = db.collection('sessions').where('is_finalized', '==', finalized)
    
    sessions = []
    for doc in query.stream():
        data = doc.to_dict()
        data['id'] = doc.id
        sessions.append(data)
    
    # Sort by date and time
    sessions.sort(key=lambda x: (x.get('date', ''), x.get('start_time', '')), reverse=True)
    return sessions

def restart_session(session_id, delete_absents=True):
    """Restart a finalized session"""
    db = get_db()
    batch = db.batch()
    
    session_ref = db.collection('sessions').document(session_id)
    batch.update(session_ref, {'is_finalized': False})
    
    if delete_absents:
        absent_records = db.collection('attendance')\
            .where('session_id', '==', session_id)\
            .where('status', '==', 'ABSENT').stream()
        for doc in absent_records:
            batch.delete(doc.reference)
            
    batch.commit()
    return True

def delete_session(session_id):
    """Delete a session and its attendance records"""
    db = get_db()
    batch = db.batch()
    
    # Delete attendance records
    attendance_docs = db.collection('attendance').where('session_id', '==', session_id).stream()
    for doc in attendance_docs:
        batch.delete(doc.reference)
        
    # Delete session
    batch.delete(db.collection('sessions').document(session_id))
    
    batch.commit()
    return True

def finalize_all_sessions(only_expired=True):
    """Finalize sessions (usually combined with app.py logic)"""
    db = get_db()
    # This is more of a wrapper, individual logic usually in app.py
    # but we can provide a way to mark all as finalized
    sessions = db.collection('sessions').where('is_finalized', '==', False).stream()
    count = 0
    for doc in sessions:
        doc.reference.update({'is_finalized': True})
        count += 1
    return count

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

def mark_attendance(session_id, student_roll_no, status='PRESENT', **kwargs):
    """Mark student attendance with optional extra metadata"""
    db = get_db()
    
    attendance_data = {
        'session_id': session_id,
        'roll': student_roll_no,
        'status': status,
        'timestamp': firestore.SERVER_TIMESTAMP,
        'marked_at': datetime.now().isoformat()
    }
    
    # Add any extra fields (subject, branch, etc.) for easy flat-query reports
    attendance_data.update(kwargs)
    
    attendance_ref = db.collection('attendance').document()
    attendance_ref.set(attendance_data)
    
    return attendance_ref.id

def log_sms(roll, phone, message, status, error_message=None):
    """Log an SMS notification"""
    db = get_db()
    log_data = {
        'roll': roll,
        'phone': phone,
        'message': message,
        'status': status,
        'error_message': error_message,
        'timestamp': firestore.SERVER_TIMESTAMP,
        'created_at': datetime.now().isoformat()
    }
    db.collection('sms_logs').add(log_data)

def get_sms_logs(limit=100):
    """Get recent SMS logs"""
    db = get_db()
    logs = []
    for doc in db.collection('sms_logs').order_by('timestamp', direction='DESCENDING').limit(limit).stream():
        data = doc.to_dict()
        data['id'] = doc.id
        logs.append(data)
    return logs

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

def get_attendance_history(roll=None, subject=None, branch=None, start_date=None, end_date=None):
    """Get attendance with multiple filters"""
    db = get_db()
    query = db.collection('attendance')
    
    if roll:
        query = query.where('roll', '==', roll)
    if subject:
        query = query.where('subject', '==', subject)
    if branch:
        query = query.where('branch', '==', branch)
    
    # Range queries in Firestore have limitations, but we'll try for start_date
    if start_date:
        query = query.where('date', '>=', start_date)
    if end_date:
        query = query.where('date', '<=', end_date)
        
    records = []
    for doc in query.stream():
        data = doc.to_dict()
        data['id'] = doc.id
        records.append(data)
    
    # Sort by date/time manually if needed
    records.sort(key=lambda x: (x.get('date', ''), x.get('time', '')), reverse=True)
    return records

def delete_attendance_record(record_id):
    """Delete a specific attendance record"""
    db = get_db()
    db.collection('attendance').document(record_id).delete()

# ==================== CORRECTION REQUESTS ====================

def submit_correction_request(roll, session_id, reason, proof_img=None):
    """Submit a correction request from student"""
    db = get_db()
    request_data = {
        'roll': roll,
        'session_id': session_id,
        'reason': reason,
        'proof_img': proof_img,
        'status': 'PENDING',
        'timestamp': firestore.SERVER_TIMESTAMP,
        'created_at': datetime.now().isoformat()
    }
    
    doc_ref = db.collection('correction_requests').document()
    doc_ref.set(request_data)
    return doc_ref.id

def get_correction_requests(roll=None, status=None):
    """Get correction requests with optional filters"""
    db = get_db()
    query = db.collection('correction_requests')
    
    if roll:
        query = query.where('roll', '==', roll)
    if status:
        query = query.where('status', '==', status)
        
    requests = []
    for doc in query.stream():
        data = doc.to_dict()
        data['id'] = doc.id
        # Try to join with session info if needed, or handle it in app.py
        requests.append(data)
    
    requests.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return requests

def handle_correction_request(request_id, action, admin_comment=''):
    """Approve or reject a correction request"""
    db = get_db()
    new_status = 'APPROVED' if action == 'APPROVE' else 'REJECTED'
    
    req_ref = db.collection('correction_requests').document(request_id)
    req_doc = req_ref.get()
    
    if not req_doc.exists:
        return False, "Request not found"
    
    req_data = req_doc.to_dict()
    
    # If approved, update attendance
    if action == 'APPROVE':
        roll = req_data['roll']
        session_id = req_data['session_id']
        
        # Mark student as present
        mark_attendance(session_id, roll)
        
    req_ref.update({
        'status': new_status,
        'admin_comment': admin_comment,
        'handled_at': firestore.SERVER_TIMESTAMP
    })
    return True, "Request updated"

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

def add_student_profile(roll, name, branch, parent_phone=None):
    """Add or update student profile"""
    db = get_db()
    student_data = {
        'roll': roll,
        'name': name,
        'branch': branch,
        'parent_phone': parent_phone,
        'updated_at': firestore.SERVER_TIMESTAMP
    }
    db.collection('students').document(roll).set(student_data, merge=True)

def get_all_students(branch=None):
    """Get all students, optionally filtered by branch"""
    db = get_db()
    query = db.collection('students')
    if branch:
        query = query.where('branch', '==', branch)
    
    students = []
    for doc in query.stream():
        data = doc.to_dict()
        data['id'] = doc.id
        students.append(data)
    return students

def delete_all_students():
    """Wipe the students collection (Admin only)"""
    db = get_db()
    # Note: For large collections, this should be batched
    docs = db.collection('students').stream()
    for doc in docs:
        doc.reference.delete()
