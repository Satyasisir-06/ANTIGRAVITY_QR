from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, jsonify, send_file
from flask_socketio import SocketIO, emit
import firebase_db as db  # Firebase Database

import qrcode
import io
import base64
import time
import traceback
from datetime import datetime, timedelta
import os
import csv
import math
import socket
from werkzeug.security import generate_password_hash, check_password_hash
from sms_utils import SMSHandler
# psycopg2 and PostgreSQL imports removed as we are now using Firebase
from teacher_utils import (
    admin_required, teacher_required, admin_or_teacher_required,
    parse_timetable_csv
)

app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY', 'super_secret_key_for_qr_attendance_system')

# Vercel/Serverless configuration for SocketIO
# We force threading mode regardless of installed packages to avoid eventlet/gevent issues on Vercel
is_vercel = 'VERCEL' in os.environ or os.environ.get('VERCEL_ENV')

if is_vercel or os.environ.get('FUNCTION_TARGET'):
    print("[INIT] Running on Serverless (Vercel/Firebase). DISABLING SocketIO.")
    # Create a dummy class that does nothing, so the app doesn't crash on emit() calls
    class MockSocketIO:
        def __init__(self, app=None, **kwargs):
            if app:
                self.init_app(app)
        def init_app(self, app):
            pass
        def run(self, app, **kwargs):
            pass
        def emit(self, event, data, **kwargs):
            print(f"[MOCK SOCKET] Emitting {event}: {data}")
        def on(self, event):
            def decorator(f):
                return f
            return decorator
            
    socketio = MockSocketIO(app)
else:
    # For local dev, using full SocketIO
    socketio = SocketIO(app, cors_allowed_origins="*")

@app.errorhandler(500)
def handle_500(e):
    print(f"[CRITICAL] 500 Internal Server Error: {e}")
    traceback.print_exc()
    return f"Internal Server Error: {str(e)}", 500

@app.errorhandler(Exception)
def handle_exception(e):
    print(f"[CRITICAL] Unhandled Exception: {e}")
    traceback.print_exc()
    return f"An error occurred: {str(e)}", 500

# SMTP CONFIGURATION
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_EMAIL = "your_email@gmail.com"
SMTP_PASSWORD = "your_app_password"

# Haversine formula for geofencing
def haversine(lat1, lon1, lat2, lon2):
    R = 6371 * 1000 # Radius of Earth in meters
    dLat = math.radians(lat2 - lat1)
    dLon = math.radians(lon2 - lon1)
    a = math.sin(dLat/2) * math.sin(dLat/2) + \
        math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * \
        math.sin(dLon/2) * math.sin(dLon/2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    d = R * c
    return d

def calculate_working_days(start_date, end_date, holidays, include_future=False):
    """Calculate working days between two dates, excluding Sundays and holidays."""
    from datetime import datetime
    try:
        start = datetime.strptime(start_date, "%Y-%m-%d")
        end = datetime.strptime(end_date, "%Y-%m-%d")
        
        # If we don't want future days, limit end to today
        if not include_future:
            today = datetime.now()
            if end > today:
                end = today
                
        working_days = 0
        curr = start
        holiday_dates = [h.get('date') for h in holidays]
        
        while curr <= end:
            # 6 is Sunday
            if curr.weekday() != 6 and curr.strftime("%Y-%m-%d") not in holiday_dates:
                working_days += 1
            curr += timedelta(days=1)
        return working_days
    except Exception as e:
        print(f"[CALC DAYS ERROR] {e}")
        return 0

# Start Firebase lazily
@app.before_request
def init_firebase_lazy():
    if not getattr(app, '_firebase_initialized', False):
        try:
            print("[LAZY INIT] Initializing Firebase...")
            db.initialize_firebase()
            app._firebase_initialized = True
        except Exception as e:
            print(f"[LAZY INIT ERROR] {e}")
            app._firebase_initialized = False # Explicitly mark failed


@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif session.get('role') == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Verify credentials using Firebase
        user = db.verify_user_password(username, password)
        
        if user:
            session['user_id'] = user.get('id', username)
            session['username'] = user['username']
            user_role = user.get('role', 'student').lower()
            session['role'] = user_role
            
            print(f"[LOGIN DEBUG] User: {user['username']}, Role: {user_role}")
            
            if user_role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user_role == 'teacher':
                flash(f"Login successful! Welcome {username}", "success")
                return redirect(url_for('teacher_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            print(f"[LOGIN DEBUG] Login failed for username: {username}")
            flash("Invalid username or password", "danger")
            
    return render_template('login.html')

@app.route('/teacher/login')
def teacher_login():
    return render_template('login.html', extra_title="Teacher Login")

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register a new student or teacher"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'student')
        
        if not username or not password:
            flash("Username and Password required", "danger")
            return redirect(url_for('register'))

        # Capture extra fields
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        phone = request.form.get('phone')

        try:
            # Check if user already exists
            if db.get_user_by_username(username):
                flash(f"User {username} already exists", "danger")
                return redirect(url_for('register'))
            
            # Create user in Firebase
            db.create_user(username, password, role, email)
            
            # If teacher, create teacher profile
            if role == 'teacher':
                db.create_teacher(
                    teacher_id=username,
                    name=full_name or f"Teacher {username}",
                    email=email,
                    phone=phone,
                    username=username
                )
                print(f"[REGISTER] Created teacher profile for {username}")
                
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))
            
        except Exception as e:
            print(f"[REGISTER ERROR] {e}")
            flash(f"Error registering user: {str(e)}", "danger")
            return redirect(url_for('register'))

    return render_template('login.html', extra_title="Register", is_register=True)



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

app.permanent_session_lifetime = 1800 # 30 minutes session timeout

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    # Get active sessions from Firebase
    active_sessions = db.get_active_sessions()
    
    # Use 0 for stats for now (Firestore requires different approach for aggregation)
    # or we can implement counters later
    return render_template('admin.html', 
                            cse_count=0,
                            ece_count=0,
                            eee_count=0,
                            mech_count=0,
                            civil_count=0,
                            subjects=[],
                            active_sessions=active_sessions,
                            server_now=datetime.now().timestamp())

@app.route('/api/stats')
def api_stats():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
        
    # Get attendance for today from Firebase
    today_str = datetime.now().strftime("%Y-%m-%d")
    attendance = db.get_attendance_history(start_date=today_str, end_date=today_str)
    
    # Aggregate by branch
    stats = {'cse': 0, 'ece': 0, 'eee': 0, 'mech': 0, 'civil': 0}
    cse_branches = ['CAI', 'CSM', 'CSD', 'CSE-A', 'CSE-B', 'CSE-C', 'CSE-D']
    
    for rec in attendance:
        branch = rec.get('branch', '').upper()
        if branch in cse_branches:
            stats['cse'] += 1
        elif 'ECE' in branch:
            stats['ece'] += 1
        elif 'EEE' in branch:
            stats['eee'] += 1
        elif 'MECH' in branch:
            stats['mech'] += 1
        elif 'CIVIL' in branch:
            stats['civil'] += 1
            
    return jsonify(stats)

@app.route('/add_subject', methods=['POST'])
def add_subject():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    subject_name = request.json.get('name')
    if not subject_name:
         return jsonify({'success': False, 'message': 'Name required'})
         
    success, result = db.add_system_subject(subject_name)
    return jsonify({'success': success, 'message': result if not success else "Subject Added"})

@app.route('/delete_subject/<id>', methods=['POST'])
def delete_subject(id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    db.delete_system_subject(id)
    return jsonify({'success': True, 'message': 'Subject Deleted'})

@app.route('/register_student', methods=['POST'])
def register_student():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
         return jsonify({'success': False, 'message': 'Missing fields'})
         
    try:
        # Check if user already exists
        if db.get_user_by_username(username):
            return jsonify({'success': False, 'message': 'Username already exists'})
            
        # Create student user
        db.create_user(username, password, role='student')
        return jsonify({'success': True, 'message': "Student Registered"})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/student')
def student_dashboard():
    if 'user_id' not in session: 
        return redirect(url_for('login'))
    
    username = session['username']
    
    # Fetch data from Firebase
    config = db.get_semester_config()
    holidays = db.get_holidays()
    
    records = []
    corrections = []
    total_present = 0
    
    if session['role'] == 'student':
        # Fetch attendance history filtered by semester dates
        records = db.get_attendance_history(
            roll=username, 
            start_date=config['start_date'], 
            end_date=config['end_date']
        )
        
        # Count present records
        total_present = sum(1 for r in records if r.get('status') == 'PRESENT')
        
        # Fetch corrections
        corrections = db.get_correction_requests(roll=username)
    
    working_days = calculate_working_days(config['start_date'], config['end_date'], holidays, include_future=False)
    total_sem_days = calculate_working_days(config['start_date'], config['end_date'], holidays, include_future=True)
    
    percentage = 0.0
    if working_days > 0:
        percentage = (total_present / working_days) * 100
        
    return render_template('student.html', 
                           records=records, 
                           corrections=corrections,
                           username=username, 
                           total_present=total_present, 
                           working_days=working_days, 
                           total_sem_days=total_sem_days,
                           holidays=holidays,
                           config=config,
                           percentage=round(percentage, 2))

@app.route('/submit_correction', methods=['POST'])
def submit_correction():
    if 'user_id' not in session or session.get('role') != 'student':
        return redirect(url_for('login'))
        
    roll = session['username']
    reason = request.form.get('reason')
    session_id = request.form.get('session_id')
    
    if not reason:
        flash('Please provide a reason for your request.', 'danger')
        return redirect(url_for('student_dashboard'))
        
    # Proof image handling remains same (stores in static/proofs)
    proof_filename = None
    if 'proof' in request.files:
        file = request.files['proof']
        if file and file.filename != '':
            ext = file.filename.split('.')[-1]
            proof_filename = f"proof_{roll}_{int(time.time())}.{ext}"
            if not os.path.exists('static/proofs'):
                os.makedirs('static/proofs')
            try:
                file.save(os.path.join('static/proofs', proof_filename))
            except Exception as e:
                print(f"[Error] Saving proof: {e}")
            
    # Submit to Firebase
    db.submit_correction_request(roll, session_id, reason, proof_filename)
    
    flash('Correction request submitted! Admin will review it soon.', 'success')
    return redirect(url_for('student_dashboard'))

@app.route('/api/my_corrections')
def my_corrections():
    if 'user_id' not in session:
        return jsonify([])
        
    requests = db.get_correction_requests(roll=session['username'])
    return jsonify(requests)

@app.route('/admin/corrections')
def view_corrections():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    pending = db.get_correction_requests(status='PENDING')
    # Filter for history
    history = [r for r in db.get_correction_requests() if r.get('status') != 'PENDING'][:50]
    
    return render_template('admin_corrections.html', pending=pending, history=history)

@app.route('/api/handle_correction', methods=['POST'])
def handle_correction():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
        
    req_id = request.form.get('id')
    action = request.form.get('action') # 'APPROVE' or 'REJECT'
    comment = request.form.get('comment', '')
    
    if not req_id or not action:
        return jsonify({'success': False, 'message': 'Missing data'}), 400
        
    success, msg = db.handle_correction_request(req_id, action, comment)
    return jsonify({'success': success, 'message': msg})

# ============================================================================
# SESSION MANAGEMENT - REWRITTEN FOR RELIABILITY
# ============================================================================

@app.route('/start_session', methods=['POST'])
def start_session():
    """Start a new class/lab session and generate QR code."""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.json
    subject = data.get('subject')
    branch = data.get('branch')
    class_type = data.get('class_type', 'Lecture')
    
    if not subject or not branch:
        return jsonify({'success': False, 'message': 'Subject and Branch are required'}), 400
    
    # Calculate session times
    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    start_time = now.strftime("%H:%M:%S")
    
    duration = 3 if class_type == 'Lab' else 1
    end_dt = now + timedelta(hours=duration)
    end_time = end_dt.strftime("%H:%M:%S")
    
    # Generate unique token
    import uuid
    token = str(uuid.uuid4())
    
    try:
        # Create session in Firebase
        # We need to adapt the duration based on class type
        duration = 3 if class_type == 'Lab' else 1
        
        # In Firebase, we'll store additional info
        # We can use a custom function or the existing create_session
        session_id = db.create_session(
            teacher_id=session.get('user_id', 'admin'),
            subject=subject,
            branch=branch,
            class_type=class_type,
            duration_hours=duration
        )
        
        # To keep QR tokens working as before, we might need to update the session doc
        # Or modify db.create_session to include token.
        # Let's just use the doc ID as token for now, or add token field.
        import uuid
        token = str(uuid.uuid4())
        
        db.get_db().collection('sessions').document(session_id).update({
            'qr_token': token,
            'date': date_str,
            'start_time': start_time,
            'end_time': end_time
        })
        
        print(f"[SESSION START] Created session {session_id}: {subject} - {branch} ({class_type})")
        
    except Exception as e:
        print(f"[SESSION START ERROR] {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Failed to create session: {str(e)}'}), 500
    
    # Generate QR code
    base_url = request.host_url.rstrip('/')
    qr_url = f"{base_url}/scan_session?token={token}"
    
    try:
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_url)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')
        
        buf = io.BytesIO()
        img.save(buf)
        buf.seek(0)
        img_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        
    except Exception as e:
        print(f"[QR GENERATION ERROR] {e}")
        img_base64 = ''
    
    return jsonify({
        'success': True,
        'session_id': session_id,
        'qr_image': img_base64,
        'qr_url': qr_url,
        'token': token,
        'end_time': end_time,
        'start_timestamp': now.timestamp(),
        'end_timestamp': end_dt.timestamp(),
        'server_now': datetime.now().timestamp()
    })

@app.route('/get_qr_img/<token>')
def get_qr_img(token):
    # Use public host URL for production
    base_url = request.host_url.rstrip('/')
    qr_url = f"{base_url}/scan_session?token={token}"
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_url)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype='image/png')

@app.route('/scan')
@app.route('/scan_session')
@app.route('/scan_session')
def scan_session():
    token = request.args.get('token')
    if not token:
        return "Invalid Link", 400
        
    # Fetch session from Firebase
    sessions = db.get_db().collection('sessions').where('qr_token', '==', token).limit(1).get()
    
    if not sessions:
        return render_template('scan_session.html', error="Invalid or Expired Session Token")
    
    session_data = sessions[0].to_dict()
    session_data['id'] = sessions[0].id
    
    config = db.get_semester_config()
    
    if not session_data:
        return render_template('scan_session.html', error="Invalid or Expired Session Token")
    
    if session_data['is_finalized']:
        return render_template('scan_session.html', error="Class has ended. Attendance is finalized.")

    # QR Expiry Check (2 minutes from start_time)
    session_start_iso = f"{session_data['date']} {session_data['start_time']}"
    start_dt = datetime.strptime(session_start_iso, "%Y-%m-%d %H:%M:%S")
    
    if datetime.now() > start_dt + timedelta(minutes=2):
        return render_template('scan_session.html', error="QR Code Expired. Please contact faculty.")

    return render_template('scan_session.html', session_data=session_data, token=token, geo_enabled=config['geo_enabled'])

@app.route('/mark_session_attendance', methods=['POST'])
def mark_session_attendance():
    data = request.json
    roll = data.get('roll', '').strip().upper()
    name = data.get('name')
    token = data.get('token')

    # Prioritize logged-in student's roll number
    if 'user_id' in session and session.get('role') == 'student':
        roll = session['username'].strip().upper()
    
    # Geofence Validation
    config = db.get_semester_config()
    
    if config.get('geo_enabled'):
        lat = data.get('lat')
        lng = data.get('lng')
        
        if not lat or not lng:
            return jsonify({'success': False, 'message': 'Location access required for attendance!'})
            
        college_lat = config.get('college_lat', 0)
        college_lng = config.get('college_lng', 0)
        radius = config.get('geo_radius', 200)
        
        dist = haversine(float(lat), float(lng), college_lat, college_lng)
        print(f"[Geofence] User Dist: {dist}m | Allowed: {radius}m")
        
        if dist > radius:
            return jsonify({'success': False, 'message': f'You are too far from class! ({int(dist)}m away)'})

    if not all([roll, name, token]):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    try:
        # Fetch session from Firebase
        sessions = db.get_db().collection('sessions').where('qr_token', '==', token).limit(1).get()
        if not sessions:
            return jsonify({'success': False, 'message': 'Invalid Session Token'}), 404
            
        session_data = sessions[0].to_dict()
        session_data['id'] = sessions[0].id
    
        # Verify not finalized
        if session_data.get('is_finalized'):
            return jsonify({'success': False, 'message': 'Attendance period has ended. Session is finalized.'}), 400
          
        # Check if already marked
        existing = db.get_attendance_history(
            roll=roll,
            subject=session_data['subject'],
            start_date=session_data['date'],
            end_date=session_data['date']
        )
        
        if existing:
            return jsonify({'success': False, 'message': 'Attendance already marked for this subject today!'}), 400
        
        # Mark attendance in Firebase
        now_time = datetime.now().strftime("%H:%M:%S")
        db.mark_attendance(session_data['id'], roll)
        
        # Update attendance doc with more fields for compatibility
        # mark_attendance as currently written only takes session_id and student_roll_no
        # Let's add more details if needed, or just rely on the session join.
        # Actually, our attendance collection needs roll, name, subject, branch, date, time for legacy reports
        latest_att = db.get_db().collection('attendance').limit(1).order_by('timestamp', direction='DESCENDING').get()
        if latest_att:
            latest_att[0].reference.update({
                'roll': roll,
                'name': name,
                'subject': session_data['subject'],
                'branch': session_data['branch'],
                'date': session_data['date'],
                'time': now_time
            })
        
        print(f"[Attendance] {roll} marked PRESENT for {session_data['subject']} - {session_data['branch']}")
    
        
        # Real-time Update via SocketIO
        try:
            socketio.emit('new_attendance', {
                'session_id': session_data['id'],
                'roll': roll,
                'name': name,
                'branch': session_data['branch'],
                'time': now_time
            })
        except Exception as socket_err:
            print(f"[SocketIO Error] {socket_err}")
            # Don't fail the request if socket fails
        
        return jsonify({'success': True, 'message': 'Attendance Marked Successfully'})
        
    except DB_INTEGRITY_ERRORS as e:
        print(f"[Attendance Error] Duplicate entry: {e}")
        return jsonify({'success': False, 'message': 'Attendance already marked for this subject today!'}), 400
    except Exception as e:
        print(f"[Attendance Error] Unexpected error: {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error marking attendance: {str(e)}'}), 500

@app.route('/mark_attendance', methods=['POST'])
def mark_attendance():
    data = request.json
    roll = data.get('roll', '').strip().upper()
    name = data.get('name')
    subject = data.get('subject')
    branch = data.get('branch')
    exp = data.get('exp')
    
    if not all([roll, name, subject, branch, exp]):
        return jsonify({'success': False, 'message': 'Missing fields'})
        
    if time.time() > float(exp):
        return jsonify({'success': False, 'message': 'QR Code Expired!'})
        
    date_str = datetime.now().strftime("%Y-%m-%d")
    time_str = datetime.now().strftime("%H:%M:%S")
    
    conn = get_db_connection()
    
    # Check duplicate
    duplicate = conn.execute('''
        SELECT id FROM attendance 
        WHERE roll = ? AND date = ? AND subject = ? AND branch = ?
    ''', (roll, date_str, subject, branch)).fetchone()
    
    if duplicate:
        conn.close()
        return jsonify({'success': False, 'message': 'Attendance already marked for today!'})
        
    # Capture Security Info
    ip_addr = request.remote_addr
    user_agent = request.user_agent.string
    
    try:
        conn.execute('INSERT INTO attendance (roll, name, subject, branch, date, time, ip_address, device_info) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                     (roll, name, subject, branch, date_str, time_str, ip_addr, user_agent))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'message': 'Attendance already marked for today!'})
    conn.close()
    
    return jsonify({'success': True})

@app.route('/backup_db')
def backup_db():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    try:
        return flask_send_file(DB_NAME, as_attachment=True, download_name=f"attendance_backup_{int(time.time())}.db")
    except Exception as e:
        flash(f"Backup failed: {str(e)}", "danger")
        return redirect(url_for('admin_dashboard'))

@app.route('/view_attendance')
def view_attendance():
    if 'user_id' not in session:
         return redirect(url_for('login'))
         
    # Filters
    f_subject = request.args.get('subject', '')
    f_branch = request.args.get('branch', '')
    f_date = request.args.get('date', '')
    
    # Page
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Fetch from Firebase
    records = db.get_attendance_history(
        subject=f_subject if f_subject else None,
        branch=f_branch if f_branch else None,
        start_date=f_date if f_date else None,
        end_date=f_date if f_date else None
    )
    
    # Manual pagination for now (Firestore pagination is more complex)
    total = len(records)
    offset = (page - 1) * per_page
    records = records[offset : offset + per_page]
    
    subjects = db.get_all_subjects()
    
    return render_template('view_attendance.html', 
                            records=records, 
                            subjects=subjects,
                            f_subject=f_subject,
                            f_branch=f_branch,
                            f_date=f_date,
                            page=page,
                            total_pages=(total // per_page) + 1)

@app.route('/reports')
def reports_page():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    # Use /tmp for serverless to avoid Read-only error
    is_serverless = os.environ.get('VERCEL') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
    reports_dir = '/tmp' if is_serverless else os.path.join('static', 'reports')
    
    if not os.path.exists(reports_dir):
        try:
            os.makedirs(reports_dir)
        except OSError:
            pass # Ignore if we can't create it (e.g. read-only root), though /tmp should work
        
    reports = []
    for f in os.listdir(reports_dir):
        if f.endswith('.csv'):
            reports.append(f)
    reports.sort(reverse=True)
    return render_template('reports.html', reports=reports)

@app.route('/api/generate_report')
def trigger_report():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    filename = generate_weekly_report()
    return jsonify({'success': True, 'filename': filename})

def generate_weekly_report():
    # Fetch data from Firebase
    end_date = datetime.now()
    start_date = end_date - timedelta(days=7)
    
    start_str = start_date.strftime("%Y-%m-%d")
    end_str = end_date.strftime("%Y-%m-%d")
    
    attendance = db.get_attendance_history(start_date=start_str, end_date=end_str)
    
    filename = f"Weekly_Report_{start_str}_to_{end_str}.csv"
    reports_dir = '/tmp' if os.environ.get('VERCEL') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME') else os.path.join('static', 'reports')
    filepath = os.path.join(reports_dir, filename)
    
    if reports_dir != '/tmp':
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    branches = ['CSM', 'CSD', 'CSE-A', 'CSE-B', 'CSE-C', 'CSE-D', 'CIVIL', 'MECH', 'ECE', 'EEE']
    
    try:
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Weekly Attendance Report', f"{start_str} to {end_str}"])
            writer.writerow([])
            writer.writerow(['Branch', 'Total Records', 'Present', 'Absent', 'Percentage (%)'])
            
            for b in branches:
                b_records = [r for r in attendance if r.get('branch', '').upper() == b]
                total = len(b_records)
                if total > 0:
                    present = sum(1 for r in b_records if r.get('status') == 'PRESENT')
                    absent = total - present
                    pct = round((present/total)*100, 2)
                    writer.writerow([b, total, present, absent, pct])
                else:
                    writer.writerow([b, 0, 0, 0, 0.0])
                    
            writer.writerow([])
            writer.writerow(['--- Defaulters List (< 75% Overall) ---'])
            writer.writerow(['Roll No', 'Name', 'Branch', 'Total Classes', 'Attended', 'Percentage (%)'])
            
            # Simple aggregation for defaulters
            student_stats = {}
            for r in attendance:
                roll = r.get('roll')
                if roll not in student_stats:
                    student_stats[roll] = {'name': r.get('name'), 'branch': r.get('branch'), 'total': 0, 'present': 0}
                student_stats[roll]['total'] += 1
                if r.get('status') == 'PRESENT':
                    student_stats[roll]['present'] += 1
            
            for roll, s in student_stats.items():
                s_pct = round((s['present']/s['total'])*100, 2)
                if s_pct < 75:
                    writer.writerow([roll, s['name'], s['branch'], s['total'], s['present'], s_pct])
    except Exception as e:
        print(f"Error generating report: {e}")
                    
    return filename

@app.route('/analytics')
def analytics():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    return render_template('analytics.html')

@app.route('/api/analytics')
def api_analytics():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
        
    # Get attendance for last 7 days from Firebase
    end_date = datetime.now()
    start_date = end_date - timedelta(days=7)
    start_str = start_date.strftime("%Y-%m-%d")
    end_str = end_date.strftime("%Y-%m-%d")
    
    attendance = db.get_attendance_history(start_date=start_str, end_date=end_str)
    
    dates = []
    present_counts = []
    absent_counts = []
    
    for i in range(6, -1, -1):
        d = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        day_records = [r for r in attendance if r.get('date') == d]
        p = sum(1 for r in day_records if r.get('status') == 'PRESENT')
        # Absent tracking is harder in real-time unless we have a daily absent record
        # but for this system, we'll use 0 or calculate from daily master
        a = sum(1 for r in day_records if r.get('status') == 'ABSENT')
        dates.append(d)
        present_counts.append(p)
        absent_counts.append(a)
        
    # Branch Performance
    branches = ['CSM', 'CSD', 'CSE-A', 'CSE-B', 'CSE-C', 'CSE-D', 'CIVIL', 'MECH', 'ECE', 'EEE']
    branch_data = []
    for b in branches:
        b_records = [r for r in attendance if r.get('branch', '').upper() == b]
        total = len(b_records)
        if total == 0:
            branch_data.append(0)
        else:
            present = sum(1 for r in b_records if r.get('status') == 'PRESENT')
            pct = round((present / total) * 100, 1)
            branch_data.append(pct)
            
    return jsonify({
        'trends': {
            'labels': dates,
            'present': present_counts,
            'absent': absent_counts
        },
        'branches': {
            'labels': branches,
            'data': branch_data
        }
    })

@app.route('/class_records')
def class_records():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    selected_branch = request.args.get('branch')
    selected_group = request.args.get('group')
    
    records = []
    today_str = datetime.now().strftime("%Y-%m-%d")
    total_strength = 0
    present_count = 0
    absent_count = 0
    absentees = []
    
    if selected_branch:
        # Fetch records for this branch (History)
        records = db.get_attendance_history(branch=selected_branch)
        
        # Calculate Daily Report (Today)
        master_students = db.get_all_students(branch=selected_branch)
        total_strength = len(master_students)
        
        # Present Today
        present_records = [r for r in records if r.get('date') == today_str and r.get('status') == 'PRESENT']
        present_rolls = {r.get('roll') for r in present_records}
        present_count = len(present_rolls)
        
        if total_strength > 0:
            absent_count = max(0, total_strength - present_count)
            for s in master_students:
                if s.get('roll') not in present_rolls:
                    absentees.append(s)
        
    # All branches
    all_branches = ["CAI", "CSM", "CSD", "CSE-A", "CSE-B", "CSE-C", "CSE-D", "CIVIL", "MECH", "ECE", "EEE"]
    
    visible_branches = all_branches
    if selected_group == 'CSE':
        visible_branches = [b for b in all_branches if b in ['CAI', 'CSM', 'CSD', 'CSE-A', 'CSE-B', 'CSE-C', 'CSE-D']]
    elif selected_group:
        visible_branches = [b for b in all_branches if b == selected_group]
    
    return render_template('class_records.html', 
                           branches=visible_branches, 
                           selected_branch=selected_branch, 
                           records=records, 
                           group=selected_group,
                           total_strength=total_strength,
                           present_count=present_count,
                           absent_count=absent_count,
                           absentees=absentees)

@app.route('/settings')
def settings():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    config = db.get_semester_config()
    raw_holidays = db.get_holidays()
    
    # Simple Grouping logic for UI (Same as before but using Firestore data)
    from itertools import groupby
    grouped_holidays = []
    for desc, items in groupby(raw_holidays, lambda x: x.get('description')):
        item_list = list(items)
        if len(item_list) > 1:
            start_h = item_list[0]
            end_h = item_list[-1]
            grouped_holidays.append({
                'id': start_h['id'],
                'ids': [i['id'] for i in item_list],
                'date_display': f"{start_h.get('date')} to {end_h.get('date')}",
                'description': desc
            })
        else:
            h = item_list[0]
            grouped_holidays.append({
                'id': h['id'],
                'ids': [h['id']],
                'date_display': h.get('date'),
                'description': desc
            })
            
    return render_template('settings.html', config=config, holidays=grouped_holidays)

@app.route('/update_semester_dates', methods=['POST'])
def update_semester_dates():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    start_date = request.form['start_date']
    end_date = request.form['end_date']
    
    db.update_semester_config({
        'start_date': start_date,
        'end_date': end_date
    })
    
    flash("Semester dates updated!", "success")
    return redirect(url_for('settings'))

@app.route('/update_geofencing', methods=['POST'])
def update_geofencing():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    geo_enabled = 'geo_enabled' in request.form
    import re
    def clean_coord(val):
        if not val: return 0.0
        cleaned = re.sub(r'[^0-9\.-]', '', str(val))
        try: return float(cleaned)
        except: return 0.0

    college_lat = clean_coord(request.form.get('college_lat'))
    college_lng = clean_coord(request.form.get('college_lng'))
    geo_radius = int(request.form.get('geo_radius', 200))
    
    db.update_semester_config({
        'geo_enabled': geo_enabled,
        'college_lat': college_lat,
        'college_lng': college_lng,
        'geo_radius': geo_radius
    })
    
    flash("Geofencing settings updated!", "success")
    return redirect(url_for('settings'))

@app.route('/update_sms_config', methods=['POST'])
def update_sms_config():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    sms_enabled = 'sms_enabled' in request.form
    sms_sid = request.form.get('sms_sid', '').strip()
    sms_auth_token = request.form.get('sms_auth_token', '').strip()
    sms_from_number = request.form.get('sms_from_number', '').strip()
    sms_threshold = request.form.get('sms_threshold')
    
    try:
        sms_threshold = int(sms_threshold) if sms_threshold else 75
    except ValueError:
        sms_threshold = 75
        
    db.update_semester_config({
        'sms_enabled': sms_enabled,
        'sms_sid': sms_sid,
        'sms_auth_token': sms_auth_token,
        'sms_from_number': sms_from_number,
        'sms_threshold': sms_threshold
    })
    
    flash('SMS Configuration updated successfully!', 'success')
    return redirect(url_for('settings'))

@app.route('/sms_logs')
def sms_logs():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    logs = db.get_sms_logs()
    return render_template('sms_logs.html', logs=logs)






@app.route('/delete_holiday/<id>', methods=['POST'])
def delete_holiday(id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    db.delete_holiday(id)
    return jsonify({'success': True})

@app.route('/delete_holidays_bulk', methods=['POST'])
def delete_holidays_bulk():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    data = request.json
    ids = data.get('ids', [])
    for holiday_id in ids:
        db.delete_holiday(holiday_id)
    return jsonify({'success': True})

def calculate_working_days(start_str, end_str, holidays, include_future=False):
    # Convert strings to date objects
    start = datetime.strptime(start_str, "%Y-%m-%d").date()
    end = datetime.strptime(end_str, "%Y-%m-%d").date()
    today = datetime.now().date()
    
    # If include_future is False, we only count up to Today or End Date
    if include_future:
        calc_end = end
    else:
        calc_end = min(today, end)
    
    if start > calc_end:
        return 0
        
    total_days = (calc_end - start).days + 1
    
    # Subtract Sundays
    sundays = 0
    for i in range(total_days):
        day = start + timedelta(days=i)
        if day.weekday() == 6: # 6 is Sunday
            sundays += 1
            
    # Subtract Holidays (that fall within the range and are NOT Sundays)
    holiday_count = 0
    holiday_dates = [datetime.strptime(h['date'], "%Y-%m-%d").date() for h in holidays]
    
    for h_date in holiday_dates:
        if start <= h_date <= calc_end and h_date.weekday() != 6:
            holiday_count += 1
            
    working_days = total_days - sundays - holiday_count
    return max(0, working_days)

@app.route('/delete_record/<id>', methods=['POST'])
def delete_record(id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    db.delete_attendance_record(id)
    return jsonify({'success': True})

@app.route('/upload_students', methods=['POST'])
def upload_students():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('settings'))
        
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('settings'))
        
    if file:
        try:
            stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
            csv_input = csv.reader(stream)
            data = list(csv_input)
            if not data:
                flash('Empty CSV', 'danger')
                return redirect(url_for('settings'))
                
            header = [h.lower() for h in data[0]]
            start_idx = 0
            if 'roll' in header or 'roll no' in header or 'name' in header:
                start_idx = 1
                
            # Clear old students if requested
            if 'replace_all' in request.form:
                db.delete_all_students()
            
            count = 0
            for i in range(start_idx, len(data)):
                row = data[i]
                if len(row) >= 3:
                     roll = row[0].strip()
                     name = row[1].strip()
                     branch = row[2].strip()
                     p_phone = row[3].strip() if len(row) > 3 else None
                     
                     db.add_student_profile(roll, name, branch, p_phone)
                     count += 1
            
            flash(f'Successfully imported {count} students!', 'success')
        except Exception as e:
            flash(f'Error processing file: {str(e)}', 'danger')
            
    return redirect(url_for('settings'))

@app.route('/add_student_manual', methods=['POST'])
def add_student_manual():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
        
    data = request.json
    roll = data.get('roll')
    name = data.get('name')
    branch = data.get('branch')
    p_phone = data.get('parent_phone')
    
    if not all([roll, name, branch]):
        return jsonify({'success': False, 'message': 'Missing fields'})
        
    try:
        db.add_student_profile(roll, name, branch, p_phone)
        return jsonify({'success': True, 'message': "Student saved successfully"})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

def send_sms(to_phone, message):
    if not to_phone:
        return False, "No phone number"
        
    # MOCK SMS - replace with Twilio/Fast2SMS in production
    print(f"\n[MOCK SMS] To: {to_phone} | Message: {message}\n")
    return True, "Mock SMS Sent"

@app.route('/notify_absent', methods=['POST'])
def notify_absent():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    data = request.json
    target = data.get('target') # 'single' or 'all'
    today_str = datetime.now().strftime("%Y-%m-%d")
    students_to_notify = []
    
    if target == 'single':
        roll = data.get('roll')
        student = db.get_student_by_roll_no(roll)
        if student:
            students_to_notify.append(student)
            
    elif target == 'branch':
        branch = data.get('branch')
        all_students = db.get_all_students(branch=branch)
        # Get present rolls from Firebase
        present = db.get_attendance_history(branch=branch, start_date=today_str, end_date=today_str)
        present_rolls = {r.get('roll') for r in present if r.get('status') == 'PRESENT'}
        
        for s in all_students:
            if s.get('roll') not in present_rolls:
                students_to_notify.append(s)
                
    config = db.get_semester_config()
    if not config.get('sms_enabled'):
        return jsonify({'success': False, 'message': 'SMS Not Enabled in Settings', 'sent': 0, 'total': 0, 'errors': []})
        
    sms_handler = SMSHandler(config.get('sms_sid'), config.get('sms_auth_token'), config.get('sms_from_number'))
    sent_count = 0
    errors = []
    
    for s in students_to_notify:
        phone = s.get('parent_phone')
        if phone:
            now_time = datetime.now().strftime("%I:%M %p")
            subject_text = f" for '{data.get('subject', 'Classes')}'" 
            msg = f"[Chaitanya Engineering College] Absent Alert: {s.get('name')} ({s.get('roll')}) was absent{subject_text} on {today_str} (Reported: {now_time})."
            
            success, status = sms_handler.send_sms(phone, msg)
            if success:
                sent_count += 1
                db.log_sms(s.get('roll'), phone, msg, 'SENT')
            else:
                errors.append(f"{s.get('roll')}: {status}")
                db.log_sms(s.get('roll'), phone, msg, 'FAILED', status)

    return jsonify({
        'success': True, 
        'sent': sent_count, 
        'total': len(students_to_notify),
        'errors': errors
    })

@app.route('/add_holiday', methods=['POST'])
def add_holiday():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    data = request.json
    start_date_str = data.get('date')
    end_date_str = data.get('end_date') # Optional
    desc = data.get('description')
    
    if not start_date_str or not desc:
        return jsonify({'success': False, 'message': 'Missing data'}), 400
        
    try:
        start_dt = datetime.strptime(start_date_str, "%Y-%m-%d")
        if end_date_str:
            end_dt = datetime.strptime(end_date_str, "%Y-%m-%d")
        else:
            end_dt = start_dt
            
        current_dt = start_dt
        while current_dt <= end_dt:
            date_str = current_dt.strftime("%Y-%m-%d")
            db.add_holiday(date_str, desc)
            current_dt += timedelta(days=1)
            
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/test_sms', methods=['POST'])
def test_sms_route():
    print("[DEBUG] Received request for /api/test_sms", flush=True)
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    data = request.json
    sid = data.get('sid', '').strip()
    token = data.get('token', '').strip()
    from_num = data.get('from_number', '').strip()
    to_num = data.get('to_number', '').strip()
    
    if not all([sid, token, from_num, to_num]):
        return jsonify({'success': False, 'message': 'Missing fields for test'})
        
    try:
        handler = SMSHandler(sid, token, from_num)
        test_msg = "[CHAITANYA ENGINEERING COLLEGE] Verification: Your SMS Gateway is now correctly configured for internal attendance alerts. Regards."
        success, msg = handler.send_sms(to_num, test_msg)
        return jsonify({'success': success, 'message': msg})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/delete_students', methods=['POST'])
def delete_students():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    db.delete_all_students()
    
    flash("All student records deleted successfully.", "success")
    return redirect(url_for('settings'))

@app.route('/export_csv')
def export_csv():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    records = db.get_attendance_history()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Roll', 'Name', 'Subject', 'Branch', 'Date', 'Time', 'Status'])
    
    for row in records:
        writer.writerow([
            row.get('id'),
            row.get('roll'),
            row.get('name'),
            row.get('subject'),
            row.get('branch'),
            row.get('date'),
            row.get('time'),
            row.get('status')
        ])
        
    output.seek(0)
    return Response(output, mimetype="text/csv", 
                    headers={"Content-Disposition": "attachment;filename=attendance_report.csv"})

@app.route('/api/active_sessions')
def api_active_sessions():
    """API endpoint to get all active (unfinalized) sessions"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    active_sessions = db.get_active_sessions(finalized=False)
    
    # Convert to list of dicts and check expiration status
    now = datetime.now()
    sessions_list = []
    
    for s in active_sessions:
        s_dict = dict(s)
        end_dt_str = f"{s.get('date')} {s.get('end_time')}"
        try:
            end_dt = datetime.strptime(end_dt_str, "%Y-%m-%d %H:%M:%S")
            s_dict['is_expired'] = now > end_dt
            s_dict['end_datetime'] = end_dt.isoformat()
        except:
            s_dict['is_expired'] = False
            s_dict['end_datetime'] = None
        sessions_list.append(s_dict)
    
    return jsonify({
        'success': True,
        'count': len(sessions_list),
        'sessions': sessions_list
    })

@app.route('/api/force_finalize_all', methods=['POST'])
def api_force_finalize_all():
    """API endpoint to force finalize all expired sessions"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    active_sessions = db.get_active_sessions(finalized=False)
    
    now = datetime.now()
    expired_sessions = []
    
    for s in active_sessions:
        end_dt_str = f"{s.get('date')} {s.get('end_time')}"
        try:
            end_dt = datetime.strptime(end_dt_str, "%Y-%m-%d %H:%M:%S")
            if now > end_dt:
                expired_sessions.append(s.get('id'))
        except:
            continue
    
    if not expired_sessions:
        return jsonify({
            'success': True,
            'message': 'No expired sessions to finalize',
            'finalized_count': 0
        })
    
    finalized_count = 0
    errors = []
    
    for session_id in expired_sessions:
        try:
            result = finalize_session_core(session_id)
            if result['success'] and not result.get('already_done'):
                finalized_count += 1
        except Exception as e:
            errors.append(f"Session {session_id}: {str(e)}")
    
    return jsonify({
        'success': True,
        'message': f'Finalized {finalized_count} expired session(s)',
        'finalized_count': finalized_count,
        'total_expired': len(expired_sessions),
        'errors': errors if errors else None
    })

@app.route('/api/restart_session', methods=['POST'])
def api_restart_session():
    """API endpoint to restart/unfinalize a specific session"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.json
    session_id = data.get('session_id')
    
    if not session_id:
        return jsonify({'success': False, 'message': 'Missing session_id'}), 400
    
    try:
        db.restart_session(session_id, delete_absents=data.get('delete_absents', True))
        return jsonify({
            'success': True,
            'message': 'Session restarted successfully. It is now active again.',
            'session_id': session_id
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error restarting session: {str(e)}'}), 500

@app.route('/api/clear_all_sessions', methods=['POST'])
def api_clear_all_sessions():
    """API endpoint to clear ALL active sessions (emergency cleanup)"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        count = db.finalize_all_sessions()
        
        print(f"[Clear All Sessions] Cleared {count} active session(s)")
        
        return jsonify({
            'success': True,
            'message': f'All {count} active session(s) have been cleared',
            'cleared_count': count
        })
    except Exception as e:
        print(f"[Clear All Sessions Error] {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error clearing sessions: {str(e)}'}), 500

@app.route('/api/delete_session', methods=['POST'])
def api_delete_session():
    """API endpoint to completely delete a session and its attendance records"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.json
    session_id = data.get('session_id')
    
    if not session_id:
        return jsonify({'success': False, 'message': 'Missing session_id'}), 400
    
    try:
        db.delete_session(session_id)
        
        print(f"[Session Delete] Session {session_id} and its attendance records deleted")
        
        return jsonify({
            'success': True,
            'message': 'Session and all its attendance records deleted successfully',
            'session_id': session_id
        })
    except Exception as e:
        print(f"[Session Delete Error] {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error deleting session: {str(e)}'}), 500


@app.route('/finalize_session', methods=['POST'])
def finalize_session():
    """Manually finalize a specific session."""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.json
    session_id = data.get('session_id')
    
    if not session_id:
        return jsonify({'success': False, 'message': 'session_id is required'}), 400
    
    result = finalize_session_core(session_id)
    return jsonify(result)


def finalize_session_core(session_id):
    """
    Core finalization logic that marks absent students.
    Called by both manual finalize and auto-finalizer.
    """
    print(f"[FINALIZE] Starting finalization for session {session_id}")
    
    try:
        # Get session details from Firebase
        sess_doc = db.get_db().collection('sessions').document(session_id).get()
        if not sess_doc.exists:
            return {'success': False, 'message': 'Session not found'}
        
        sess = sess_doc.to_dict()
        if sess.get('is_finalized'):
            return {'success': True, 'message': 'Session already finalized', 'already_done': True, 'absent_count': 0}
        
        branch = sess.get('branch', '').strip().upper()
        subject = sess.get('subject')
        date = sess.get('date')
        
        # Get all students in this branch
        all_students = db.get_all_students(branch=branch)
        if not all_students:
            db.get_db().collection('sessions').document(session_id).update({'is_finalized': True})
            return {'success': True, 'message': 'Session finalized (no students in branch)', 'absent_count': 0}
        
        all_rolls = {s.get('roll') for s in all_students}
        
        # Get present students
        present_attendance = db.get_attendance_history(subject=subject, start_date=date, end_date=date)
        present_rolls = {r.get('roll') for r in present_attendance if r.get('session_id') == session_id and r.get('status') == 'PRESENT'}
        
        # Calculate absentees
        absent_rolls = all_rolls - present_rolls
        
        # Insert absent records
        now_time = datetime.now().strftime("%H:%M:%S")
        for roll in absent_rolls:
            student = next((s for s in all_students if s.get('roll') == roll), {})
            db.mark_attendance(
                session_id, 
                roll, 
                status='ABSENT',
                name=student.get('name'),
                subject=subject,
                branch=branch,
                date=date,
                time=now_time
            )
            
        # Mark session as finalized
        db.get_db().collection('sessions').document(session_id).update({'is_finalized': True})
        
        return {'success': True, 'message': 'Session finalized successfully', 'absent_count': len(absent_rolls)}
        
    except Exception as e:
        print(f"[FINALIZE ERROR] {e}")
        traceback.print_exc()
        return {'success': False, 'message': str(e)}
        
# Alias for compatibility if needed elsewhere
finalize_session_logic = finalize_session_core


def auto_finalizer_thread():
    """
    Background thread that auto-finalizes expired sessions using Firestore.
    Runs every 60 seconds.
    """
    print("[AUTO-FINALIZER] Thread started. Checking every 60 seconds...")
    
    while True:
        try:
            # Get active sessions from Firebase
            active_sessions = db.get_active_sessions(finalized=False)
            
            if not active_sessions:
                time.sleep(60)
                continue
            
            now = datetime.now()
            finalized_count = 0
            
            for sess in active_sessions:
                try:
                    # Session data in Firebase uses timestamps (if created by our new code)
                    # or date/time strings (if created by interim code)
                    # Let's handle both
                    
                    if sess.get('end_time'):
                        # If and end_time timestamp exists
                        if now.timestamp() > sess.get('end_time'):
                             db.finalize_session(sess['id'])
                             finalized_count += 1
                    elif sess.get('date') and sess.get('end_time_str'):
                        # Fallback for old sessions with string dates
                        end_dt_str = f"{sess['date']} {sess.get('end_time_str')}"
                        end_dt = datetime.strptime(end_dt_str, "%Y-%m-%d %H:%M:%S")
                        if now > end_dt:
                            finalize_session_core(sess['id'])
                            finalized_count += 1
                except Exception as e:
                    print(f"[AUTO-FINALIZER] Error finalizing {sess.get('id')}: {e}")
            
            if finalized_count > 0:
                print(f"[AUTO-FINALIZER] ✓ Auto-finalized {finalized_count} session(s)")
            
        except Exception as e:
            print(f"[AUTO-FINALIZER] Critical error: {e}")
            traceback.print_exc()
        
        time.sleep(60)

def weekly_report_thread():
    import time
    while True:
        try:
            now = datetime.now()
            # Run every Monday at 00:05 AM
            if now.weekday() == 0 and now.hour == 0 and now.minute == 5:
                # We don't want to import app here, we use the global generate_weekly_report
                print(f"[Weekly Report] Auto-generating Monday summary...")
                generate_weekly_report()
                time.sleep(120) # Avoid multiple triggers
        except Exception as e:
            print(f"[Weekly Report Thread Error] {e}")
        time.sleep(40)

# ==================== TEACHER ROUTES ====================



@app.route('/teacher')
@teacher_required
def teacher_dashboard():
    """Teacher dashboard - shows assigned subjects and active sessions"""
    try:
        user_id = session.get('user_id')
        username = session.get('username')
        
        # Get teacher info from Firebase
        # First try direct lookup by ID (which is username)
        teacher_ref = db.get_db().collection('teachers').document(user_id)
        teacher_doc = teacher_ref.get()
        
        if not teacher_doc.exists:
            # AUTO-HEAL: Create profile if missing
            print(f"[TEACHER DASHBOARD] Profile missing for {user_id}. Creating default.")
            db.create_teacher(
                teacher_id=user_id,
                name=f"Teacher {username}",
                username=username,
                email=None
            )
            # Re-fetch
            teacher_doc = teacher_ref.get()
        
        teacher = teacher_doc.to_dict()
        teacher['id'] = teacher_doc.id
        
        # Get today's subjects
        from datetime import datetime
        today = datetime.now().strftime('%A')
        
        # Get all subjects
        all_subjects = db.get_teacher_subjects(teacher['id'])
        
        # Filter for today
        today_subjects = [s for s in all_subjects if s.get('day_of_week') == today]
        
        # Get active sessions
        active_sessions = db.get_active_sessions(teacher_id=teacher['id'])
        
        return render_template('teacher_simple.html',
                             teacher=teacher,
                             today_subjects=today_subjects,
                             all_subjects=all_subjects,
                             active_sessions=active_sessions,
                             server_now=int(time.time()))
    except Exception as e:
        print(f"[TEACHER DASHBOARD ERROR] {e}")
        traceback.print_exc()
        flash('Error loading dashboard', 'error')
        return redirect(url_for('logout'))

@app.route('/teacher/add_subject', methods=['POST'])
@teacher_required
def teacher_add_subject():
    """Teacher adds their own subject/schedule"""
    try:
        user_id = session.get('user_id')
        teacher_ref = db.get_db().collection('teachers').document(user_id)
        if not teacher_ref.get().exists:
            flash('Teacher profile not found', 'error')
            return redirect(url_for('teacher_dashboard'))
        
        subject = request.form.get('subject')
        branch = request.form.get('branch')
        day_of_week = request.form.get('day_of_week')
        time_slot = request.form.get('time_slot')
        
        if not all([subject, branch, day_of_week, time_slot]):
            flash('All fields are required', 'error')
            return redirect(url_for('teacher_dashboard'))
            
        db.add_teacher_subject(user_id, subject, branch, day_of_week, time_slot)
        
        flash(f'Successfully added {subject} - {branch}', 'success')
        return redirect(url_for('teacher_dashboard'))
    except Exception as e:
        print(f"[ADD SUBJECT ERROR] {e}")
        flash('Error adding subject', 'error')
        return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/delete_subject', methods=['POST'])
@teacher_required
def teacher_delete_subject():
    """Teacher deletes their own subject"""
    try:
        subject_id = request.form.get('subject_id')
        db.delete_teacher_subject(subject_id)
        flash('Subject deleted successfully', 'success')
        return redirect(url_for('teacher_dashboard'))
    except Exception as e:
        print(f"[DELETE SUBJECT ERROR] {e}")
        flash('Error deleting subject', 'error')
        return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/start_session', methods=['POST'])
@teacher_required
def teacher_start_session():
    """Teacher creates a new session"""
    try:
        subject = request.form.get('subject')
        branch = request.form.get('branch')
        class_type = request.form.get('class_type', 'Lecture')
        
        user_id = session.get('user_id')
        
        # Calculate duration
        duration = 3 if class_type == 'Lab' else 1
        
        # Create session
        session_id = db.create_session(user_id, subject, branch, class_type, duration)
        
        print(f"[SESSION START] Teacher {user_id} created session {session_id}")
        
        return jsonify({
            'success': True,
            'message': f'Session started for {subject} - {branch}',
            'session_id': session_id
        })
    except Exception as e:
        print(f"[START SESSION ERROR] {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/teacher/finalize_session', methods=['POST'])
@teacher_required
def teacher_finalize_session():
    """Teacher finalizes session"""
    try:
        session_id = request.json.get('session_id') if request.json else request.form.get('session_id')
        
        # Finalize
        db.finalize_session(session_id)
        
        return jsonify({
            'success': True, 
            'message': 'Session finalized successfully. Attendance marked.'
        })
    except Exception as e:
        print(f"[FINALIZE ERROR] {e}")
        return jsonify({'success': False, 'message': str(e)})

# ==================== ADMIN TIMETABLE UPLOAD ====================

@app.route('/admin/get_teachers')
@admin_required
def get_teachers():
    """Get list of teachers with their subject counts for admin dashboard"""
    # TODO: Implement Firebase version
    return jsonify({'success': True, 'teachers': []})

@app.route('/admin/teacher_session_history')
@admin_required
def teacher_session_history():
    """Get history of all teacher-created sessions (Teacher Attendance)"""
    # TODO: Implement Firebase version
    return jsonify({'success': True, 'history': []})

@app.route('/admin/system_setup')
@admin_required
def admin_system_setup():
    """Admin-only route to run initial teacher data setup from local CSV"""
    return jsonify({
        'success': False, 
        'message': 'System setup is disabled during migration.'
    })

@app.route('/admin/create_teacher', methods=['POST'])
@admin_required
def create_teacher_manual():
    """Manual teacher creation by Admin"""
    try:
        data = request.json
        teacher_id = data.get('teacher_id')
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        
        if not all([teacher_id, name, password]):
            return jsonify({'success': False, 'message': 'Missing required fields'})
            
        # Create in Firebase
        # 1. Create User
        db.create_user(teacher_id, password, 'teacher', email)
        
        # 2. Create Profile
        db.create_teacher(
            teacher_id=teacher_id,
            name=name,
            username=teacher_id,
            email=email
        )
        
        return jsonify({'success': True, 'message': f'Teacher {name} created successfully'})
        
    except Exception as e:
        print(f"[CREATE TEACHER ERROR] {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/upload_timetable', methods=['POST'])
@admin_required
def upload_timetable():
    """Admin uploads teacher timetable CSV"""
    # TODO: Implement Firebase version of batch upload
    # For now, return a feature not available message
    return jsonify({
        'success': False, 
        'message': 'Bulk upload feature is currently disabled during system migration. Please add teachers manually or contact support.'
    })

@app.route('/success')
def success_page():
    return render_template('success.html')

if __name__ == '__main__':
    # Start app
    # host='0.0.0.0' makes the server accessible from other devices on the network
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
