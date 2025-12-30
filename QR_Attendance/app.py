from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, jsonify, send_file
from flask_socketio import SocketIO, emit
import sqlite3
import qrcode
import io
import base64
import time
from datetime import datetime, timedelta
import os
import csv
import math
import socket
from werkzeug.security import generate_password_hash, check_password_hash
from sms_utils import SMSHandler

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_qr_attendance_system'  # Change this for production
socketio = SocketIO(app, cors_allowed_origins="*")

# SMTP CONFIGURATION
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_EMAIL = "your_email@gmail.com" # Replace with your email
SMTP_PASSWORD = "your_app_password" # Replace with your app password

DB_NAME = "attendance.db"

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

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    
    # Users Table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL
                )''')
    
    # Attendance Table
    c.execute('''CREATE TABLE IF NOT EXISTS attendance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    roll TEXT NOT NULL,
                    name TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    branch TEXT NOT NULL,
                    date TEXT NOT NULL,
                    time TEXT NOT NULL
                )''')
    
    # Sessions Table (New for v2.0)
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject TEXT NOT NULL,
                    branch TEXT NOT NULL,
                    date TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    class_type TEXT NOT NULL,
                    qr_token TEXT NOT NULL,
                    is_finalized BOOLEAN DEFAULT 0
                )''')
    
    # Subjects Table
    c.execute('''CREATE TABLE IF NOT EXISTS subjects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL
                )''')

    # Indexing for performance
    c.execute('CREATE INDEX IF NOT EXISTS idx_roll ON attendance(roll)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_date ON attendance(date)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_subject ON attendance(subject)')
    
    # Check for new columns (Migration for IP Logging)
    c.execute("PRAGMA table_info(attendance)")
    columns = [info[1] for info in c.fetchall()]
    if 'ip_address' not in columns:
        c.execute('ALTER TABLE attendance ADD COLUMN ip_address TEXT')
        c.execute('ALTER TABLE attendance ADD COLUMN device_info TEXT')
    
    if 'session_id' not in columns:
         c.execute('ALTER TABLE attendance ADD COLUMN session_id INTEGER')
    if 'status' not in columns:
         c.execute('ALTER TABLE attendance ADD COLUMN status TEXT DEFAULT "PRESENT"')
        
    # Semester Config Table (Updated for Geofencing)
    c.execute('''CREATE TABLE IF NOT EXISTS semester_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start_date TEXT,
                    end_date TEXT,
                    college_lat REAL,
                    college_lng REAL,
                    geo_enabled INTEGER DEFAULT 0,
                    geo_radius INTEGER DEFAULT 200,
                    sms_enabled INTEGER DEFAULT 0,
                    sms_sid TEXT,
                    sms_auth_token TEXT,
                    sms_from_number TEXT,
                    sms_threshold INTEGER DEFAULT 75
                )''')

    # SMS Logs Table
    c.execute('''CREATE TABLE IF NOT EXISTS sms_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    roll TEXT NOT NULL,
                    session_id INTEGER,
                    phone TEXT,
                    message TEXT,
                    status TEXT,
                    error_message TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')

    # Unique constraint to prevent duplicate scans for same subject/student/date
    c.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_attendance ON attendance(roll, subject, date)')
    
    # Initialize default config if empty
    c.execute("SELECT COUNT(*) FROM semester_config")
    if c.fetchone()[0] == 0:
        # Default: current year start/end
        start = datetime.now().replace(month=1, day=1).strftime("%Y-%m-%d")
        end = datetime.now().replace(month=12, day=31).strftime("%Y-%m-%d")
        c.execute("INSERT INTO semester_config (start_date, end_date, geo_enabled, geo_radius) VALUES (?, ?, 0, 200)", (start, end))
    else:
        # Migration for Geofencing
        c.execute("PRAGMA table_info(semester_config)")
        cols = [info[1] for info in c.fetchall()]
        if 'geo_enabled' not in cols:
             c.execute("ALTER TABLE semester_config ADD COLUMN geo_enabled INTEGER DEFAULT 0")
             c.execute("ALTER TABLE semester_config ADD COLUMN geo_radius INTEGER DEFAULT 200")
             c.execute("ALTER TABLE semester_config ADD COLUMN college_lat REAL")
             c.execute("ALTER TABLE semester_config ADD COLUMN college_lng REAL")

        # Migration for SMS Settings if table pre-existed
        if 'sms_enabled' not in cols:
             c.execute("ALTER TABLE semester_config ADD COLUMN sms_enabled INTEGER DEFAULT 0")
             c.execute("ALTER TABLE semester_config ADD COLUMN sms_sid TEXT")
             c.execute("ALTER TABLE semester_config ADD COLUMN sms_auth_token TEXT")
             c.execute("ALTER TABLE semester_config ADD COLUMN sms_from_number TEXT")
             c.execute("ALTER TABLE semester_config ADD COLUMN sms_threshold INTEGER DEFAULT 75")

    # Holidays Table
    c.execute('''CREATE TABLE IF NOT EXISTS holidays (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT UNIQUE NOT NULL,
                    description TEXT
                )''')
                
    # Master Student List Table
    c.execute('''CREATE TABLE IF NOT EXISTS students (
                    roll TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    branch TEXT NOT NULL,
                    parent_email TEXT,
                    parent_phone TEXT
                )''')

    # Migration for parent_phone if table pre-existed
    c.execute("PRAGMA table_info(students)")
    st_cols = [info[1] for info in c.fetchall()]
    if 'parent_phone' not in st_cols:
        c.execute('ALTER TABLE students ADD COLUMN parent_phone TEXT')

    # Correction Requests Table (New)
    c.execute('''CREATE TABLE IF NOT EXISTS correction_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    roll TEXT NOT NULL,
                    session_id INTEGER,
                    reason TEXT NOT NULL,
                    proof_img TEXT,
                    status TEXT DEFAULT 'PENDING',
                    admin_comment TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )''')
    
    # Check for new columns (Migration for Parent Phone)
    c.execute("PRAGMA table_info(students)")
    s_columns = [info[1] for info in c.fetchall()]
    if 'parent_email' in s_columns:
        # We rename or ignore likely, but better to add phone column
        pass
    if 'parent_phone' not in s_columns:
        c.execute('ALTER TABLE students ADD COLUMN parent_phone TEXT')
    
    # Check if admin exists, if not create default
    c.execute("SELECT * FROM users WHERE username = ?", ('admin',))
    if not c.fetchone():
        hashed_pw = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                  ('admin', hashed_pw, 'admin'))
        
    # Check if a student user exists for demo
    c.execute("SELECT * FROM users WHERE username = ?", ('student',))
    if not c.fetchone():
        hashed_pw = generate_password_hash('student123')
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                  ('student', hashed_pw, 'student'))

    # Add default subjects if empty
    c.execute("SELECT COUNT(*) FROM subjects")
    if c.fetchone()[0] == 0:
        default_subs = [('Python Programming',), ('Data Structures',), ('Web Development',), ('Database Management',)]
        c.executemany("INSERT INTO subjects (name) VALUES (?)", default_subs)
                  
    conn.commit()
    conn.close()

# Initialize DB on start
init_db()

@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash("Invalid credentials", "danger")
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'] # This should be the Roll No
        password = request.form['password']
        
        if not username or not password:
            flash("Username and Password required", "danger")
            return redirect(url_for('register'))

        conn = get_db_connection()
        try:
            hashed_pw = generate_password_hash(password)
            conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hashed_pw, 'student'))
            conn.commit()
            flash("Registration Successful! Please Login.", "success")
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            flash("Username already exists", "danger")
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

app.permanent_session_lifetime = 1800 # 30 minutes session timeout

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    # Analytics Stats
    today_str = datetime.now().strftime("%Y-%m-%d")
    
    total_attendance = conn.execute('SELECT COUNT(*) FROM attendance').fetchone()[0]
    present_today = conn.execute('SELECT COUNT(*) FROM attendance WHERE date = ?', (today_str,)).fetchone()[0]
    # Class-Group Stats (For the 5 main toggles)
    # CSE Group: CAI, CSM, CSD, CSE-A, CSE-B, CSE-C, CSE-D
    cse_count = conn.execute("SELECT COUNT(*) FROM attendance WHERE date = ? AND branch IN ('CAI', 'CSM', 'CSD', 'CSE-A', 'CSE-B', 'CSE-C', 'CSE-D')", (today_str,)).fetchone()[0]
    ece_count = conn.execute("SELECT COUNT(*) FROM attendance WHERE date = ? AND branch = 'ECE'", (today_str,)).fetchone()[0]
    eee_count = conn.execute("SELECT COUNT(*) FROM attendance WHERE date = ? AND branch = 'EEE'", (today_str,)).fetchone()[0]
    mech_count = conn.execute("SELECT COUNT(*) FROM attendance WHERE date = ? AND branch = 'MECH'", (today_str,)).fetchone()[0]
    civil_count = conn.execute("SELECT COUNT(*) FROM attendance WHERE date = ? AND branch = 'CIVIL'", (today_str,)).fetchone()[0]
    
    # Correction for safety
    mech_count = conn.execute("SELECT COUNT(*) FROM attendance WHERE date = ? AND branch = 'MECH'", (today_str,)).fetchone()[0]

    # Fetch Subjects for Dropdown
    subjects = conn.execute('SELECT * FROM subjects ORDER BY name').fetchall()
    
    # Fetch Active Sessions
    active_sessions = conn.execute("SELECT * FROM sessions WHERE is_finalized = 0").fetchall()
    
    conn.close()
    
    return render_template('admin.html', 
                           cse_count=cse_count,
                           ece_count=ece_count,
                           eee_count=eee_count,
                           mech_count=mech_count,
                           civil_count=civil_count,
                           subjects=subjects,
                           active_sessions=active_sessions)

@app.route('/api/stats')
def api_stats():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = get_db_connection()
    today_str = datetime.now().strftime("%Y-%m-%d")
    
    cse_count = conn.execute("SELECT COUNT(*) FROM attendance WHERE date = ? AND branch IN ('CAI', 'CSM', 'CSD', 'CSE-A', 'CSE-B', 'CSE-C', 'CSE-D')", (today_str,)).fetchone()[0]
    ece_count = conn.execute("SELECT COUNT(*) FROM attendance WHERE date = ? AND branch = 'ECE'", (today_str,)).fetchone()[0]
    eee_count = conn.execute("SELECT COUNT(*) FROM attendance WHERE date = ? AND branch = 'EEE'", (today_str,)).fetchone()[0]
    mech_count = conn.execute("SELECT COUNT(*) FROM attendance WHERE date = ? AND branch = 'MECH'", (today_str,)).fetchone()[0]
    civil_count = conn.execute("SELECT COUNT(*) FROM attendance WHERE date = ? AND branch = 'CIVIL'", (today_str,)).fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'cse': cse_count,
        'ece': ece_count,
        'eee': eee_count,
        'mech': mech_count,
        'civil': civil_count
    })

@app.route('/add_subject', methods=['POST'])
def add_subject():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    subject_name = request.json.get('name')
    if not subject_name:
         return jsonify({'success': False, 'message': 'Name required'})
         
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO subjects (name) VALUES (?)", (subject_name,))
        conn.commit()
        success = True
        msg = "Subject Added"
    except sqlite3.IntegrityError:
        success = False
        msg = "Subject already exists"
    conn.close()
    conn.close()
    return jsonify({'success': success, 'message': msg})

@app.route('/delete_subject/<int:id>', methods=['POST'])
def delete_subject(id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    conn = get_db_connection()
    conn.execute('DELETE FROM subjects WHERE id = ?', (id,))
    conn.commit()
    conn.close()
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
         
    hashed_pw = generate_password_hash(password)
    
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                     (username, hashed_pw, 'student'))
        conn.commit()
        success = True
        msg = "Student Registered"
    except sqlite3.IntegrityError:
        success = False
        msg = "Username already exists"
    conn.close()
    return jsonify({'success': success, 'message': msg})

@app.route('/student')
def student_dashboard():
    if 'user_id' not in session: 
        return redirect(url_for('login'))
    
    username = session['username']
    conn = get_db_connection()
    
    total_present = 0
    records = []
    corrections = []
    
    if session['role'] == 'student':
        # Match by Roll Number (which is the username)
        query_res = conn.execute("SELECT COUNT(*) FROM attendance WHERE roll = ? AND status='PRESENT'", (username,)).fetchone()
        if query_res:
            total_present = query_res[0]
        
        records = conn.execute("SELECT * FROM attendance WHERE roll = ? ORDER BY date DESC, time DESC", (username,)).fetchall()
        
        # Fetch pending/history of corrections
        # Fetch pending/history of corrections
        corrections = conn.execute("""
            SELECT cr.*, s.subject 
            FROM correction_requests cr 
            LEFT JOIN sessions s ON cr.session_id = s.id 
            WHERE cr.roll = ? 
            ORDER BY cr.timestamp DESC
        """, (username,)).fetchall()
    
    # Calculate Percentage based on Semester Config
    config = conn.execute("SELECT * FROM semester_config").fetchone()
    holidays = conn.execute("SELECT * FROM holidays").fetchall()
    
    working_days = 0
    total_sem_days = 0
    percentage = 0.0
    
    if config:
        working_days = calculate_working_days(config['start_date'], config['end_date'], holidays, include_future=False)
        total_sem_days = calculate_working_days(config['start_date'], config['end_date'], holidays, include_future=True)
        if working_days > 0:
            percentage = (total_present / working_days) * 100
        
    conn.close()
    return render_template('student.html', 
                           records=records, 
                           corrections=corrections,
                           username=username, 
                           total_present=total_present, 
                           working_days=working_days, 
                           total_sem_days=total_sem_days,
                           holidays=holidays,
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
        
    # Convert session_id to None if empty (general report)
    if not session_id or session_id == '':
        session_id = None
    
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
            
    conn = get_db_connection()
    conn.execute("INSERT INTO correction_requests (roll, session_id, reason, proof_img, status) VALUES (?, ?, ?, ?, ?)",
                 (roll, session_id, reason, proof_filename, 'PENDING'))
    conn.commit()
    conn.close()
    
    flash('Correction request submitted! Admin will review it soon.', 'success')
    return redirect(url_for('student_dashboard'))

@app.route('/api/my_corrections')
def my_corrections():
    if 'user_id' not in session:
        return jsonify([])
        
    conn = get_db_connection()
    requests = conn.execute("""
        SELECT cr.*, s.subject 
        FROM correction_requests cr 
        LEFT JOIN sessions s ON cr.session_id = s.id 
        WHERE cr.roll = ? 
        ORDER BY cr.timestamp DESC
    """, (session['username'],)).fetchall()
    conn.close()
    
    return jsonify([dict(r) for r in requests])

@app.route('/admin/corrections')
def view_corrections():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    pending = conn.execute("""
        SELECT cr.*, s.name as student_name 
        FROM correction_requests cr 
        LEFT JOIN students s ON cr.roll = s.roll 
        WHERE cr.status = 'PENDING' 
        ORDER BY cr.timestamp DESC
    """).fetchall()
    
    history = conn.execute("""
        SELECT cr.*, s.name as student_name 
        FROM correction_requests cr 
        LEFT JOIN students s ON cr.roll = s.roll 
        WHERE cr.status != 'PENDING' 
        ORDER BY cr.timestamp DESC 
        LIMIT 50
    """).fetchall()
    conn.close()
    
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
        
    conn = get_db_connection()
    req = conn.execute("SELECT * FROM correction_requests WHERE id = ?", (req_id,)).fetchone()
    
    if not req:
        conn.close()
        return jsonify({'success': False, 'message': 'Request not found'}), 404
        
    new_status = 'APPROVED' if action == 'APPROVE' else 'REJECTED'
    
    try:
        if action == 'APPROVE':
            # Update attendance table if it's an approval
            # We need to find the specific attendance record or insert one if missing
            # Since we have session_id and roll, we can update
            conn.execute("UPDATE attendance SET status = 'PRESENT' WHERE roll = ? AND session_id = ?", (req['roll'], req['session_id']))
            
        conn.execute("UPDATE correction_requests SET status = ?, admin_comment = ? WHERE id = ?", (new_status, comment, req_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/start_session', methods=['POST'])
def start_session():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.json
    subject = data.get('subject')
    branch = data.get('branch')
    class_type = data.get('class_type', 'Lecture') # 'Lecture' or 'Lab'
    
    if not subject or not branch:
        return jsonify({'success': False, 'message': 'Missing data'}), 400
    
    # Calculate times
    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    start_time = now.strftime("%H:%M:%S")
    
    duration = 3 if class_type == 'Lab' else 1
    end_dt = now + timedelta(hours=duration)
    end_time = end_dt.strftime("%H:%M:%S")

    # Generate Unique Token for Session
    import uuid
    token = str(uuid.uuid4())
    
    # Save Session
    conn = get_db_connection()
    cursor = conn.execute('''INSERT INTO sessions 
                            (subject, branch, date, start_time, end_time, class_type, qr_token) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)''',
                            (subject, branch, date_str, start_time, end_time, class_type, token))
    session_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # QR Data: URL for scanning
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    local_ip = get_local_ip()
    port = request.host.split(':')[-1] if ':' in request.host else '5000'
    host_url = f"http://{local_ip}:{port}"
    qr_url = f"{host_url}/scan_session?token={token}"
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_url)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    img_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    
    return jsonify({
        'success': True, 
        'qr_image': img_base64,
        'session_id': session_id,
        'end_time': end_time,
        'token': token,
        'qr_url': qr_url
    })

@app.route('/get_qr_img/<token>')
def get_qr_img(token):
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    local_ip = get_local_ip()
    port = request.host.split(':')[-1] if ':' in request.host else '5000'
    host_url = f"http://{local_ip}:{port}"
    qr_url = f"{host_url}/scan_session?token={token}"
    
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
        
    conn = get_db_connection()
    session_data = conn.execute("SELECT * FROM sessions WHERE qr_token = ?", (token,)).fetchone()
    config = conn.execute("SELECT * FROM semester_config").fetchone()
    conn.close()
    
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
    conn = get_db_connection()
    config = conn.execute("SELECT * FROM semester_config").fetchone()
    
    if config['geo_enabled']:
        lat = data.get('lat')
        lng = data.get('lng')
        
        if not lat or not lng:
            conn.close()
            return jsonify({'success': False, 'message': 'Location access required for attendance!'})
            
        college_lat = config['college_lat'] or 0
        college_lng = config['college_lng'] or 0
        radius = config['geo_radius'] or 200
        
        dist = haversine(float(lat), float(lng), college_lat, college_lng)
        print(f"[Geofence] User Dist: {dist}m | Allowed: {radius}m")
        
        if dist > radius:
            conn.close()
            return jsonify({'success': False, 'message': f'You are too far from class! ({int(dist)}m away)'})

    if not all([roll, name, token]):
        conn.close()
        return jsonify({'success': False, 'message': 'Missing fields'})
        
    session_data = conn.execute("SELECT * FROM sessions WHERE qr_token = ?", (token,)).fetchone()
    
    if not session_data:
        conn.close()
        return jsonify({'success': False, 'message': 'Invalid Session'})
    
    # Verify not finalized
    if session_data['is_finalized']:
         conn.close()
         return jsonify({'success': False, 'message': 'Attendance Finalized'})
         
    # Upsert attendance
    # We check if student already marked for THIS subject TODAY
    # This prevents multiple scans for the same subject even in different sessions
    existing = conn.execute('''
        SELECT id FROM attendance 
        WHERE roll = ? AND date = ? AND subject = ? AND branch = ?
    ''', (roll, session_data['date'], session_data['subject'], session_data['branch'])).fetchone()
    
    if existing:
        conn.close()
        return jsonify({'success': False, 'message': 'Attendance already marked for this subject today!'})
    
    # Insert
    now_time = datetime.now().strftime("%H:%M:%S")
    try:
        conn.execute('''INSERT INTO attendance 
                        (roll, name, subject, branch, date, time, session_id, status) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, 'PRESENT')''',
                        (roll, name, session_data['subject'], session_data['branch'], 
                         session_data['date'], now_time, session_data['id']))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'message': 'Attendance already marked for this subject today!'})
    conn.close()
    
    # Real-time Update
    socketio.emit('new_attendance', {
        'session_id': session_data['id'],
        'roll': roll,
        'name': name,
        'branch': session_data['branch'],
        'time': now_time
    })
    
    return jsonify({'success': True, 'message': 'Attendance Marked Successfully'})

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
         
    conn = get_db_connection()
    
    # Filters
    f_subject = request.args.get('subject', '')
    f_branch = request.args.get('branch', '')
    f_date = request.args.get('date', '')
    
    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    
    query = "SELECT * FROM attendance WHERE 1=1"
    params = []
    
    if f_subject:
        query += " AND subject = ?"
        params.append(f_subject)
    if f_branch:
        query += " AND branch = ?"
        params.append(f_branch)
    if f_date:
        query += " AND date = ?"
        params.append(f_date)
        
    # Get total count for pagination
    count_query = "SELECT COUNT(*) FROM (" + query + ")"
    total_records = conn.execute(count_query, params).fetchone()[0]
    total_pages = (total_records + per_page - 1) // per_page
    
    # Add limit and offset
    query += " ORDER BY date DESC, time DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    
    records = conn.execute(query, params).fetchall()
    conn.close()
    
    return render_template('view.html', records=records, page=page, total_pages=total_pages, 
                           f_subject=f_subject, f_branch=f_branch, f_date=f_date)

@app.route('/reports')
def reports_page():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    reports_dir = os.path.join('static', 'reports')
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
        
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
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Range: Last 7 days
    end_date = datetime.now()
    start_date = end_date - timedelta(days=7)
    
    start_str = start_date.strftime("%Y-%m-%d")
    end_str = end_date.strftime("%Y-%m-%d")
    
    filename = f"Weekly_Report_{start_str}_to_{end_str}.csv"
    filepath = os.path.join('static', 'reports', filename)
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    # Fetch Data: Branch-wise summary
    branches = ['CSM', 'CSD', 'CSE-A', 'CSE-B', 'CSE-C', 'CSE-D', 'CIVIL', 'MECH', 'ECE', 'EEE']
    
    try:
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Weekly Attendance Report', f"{start_str} to {end_str}"])
            writer.writerow([])
            writer.writerow(['Branch', 'Total Records', 'Present', 'Absent', 'Percentage (%)'])
            
            for b in branches:
                total = cur.execute("SELECT COUNT(*) FROM attendance WHERE branch = ? AND date >= ? AND date <= ?", (b, start_str, end_str)).fetchone()[0]
                if total > 0:
                    present = cur.execute("SELECT COUNT(*) FROM attendance WHERE branch = ? AND status='PRESENT' AND date >= ? AND date <= ?", (b, start_str, end_str)).fetchone()[0]
                    absent = total - present
                    pct = round((present/total)*100, 2)
                    writer.writerow([b, total, present, absent, pct])
                else:
                    writer.writerow([b, 0, 0, 0, 0.0])
                    
            writer.writerow([])
            writer.writerow(['--- Defaulters List (< 75% Overall) ---'])
            writer.writerow(['Roll No', 'Name', 'Branch', 'Total Classes', 'Attended', 'Percentage (%)'])
            
            # This part is heavy but accurate
            students = cur.execute("SELECT DISTINCT roll, name, branch FROM attendance").fetchall()
            for s in students:
                res = cur.execute("SELECT COUNT(*), SUM(CASE WHEN status='PRESENT' THEN 1 ELSE 0 END) FROM attendance WHERE roll = ?", (s['roll'],)).fetchone()
                s_total = res[0]
                s_present = res[1] or 0
                
                if s_total > 0:
                    s_pct = round((s_present/s_total)*100, 2)
                    if s_pct < 75:
                        writer.writerow([s['roll'], s['name'], s['branch'], s_total, s_present, s_pct])
    except Exception as e:
        print(f"Error generating report: {e}")
                    
    conn.close()
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
        
    conn = get_db_connection()
    cur = conn.cursor()
    
    # 1. Attendance Trends (Last 7 Days)
    dates = []
    present_counts = []
    absent_counts = []
    
    for i in range(6, -1, -1):
        d = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        # Counts
        p = cur.execute("SELECT COUNT(*) FROM attendance WHERE date = ? AND status = 'PRESENT'", (d,)).fetchone()[0]
        a = cur.execute("SELECT COUNT(*) FROM attendance WHERE date = ? AND status = 'ABSENT'", (d,)).fetchone()[0]
        dates.append(d)
        present_counts.append(p)
        absent_counts.append(a)
        
    # 2. Branch Performance (All Time)
    # Get all branches with records
    branches = ['CSM', 'CSD', 'CSE-A', 'CSE-B', 'CSE-C', 'CSE-D', 'CIVIL', 'MECH', 'ECE', 'EEE'] # Hardcoded for consistent sorting or fetch DISTINCT
    branch_data = []
    
    for b in branches:
        total = cur.execute("SELECT COUNT(*) FROM attendance WHERE branch = ?", (b,)).fetchone()[0]
        if total == 0:
            branch_data.append(0)
        else:
            present = cur.execute("SELECT COUNT(*) FROM attendance WHERE branch = ? AND status = 'PRESENT'", (b,)).fetchone()[0]
            pct = round((present / total) * 100, 1)
            branch_data.append(pct)
            
    conn.close()
    
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
        
    conn = get_db_connection()
    selected_branch = request.args.get('branch')
    selected_group = request.args.get('group')
    
    records = []
    
    # Stats for Today
    today_str = datetime.now().strftime("%Y-%m-%d")
    total_strength = 0
    present_count = 0
    absent_count = 0
    absentees = []
    
    if selected_branch:
        # Fetch records for this branch (History)
        records = conn.execute("SELECT * FROM attendance WHERE branch = ? ORDER BY date DESC, time DESC", (selected_branch,)).fetchall()
        
        # Calculate Daily Report (Today)
        # 1. Total Students in Master List
        master_students = conn.execute("SELECT * FROM students WHERE branch = ?", (selected_branch,)).fetchall()
        total_strength = len(master_students)
        
        # 2. Present Today (Only count 'PRESENT' status)jk
        present_records = conn.execute("SELECT roll FROM attendance WHERE branch = ? AND date = ? AND status = 'PRESENT'", (selected_branch, today_str)).fetchall()
        present_rolls = {r['roll'] for r in present_records}
        present_count = len(present_rolls)
        
        if total_strength > 0:
            # 3. Absentees
            absent_count = max(0, total_strength - present_count)
            for s in master_students:
                if s['roll'] not in present_rolls:
                    absentees.append(s)
        
    conn.close()
    
    # All branches
    all_branches = ["CAI", "CSM", "CSD", "CSE-A", "CSE-B", "CSE-C", "CSE-D", "CIVIL", "MECH", "ECE", "EEE"]
    
    # Filter if group is selected
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
        
    conn = get_db_connection()
    config = conn.execute("SELECT * FROM semester_config").fetchone()
    holidays = conn.execute("SELECT * FROM holidays ORDER BY date").fetchall()
    conn.close()
    
    return render_template('settings.html', config=config, holidays=holidays)

@app.route('/update_semester', methods=['POST'])
def update_semester():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    start_date = request.form['start_date']
    end_date = request.form['end_date']
    
    # Geofencing Config
    geo_enabled = 1 if 'geo_enabled' in request.form else 0
    college_lat = request.form.get('college_lat')
    college_lng = request.form.get('college_lng')
    geo_radius = request.form.get('geo_radius', 200)
    
    conn = get_db_connection()
    conn.execute('''UPDATE semester_config 
                    SET start_date = ?, end_date = ?, 
                        geo_enabled = ?, college_lat = ?, college_lng = ?, geo_radius = ?
                    WHERE id = 1''', 
                 (start_date, end_date, geo_enabled, college_lat, college_lng, geo_radius))
    conn.commit()
    conn.close()
    
    flash("Semester dates updated!", "success")
    return redirect(url_for('settings'))

@app.route('/update_sms_config', methods=['POST'])
def update_sms_config():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    sms_enabled = 1 if 'sms_enabled' in request.form else 0
    sms_sid = request.form.get('sms_sid', '').strip()
    sms_auth_token = request.form.get('sms_auth_token', '').strip()
    sms_from_number = request.form.get('sms_from_number', '').strip()
    sms_threshold = request.form.get('sms_threshold')
    
    try:
        sms_threshold = int(sms_threshold) if sms_threshold else 75
    except ValueError:
        sms_threshold = 75
        
    print(f"[DEBUG] Updating SMS Config: Enabled={sms_enabled}, SID={sms_sid}, Token={'*' * len(sms_auth_token)}")
    
    conn = get_db_connection()
    # Update all rows (standardizing as there should only be one config row)
    conn.execute('''UPDATE semester_config 
                    SET sms_enabled = ?, sms_sid = ?, sms_auth_token = ?, 
                        sms_from_number = ?, sms_threshold = ?''',
                 (sms_enabled, sms_sid, sms_auth_token, sms_from_number, sms_threshold))
    conn.commit()
    conn.close()
    flash('SMS Configuration updated successfully!', 'success')
    return redirect(url_for('settings'))

@app.route('/sms_logs')
def sms_logs():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    logs = conn.execute("SELECT * FROM sms_logs ORDER BY timestamp DESC LIMIT 100").fetchall()
    conn.close()
    return render_template('sms_logs.html', logs=logs)






@app.route('/delete_holiday/<int:id>', methods=['POST'])
def delete_holiday(id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    conn = get_db_connection()
    conn.execute("DELETE FROM holidays WHERE id = ?", (id,))
    conn.commit()
    conn.close()
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

@app.route('/delete_record/<int:id>', methods=['POST'])
def delete_record(id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    conn = get_db_connection()
    conn.execute('DELETE FROM attendance WHERE id = ?', (id,))
    conn.commit()
    conn.close()
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
            
            # Skip header if present (heuristic: check if first row has "roll")
            data = list(csv_input)
            if not data:
                flash('Empty CSV', 'danger')
                return redirect(url_for('settings'))
                
            header = [h.lower() for h in data[0]]
            start_idx = 0
            if 'roll' in header or 'roll no' in header or 'name' in header:
                start_idx = 1
                
            count = 0
            conn = get_db_connection()
            
            # Check for "Replace All" mode
            if 'replace_all' in request.form:
                conn.execute("DELETE FROM students")
            
            for i in range(start_idx, len(data)):
                row = data[i]
                if len(row) >= 3:
                     # Expected format: Roll, Name, Branch, Parent Phone (Optional)
                     roll = row[0].strip()
                     name = row[1].strip()
                     branch = row[2].strip()
                     p_phone = row[3].strip() if len(row) > 3 else None
                     
                     conn.execute("REPLACE INTO students (roll, name, branch, parent_email, parent_phone) VALUES (?, ?, ?, ?, ?)", (roll, name, branch, None, p_phone))
                     count += 1
            
            conn.commit()
            conn.close()
            flash(f'Successfully imported {count} students!', 'success')
        except Exception as e:
            flash(f'Error processing file: {str(e)}', 'danger')
            
    return redirect(url_for('settings'))

@app.route('/add_student_manual', methods=['POST'])
def add_student_manual():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    data = request.json
    data = request.json
    print(f"DEBUG: Received manual add data: {data}", flush=True)
    
    roll = data.get('roll')
    name = data.get('name')
    branch = data.get('branch')
    p_phone = data.get('parent_phone')
    
    if not all([roll, name, branch]):
        print("DEBUG: Missing fields", flush=True)
        return jsonify({'success': False, 'message': 'Missing fields'})
        
    conn = get_db_connection()
    try:
        print(f"DEBUG: Executing REPLACE for {roll} with phone {p_phone}", flush=True)
        # Use INSERT OR REPLACE to ensure upsert behavior
        conn.execute("INSERT OR REPLACE INTO students (roll, name, branch, parent_phone) VALUES (?, ?, ?, ?)", 
                     (roll, name, branch, p_phone))
        conn.commit()
        print("DEBUG: Commit successful", flush=True)
        success = True
        msg = "Student saved successfully"
    except Exception as e:
        print(f"DEBUG: Error saving student: {e}", flush=True)
        success = False
        msg = str(e)
    conn.close()
    return jsonify({'success': success, 'message': msg})

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
    
    conn = get_db_connection()
    today_str = datetime.now().strftime("%Y-%m-%d")
    
    students_to_notify = []
    
    if target == 'single':
        roll = data.get('roll')
        student = conn.execute("SELECT * FROM students WHERE roll = ?", (roll,)).fetchone()
        if student:
            students_to_notify.append(student)
            
    elif target == 'branch':
        branch = data.get('branch')
        # Get all students of branch
        all_students = conn.execute("SELECT * FROM students WHERE branch = ?", (branch,)).fetchall()
        # Get present rolls
        present = conn.execute("SELECT roll FROM attendance WHERE branch = ? AND date = ?", (branch, today_str)).fetchall()
        present_rolls = {r['roll'] for r in present}
        
        for s in all_students:
            if s['roll'] not in present_rolls:
                students_to_notify.append(s)
                
    sent_count = 0
    errors = []
    
    for s in students_to_notify:
        phone = s['parent_phone']
        if phone:
            msg = f"Absent Alert: {s['name']} ({s['roll']}) was absent today ({today_str}). Please contact college."
            success, status = send_sms(phone, msg)
            if success:
                sent_count += 1
            else:
                errors.append(f"{s['roll']}: {status}")
        else:
            errors.append(f"{s['roll']}: No parent phone")
            
    conn.close()
    
    return jsonify({
        'success': True, 
        'sent': sent_count, 
        'total': len(students_to_notify),
        'errors': errors
    })

@app.route('/add_holiday', methods=['POST'])
def add_holiday():
    print("DEBUG: Entered add_holiday route", flush=True)
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    data = request.json
    start_date_str = data.get('date')
    end_date_str = data.get('end_date') # Optional
    desc = data.get('description')
    
    print(f"DEBUG DATA: Start={start_date_str}, End={end_date_str}, Desc={desc}", flush=True)
    
    if not start_date_str or not desc:
        print("DEBUG: Missing data", flush=True)
        return jsonify({'success': False, 'message': 'Missing data'}), 400
        
    conn = get_db_connection()
    try:
        start_dt = datetime.strptime(start_date_str, "%Y-%m-%d")
        
        if end_date_str:
            end_dt = datetime.strptime(end_date_str, "%Y-%m-%d")
        else:
            end_dt = start_dt
            
        # Iterate and insert each day
        current_dt = start_dt
        while current_dt <= end_dt:
            date_str = current_dt.strftime("%Y-%m-%d")
            # Check for generic duplicate on that date
            existing = conn.execute("SELECT id FROM holidays WHERE date = ?", (date_str,)).fetchone()
            if not existing:
                print(f"DEBUG: Inserting {date_str}", flush=True)
                conn.execute('INSERT INTO holidays (date, description) VALUES (?, ?)', (date_str, desc))
            else:
                print(f"DEBUG: Skipping duplicate {date_str}", flush=True)
            current_dt += timedelta(days=1)
            
        conn.commit()
        print("DEBUG: Commit successful", flush=True)
        return jsonify({'success': True})
    except Exception as e:
        print(f"DEBUG EXCEPTION: {e}", flush=True)
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        conn.close()

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
        
    conn = get_db_connection()
    conn.execute("DELETE FROM students")
    conn.commit()
    conn.close()
    
    flash("All student records deleted successfully.", "success")
    return redirect(url_for('settings'))

@app.route('/export_csv')
def export_csv():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    # Apply same filters if needed, but for now export all or add params
    # Simplest: export all
    cursor = conn.execute("SELECT * FROM attendance ORDER BY date DESC, time DESC")
    rows = cursor.fetchall()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Roll', 'Name', 'Subject', 'Branch', 'Date', 'Time'])
    
    for row in rows:
        writer.writerow(list(row))
        
    conn.close()
    
    output.seek(0)
    return Response(output, mimetype="text/csv", 
                    headers={"Content-Disposition": "attachment;filename=attendance_report.csv"})

@app.route('/finalize_session', methods=['POST'])
def finalize_session():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    data = request.json
    session_id = data.get('session_id')
    
    result = finalize_session_logic(session_id)
    if not result['success']:
        return jsonify(result)
        
    return jsonify(result)

def finalize_session_logic(session_id):
    print(f"[DEBUG] Starting finalization for session {session_id}")
    conn = get_db_connection()
    current_session = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
    
    if not current_session or current_session['is_finalized']:
        print(f"[DEBUG] Session {session_id} not found or already finalized.")
        conn.close()
        return {'success': False, 'message': 'Invalid or Already Finalized'}
        
    branch = current_session['branch'].strip().upper()
    print(f"[DEBUG] Finalizing for branch: {branch}")
    
    # 1. Fetch all students in branch
    all_students = conn.execute("SELECT roll FROM students WHERE UPPER(TRIM(branch)) = ?", (branch,)).fetchall()
    all_rolls = {s['roll'] for s in all_students}
    print(f"[DEBUG] Found {len(all_rolls)} total students in branch {branch}.")
    
    # 2. Fetch all PRESENT students for this session
    present_records = conn.execute("SELECT roll FROM attendance WHERE session_id = ? AND status = 'PRESENT'", (session_id,)).fetchall()
    present_rolls = {r['roll'] for r in present_records}
    print(f"[DEBUG] Found {len(present_rolls)} present students.")
    
    # 3. Identify Absentees
    absent_rolls = all_rolls - present_rolls
    print(f"[DEBUG] Marking {len(absent_rolls)} students as ABSENT.")
    
    # Prepare data for executemany
    student_map_rows = conn.execute("SELECT roll, name FROM students WHERE branch = ?", (branch,)).fetchall()
    student_map = {r['roll']: r['name'] for r in student_map_rows}
    
    absent_data = []
    now_time = datetime.now().strftime("%H:%M:%S")
    for roll in absent_rolls:
        absent_data.append((
            roll, 
            student_map.get(roll, 'Unknown'), 
            current_session['subject'], 
            current_session['branch'], 
            current_session['date'], 
            now_time, 
            session_id, 
            'ABSENT'
        ))
    
    try:
        if absent_data:
            conn.executemany('''INSERT INTO attendance 
                                (roll, name, subject, branch, date, time, session_id, status) 
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', absent_data)
            print(f"[DEBUG] Inserted {len(absent_data)} absent records into database.")
                                
        # 5. Mark Session Finalized
        conn.execute("UPDATE sessions SET is_finalized = 1 WHERE id = ?", (session_id,))
        
        # 6. Trigger SMS Alerts if enabled
        config = conn.execute("SELECT * FROM semester_config LIMIT 1").fetchone()
        if config and config['sms_enabled']:
            print(f"[DEBUG] SMS Alerts enabled. Processing {len(absent_data)} absentees.")
            sms_handler = SMSHandler(config['sms_sid'], config['sms_auth_token'], config['sms_from_number'])
            
            for roll, name, subject, branch, date, time, s_id, status in absent_data:
                # Fetch parent phone
                student = conn.execute("SELECT parent_phone FROM students WHERE roll = ?", (roll,)).fetchone()
                if student and student['parent_phone']:
                    phone = student['parent_phone']
                    
                    # 7. Calculate Current Attendance Percentage for Warning
                    total_sessions = conn.execute("SELECT COUNT(*) FROM sessions WHERE subject = ? AND branch = ? AND is_finalized = 1", 
                                                 (subject, branch)).fetchone()[0]
                    present_count = conn.execute("SELECT COUNT(*) FROM attendance WHERE roll = ? AND subject = ? AND branch = ? AND status = 'PRESENT'", 
                                                (roll, subject, branch)).fetchone()[0]
                    
                    attendance_pct = (present_count / total_sessions * 100) if total_sessions > 0 else 100
                    
                    from sms_utils import format_absence_message
                    message = format_absence_message(name, subject, date, attendance_pct, config['sms_threshold'])
                    
                    success, result_msg = sms_handler.send_sms(phone, message)
                    
                    # Log SMS
                    conn.execute("""INSERT INTO sms_logs (roll, session_id, phone, message, status, error_message)
                                   VALUES (?, ?, ?, ?, ?, ?)""",
                                (roll, session_id, phone, message, result_msg if success else "FAILED", None if success else result_msg))
                    print(f"[DEBUG] SMS to {roll} ({phone}): {result_msg}")
        
        conn.commit()
        print(f"[DEBUG] Session {session_id} marked as finalized and SMS processed.")
    except Exception as e:
        print(f"[DEBUG] Database Error during finalization: {e}")
        return {'success': False, 'message': f'DB Error: {str(e)}'}
    finally:
        conn.close()
    
    print(f"[Auto-Finalizer] Finalized Session {session_id}. Marked {len(absent_data)} absent.")
    
    return {
        'success': True, 
        'message': f'Attendance Finalized. {len(absent_data)} students marked ABSENT.',
        'absent_count': len(absent_data)
    }

def auto_finalizer_thread():
    import time
    while True:
        try:
            conn = get_db_connection()
            # Find active sessions that have ended
            # We need to parse date and time to compare
            active_sessions = conn.execute("SELECT * FROM sessions WHERE is_finalized = 0").fetchall()
            conn.close()
            
            now = datetime.now()
            
            for s in active_sessions:
                s_end_iso = f"{s['date']} {s['end_time']}"
                try:
                    end_dt = datetime.strptime(s_end_iso, "%Y-%m-%d %H:%M:%S")
                    if now > end_dt:
                        print(f"[Auto-Finalizer] Session {s['id']} expired at {end_dt}. Finalizing now...")
                        finalize_session_logic(s['id'])
                except ValueError:
                    continue
                    
        except Exception as e:
            print(f"[Auto-Finalizer] Error: {e}")
            
        time.sleep(60) # Check every minute

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

@app.route('/success')
def success_page():
    return render_template('success.html')

if __name__ == '__main__':
    # Initialize DB (creates tables and runs migrations)
    init_db()
    
    # Start Background Threads
    import threading
    
    t1 = threading.Thread(target=auto_finalizer_thread)
    t1.daemon = True
    t1.start()

    t2 = threading.Thread(target=weekly_report_thread)
    t2.daemon = True
    t2.start()
    
    # host='0.0.0.0' makes the server accessible from other devices on the network
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
