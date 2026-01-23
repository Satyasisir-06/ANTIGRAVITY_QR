from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, jsonify, send_file
from flask_socketio import SocketIO, emit
import sqlite3
try:
    import psycopg2
    from psycopg2 import IntegrityError as PostgresIntegrityError
except ImportError:
    PostgresIntegrityError = None

# Common Integrity Error tuple for catching
DB_INTEGRITY_ERRORS = (sqlite3.IntegrityError, PostgresIntegrityError) if PostgresIntegrityError else (sqlite3.IntegrityError,)

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

app = Flask(__name__, 
            static_folder='static',
            template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY', 'super_secret_key_for_qr_attendance_system')

# Vercel/Serverless configuration for SocketIO
is_vercel = 'VERCEL' in os.environ
if is_vercel:
    print("[INIT] Running on Vercel mode. Forcing threading mode and disabling background tasks.")
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', manage_session=False)
else:
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

class DBRow:
    """A row object that allows access by index and name (case-insensitive), like sqlite3.Row"""
    def __init__(self, data, description):
        self.data = data
        self.description = description
        # Map lowercase names to indices for case-insensitive lookup
        self._mapping = {d[0].lower(): i for i, d in enumerate(description)}

    def __getitem__(self, key):
        if isinstance(key, int):
            return self.data[key]
        return self.data[self._mapping[key.lower()]]

    def keys(self):
        return [d[0] for d in self.description]

    def __getattr__(self, name):
        name_lower = name.lower()
        if name_lower in self._mapping:
            return self.data[self._mapping[name_lower]]
        raise AttributeError(name)

class DBResult:
    def __init__(self, cursor, is_postgres):
        self.cursor = cursor
        self.is_postgres = is_postgres

    def fetchone(self):
        row = self.cursor.fetchone()
        if self.is_postgres and row is not None:
            return DBRow(list(row), self.cursor.description)
        return row

    def fetchall(self):
        rows = self.cursor.fetchall()
        if self.is_postgres:
            return [DBRow(list(row), self.cursor.description) for row in rows]
        return rows

    def __iter__(self):
        if self.is_postgres:
            for row in self.cursor:
                yield DBRow(list(row), self.cursor.description)
        else:
            for row in self.cursor:
                yield row

    @property
    def lastrowid(self):
        if hasattr(self.cursor, 'lastrowid'):
            return self.cursor.lastrowid
        return None

    def rowcount(self):
        return self.cursor.rowcount

class DBWrapper:
    def __init__(self, conn, is_postgres):
        self.conn = conn
        self.is_postgres = is_postgres

    def execute(self, query, args=()):
        if self.is_postgres:
            query = query.replace('?', '%s')
            cur = self.conn.cursor()
            cur.execute(query, args)
            return DBResult(cur, True)
        else:
            res = self.conn.execute(query, args)
            return DBResult(res, False)

    def cursor(self):
        if self.is_postgres:
            return self.conn.cursor()
        else:
            return self.conn.cursor()

    def executemany(self, query, args_list):
        if self.is_postgres:
            query = query.replace('?', '%s')
            cur = self.conn.cursor()
            cur.executemany(query, args_list)
            return DBResult(cur, True)
        else:
            res = self.conn.executemany(query, args_list)
            return DBResult(res, False)

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()

def get_db_connection():
    db_url = os.environ.get('DATABASE_URL')
    if db_url:
        # Compatibility fix: Some platforms use 'postgres://', but psycopg2 needs 'postgresql://'
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)
            
        try:
            import psycopg2
            # Use standard cursor (returns tuples) so our DBRow can index it easily
            conn = psycopg2.connect(db_url, sslmode='require')
            return DBWrapper(conn, True)
        except Exception as e:
            print(f"[ERROR] Failed to connect to Supabase: {e}")
            raise e
    else:
        conn = sqlite3.connect(DB_NAME, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return DBWrapper(conn, False)

def init_db():
    db_url = os.environ.get('DATABASE_URL')
    conn = get_db_connection()
    
    if db_url:
        print("[DATABASE] Using Supabase/PostgreSQL. Running light init.")
        try:
            # Ensure users table has at least one admin
            admin = conn.execute("SELECT * FROM users WHERE username = ?", ('admin',)).fetchone()
            if not admin:
                hashed_pw = generate_password_hash('admin123')
                conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                          ('admin', hashed_pw, 'admin'))
                conn.commit()
            
            # Simple check for semester_config
            config = conn.execute("SELECT COUNT(*) FROM semester_config").fetchone()[0]
            if config == 0:
                start = datetime.now().replace(month=1, day=1).strftime("%Y-%m-%d")
                end = datetime.now().replace(month=12, day=31).strftime("%Y-%m-%d")
                conn.execute("INSERT INTO semester_config (start_date, end_date, geo_enabled, geo_radius) VALUES (?, ?, ?, ?)", (start, end, False, 200))
                conn.commit()
                
        except Exception as e:
            print(f"[DATABASE] Init Error (Postgres): {e}. This might be expected if script was already run.")
        finally:
            conn.close()
        return

    # LOCAL SQLITE LOGIC (Legacy)
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
    c.execute('CREATE INDEX IF NOT EXISTS idx_branch ON attendance(branch)')
    
    # Check for new columns (Migration for IP Logging)
    c.execute("PRAGMA table_info(attendance)")
    columns = [info[1] for info in c.fetchall()]
    if 'ip_address' not in columns:
        c.execute('ALTER TABLE attendance ADD COLUMN ip_address TEXT')
        c.execute('ALTER TABLE attendance ADD COLUMN device_info TEXT')

# ... (omitting lines for brevity, target content handles matching) ...

# Initialize DB on start
# Removed global init_db() call to prevent double initialization and slow startup
# It is called in if __name__ == '__main__' or should be handled by WSGI entry point explicitly

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
        except DB_INTEGRITY_ERRORS:
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
    
    # Optimized: Single GROUP BY query for branch stats
    branch_stats = conn.execute("""
        SELECT branch, COUNT(*) 
        FROM attendance 
        WHERE date = ? 
        GROUP BY branch
    """, (today_str,)).fetchall()
    
    # Dictionary for O(1) lookups
    # Normalize branch names from DB to upper case key
    stats_map = {row[0].upper(): row[1] for row in branch_stats if row[0]}
    
    # Helper to get count for a list of branches or single branch
    def get_count(branches):
        if isinstance(branches, str):
            return stats_map.get(branches.upper(), 0)
        return sum(stats_map.get(b.upper(), 0) for b in branches)
    
    cse_branches = ['CAI', 'CSM', 'CSD', 'CSE-A', 'CSE-B', 'CSE-C', 'CSE-D']
    
    cse_count = get_count(cse_branches)
    ece_count = get_count('ECE')
    eee_count = get_count('EEE')
    mech_count = get_count('MECH')
    civil_count = get_count('CIVIL')

    # Fetch Subjects for Dropdown
    subjects = conn.execute('SELECT * FROM subjects ORDER BY name').fetchall()
    
    # Fetch Active Sessions
    active_sessions_raw = conn.execute("SELECT * FROM sessions WHERE is_finalized = ?", (False,)).fetchall()
    
    # Add absolute end_timestamp for accurate JS timers
    active_sessions = []
    for s in active_sessions_raw:
        s_dict = dict(s)
        try:
            # Reconstruct datetime to get localized/absolute timestamp
            start_dt_str = f"{s['date']} {s['start_time']}"
            start_dt_obj = datetime.strptime(start_dt_str, "%Y-%m-%d %H:%M:%S")
            s_dict['start_timestamp'] = start_dt_obj.timestamp()
            
            end_dt_str = f"{s['date']} {s['end_time']}"
            end_dt_obj = datetime.strptime(end_dt_str, "%Y-%m-%d %H:%M:%S")
            s_dict['end_timestamp'] = end_dt_obj.timestamp()
        except Exception:
            s_dict['start_timestamp'] = 0
            s_dict['end_timestamp'] = 0
        active_sessions.append(s_dict)
    
    conn.close()
    
    return render_template('admin.html', 
                           cse_count=cse_count,
                           ece_count=ece_count,
                           eee_count=eee_count,
                           mech_count=mech_count,
                           civil_count=civil_count,
                           subjects=subjects,
                           active_sessions=active_sessions,
                           server_now=datetime.now().timestamp())

@app.route('/api/stats')
def api_stats():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = get_db_connection()
    today_str = datetime.now().strftime("%Y-%m-%d")
    
    # Optimized: Single Query
    branch_stats = conn.execute("""
        SELECT branch, COUNT(*) 
        FROM attendance 
        WHERE date = ? 
        GROUP BY branch
    """, (today_str,)).fetchall()
    
    stats_map = {row[0].upper(): row[1] for row in branch_stats if row[0]}
    
    def get_count(branches):
        if isinstance(branches, str):
            return stats_map.get(branches.upper(), 0)
        return sum(stats_map.get(b.upper(), 0) for b in branches)
    
    cse_branches = ['CAI', 'CSM', 'CSD', 'CSE-A', 'CSE-B', 'CSE-C', 'CSE-D']
    
    conn.close()
    
    return jsonify({
        'cse': get_count(cse_branches),
        'ece': get_count('ECE'),
        'eee': get_count('EEE'),
        'mech': get_count('MECH'),
        'civil': get_count('CIVIL')
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
    # Fetch Semester Config first to filter attendance by date
    config = conn.execute("SELECT * FROM semester_config").fetchone()
    holidays = conn.execute("SELECT * FROM holidays").fetchall()
    
    total_present = 0
    records = []
    corrections = []
    
    if session['role'] == 'student':
        # Filter by Current Semester Dates
        start_date = config['start_date']
        end_date = config['end_date']
        
        # Count Present only within semester range
        query_res = conn.execute("SELECT COUNT(*) FROM attendance WHERE roll = ? AND status='PRESENT' AND date >= ? AND date <= ?", 
                                 (username, start_date, end_date)).fetchone()
        if query_res:
            total_present = query_res[0]
        
        # Fetch records for current semester only (or all? usually semester specific dashboard)
        records = conn.execute("SELECT * FROM attendance WHERE roll = ? AND date >= ? AND date <= ? ORDER BY date DESC, time DESC", 
                               (username, start_date, end_date)).fetchall()
        
        # Fetch pending/history of corrections
        corrections = conn.execute("""
            SELECT cr.*, s.subject 
            FROM correction_requests cr 
            LEFT JOIN sessions s ON cr.session_id = s.id 
            WHERE cr.roll = ? 
            ORDER BY cr.timestamp DESC
        """, (username,)).fetchall()
    
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
        conn = get_db_connection()
        cursor = conn.execute('''
            INSERT INTO sessions (subject, branch, date, start_time, end_time, class_type, qr_token, is_finalized) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (subject, branch, date_str, start_time, end_time, class_type, token, False))
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
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
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    try:
        conn = get_db_connection()
        config = conn.execute("SELECT * FROM semester_config").fetchone()
        
        session_data = conn.execute("SELECT * FROM sessions WHERE qr_token = ?", (token,)).fetchone()
        
        if not session_data:
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid Session Token'}), 404
    
        # Verify not finalized
        if session_data['is_finalized']:
            conn.close()
            return jsonify({'success': False, 'message': 'Attendance period has ended. Session is finalized.'}), 400
          
        # Upsert attendance
        # We check if student already marked for THIS subject TODAY
        # This prevents multiple scans for the same subject even in different sessions
        existing = conn.execute('''
            SELECT id FROM attendance 
            WHERE LOWER(roll) = LOWER(?) AND date = ? AND LOWER(subject) = LOWER(?) AND LOWER(branch) = LOWER(?)
        ''', (roll, session_data['date'], session_data['subject'], session_data['branch'])).fetchone()
        
        if existing:
            conn.close()
            return jsonify({'success': False, 'message': 'Attendance already marked for this subject today!'}), 400
        
        # Insert attendance record
        now_time = datetime.now().strftime("%H:%M:%S")
        conn.execute('''INSERT INTO attendance 
                        (roll, name, subject, branch, date, time, session_id, status) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, 'PRESENT')''',
                        (roll, name, session_data['subject'], session_data['branch'], 
                         session_data['date'], now_time, session_data['id']))
        conn.commit()
        conn.close()
        
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
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Range: Last 7 days
    end_date = datetime.now()
    start_date = end_date - timedelta(days=7)
    
    start_str = start_date.strftime("%Y-%m-%d")
    end_str = end_date.strftime("%Y-%m-%d")
    
    filename = f"Weekly_Report_{start_str}_to_{end_str}.csv"
    # Use /tmp for Vercel/Serverless environments
    reports_dir = '/tmp' if os.environ.get('VERCEL') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME') else os.path.join('static', 'reports')
    
    filename = f"Weekly_Report_{start_str}_to_{end_str}.csv"
    filepath = os.path.join(reports_dir, filename)
    
    # Ensure directory exists (if not /tmp which always exists)
    if reports_dir != '/tmp':
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
        
    # 2. Branch Performance (Dynamic)
    branch_rows = cur.execute("SELECT DISTINCT branch FROM students WHERE branch IS NOT NULL AND branch != ''").fetchall()
    branches = sorted([r[0] for r in branch_rows])
    if not branches:
        branches = ['CSM', 'CSD', 'CSE-A', 'CSE-B', 'CSE-C', 'CSE-D', 'CIVIL', 'MECH', 'ECE', 'EEE']
        
    branch_data = []
    for b in branches:
        # Using LOWER for case-insensitivity consistency
        total = cur.execute("SELECT COUNT(*) FROM attendance WHERE LOWER(branch) = LOWER(?)", (b,)).fetchone()[0]
        if total == 0:
            branch_data.append(0)
        else:
            present = cur.execute("SELECT COUNT(*) FROM attendance WHERE LOWER(branch) = LOWER(?) AND status = 'PRESENT'", (b,)).fetchone()[0]
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
    raw_holidays = conn.execute("SELECT * FROM holidays ORDER BY date").fetchall()
    
    # Simple Grouping logic for UI
    from itertools import groupby
    grouped_holidays = []
    for desc, items in groupby(raw_holidays, lambda x: x['description']):
        item_list = list(items)
        if len(item_list) > 1:
            start_h = item_list[0]
            end_h = item_list[-1]
            grouped_holidays.append({
                'id': start_h['id'], # For deletion (might need better logic but this works for now)
                'ids': [i['id'] for i in item_list],
                'date_display': f"{start_h['date']} to {end_h['date']}",
                'description': desc
            })
        else:
            h = item_list[0]
            grouped_holidays.append({
                'id': h['id'],
                'ids': [h['id']],
                'date_display': h['date'],
                'description': desc
            })
            
    conn.close()
    return render_template('settings.html', config=config, holidays=grouped_holidays)

@app.route('/update_semester_dates', methods=['POST'])
def update_semester_dates():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    start_date = request.form['start_date']
    end_date = request.form['end_date']
    
    conn = get_db_connection()
    row = conn.execute("SELECT id FROM semester_config LIMIT 1").fetchone()
    
    if not row:
         conn.execute('''INSERT INTO semester_config (start_date, end_date) 
                         VALUES (?, ?)''', (start_date, end_date))
    else:
        cfg_id = row['id'] if hasattr(row, 'id') else row[0]
        conn.execute('''UPDATE semester_config 
                        SET start_date = ?, end_date = ?
                        WHERE id = ?''', 
                     (start_date, end_date, cfg_id))
    conn.commit()
    conn.close()
    
    flash("Semester dates updated!", "success")
    return redirect(url_for('settings'))

@app.route('/update_geofencing', methods=['POST'])
def update_geofencing():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    geo_enabled = 1 if 'geo_enabled' in request.form else 0
    import re
    def clean_coord(val):
        if not val: return 0.0
        cleaned = re.sub(r'[^0-9\.-]', '', str(val))
        try: return float(cleaned)
        except: return 0.0

    college_lat = clean_coord(request.form.get('college_lat'))
    college_lng = clean_coord(request.form.get('college_lng'))
    geo_radius = request.form.get('geo_radius', 200)
    
    conn = get_db_connection()
    row = conn.execute("SELECT id FROM semester_config LIMIT 1").fetchone()
    
    if not row:
         conn.execute('''INSERT INTO semester_config (geo_enabled, college_lat, college_lng, geo_radius) 
                         VALUES (?, ?, ?, ?)''',
                         (geo_enabled, college_lat, college_lng, geo_radius))
    else:
        cfg_id = row['id'] if hasattr(row, 'id') else row[0]
        conn.execute('''UPDATE semester_config 
                        SET geo_enabled = ?, college_lat = ?, college_lng = ?, geo_radius = ?
                        WHERE id = ?''', 
                     (geo_enabled, college_lat, college_lng, geo_radius, cfg_id))
    conn.commit()
    conn.close()
    
    flash("Geofencing settings updated!", "success")
    return redirect(url_for('settings'))

@app.route('/update_sms_config', methods=['POST'])
def update_sms_config():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
        
    # Explicitly cast to integer (1/0) for PostgreSQL compatibility
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

@app.route('/delete_holidays_bulk', methods=['POST'])
def delete_holidays_bulk():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    data = request.json
    ids = data.get('ids', [])
    if not ids:
        return jsonify({'success': False, 'message': 'No IDs provided'}), 400
        
    conn = get_db_connection()
    # Batch delete
    conn.execute(f"DELETE FROM holidays WHERE id IN ({','.join(['?']*len(ids))})", ids)
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
                     
                     if conn.is_postgres:
                         conn.execute("""
                            INSERT INTO students (roll, name, branch, parent_email, parent_phone) VALUES (?, ?, ?, ?, ?)
                            ON CONFLICT(roll) DO UPDATE SET
                            name=EXCLUDED.name,
                            branch=EXCLUDED.branch,
                            parent_email=EXCLUDED.parent_email,
                            parent_phone=EXCLUDED.parent_phone
                         """, (roll, name, branch, None, p_phone))
                     else:
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
        if conn.is_postgres:
            conn.execute("""
                INSERT INTO students (roll, name, branch, parent_phone) VALUES (?, ?, ?, ?)
                ON CONFLICT(roll) DO UPDATE SET
                name=EXCLUDED.name,
                branch=EXCLUDED.branch,
                parent_phone=EXCLUDED.parent_phone
            """, (roll, name, branch, p_phone))
        else:
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
                
    # Fetch Gateway Config
    config = conn.execute("SELECT * FROM semester_config").fetchone()
    
    if not config or not config['sms_enabled']:
        conn.close()
        return jsonify({'success': False, 'message': 'SMS Not Enabled in Settings', 'sent': 0, 'total': 0, 'errors': []})
        
    sms_handler = SMSHandler(config['sms_sid'], config['sms_auth_token'], config['sms_from_number'])
    
    sent_count = 0
    errors = []
    
    for s in students_to_notify:
        phone = s['parent_phone']
        if phone:
            # We determine subject/threshold context if possible, otherwise generic
            # For manual notification, stick to generic or require context
            now_time = datetime.now().strftime("%I:%M %p")
            subject_text = f" for '{data.get('subject', 'Classes')}'" 
            msg = f"[Chaitanya Engineering College] Absent Alert: {s['name']} ({s['roll']}) was absent{subject_text} on {today_str} (Reported: {now_time})."
            
            success, status = sms_handler.send_sms(phone, msg)
            if success:
                sent_count += 1
                # Log it
                conn.execute("INSERT INTO sms_logs (roll, phone, message, status) VALUES (?, ?, ?, ?)", 
                             (s['roll'], phone, msg, 'SENT'))
            else:
                errors.append(f"{s['roll']}: {status}")
                conn.execute("INSERT INTO sms_logs (roll, phone, message, status, error_message) VALUES (?, ?, ?, ?, ?)", 
                             (s['roll'], phone, msg, 'FAILED', status))

            
    conn.commit()

            
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

@app.route('/api/active_sessions')
def api_active_sessions():
    """API endpoint to get all active (unfinalized) sessions"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    conn = get_db_connection()
    active_sessions = conn.execute("SELECT * FROM sessions WHERE is_finalized = ? ORDER BY date DESC, start_time DESC", (False,)).fetchall()
    conn.close()
    
    # Convert to list of dicts and check expiration status
    now = datetime.now()
    sessions_list = []
    
    for s in active_sessions:
        s_dict = dict(s)
        end_dt_str = f"{s['date']} {s['end_time']}"
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
    
    conn = get_db_connection()
    active_sessions = conn.execute("SELECT * FROM sessions WHERE is_finalized = ?", (False,)).fetchall()
    conn.close()
    
    now = datetime.now()
    expired_sessions = []
    
    for s in active_sessions:
        end_dt_str = f"{s['date']} {s['end_time']}"
        try:
            end_dt = datetime.strptime(end_dt_str, "%Y-%m-%d %H:%M:%S")
            if now > end_dt:
                expired_sessions.append(s['id'])
        except:
            continue
    
    if not expired_sessions:
        return jsonify({
            'success': True,
            'message': 'No expired sessions to finalize',
            'finalized_count': 0
        })
    
    # Finalize each expired session
    finalized_count = 0
    errors = []
    
    for session_id in expired_sessions:
        try:
            result = finalize_session_logic(session_id)
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
        conn = get_db_connection()
        
        # Check if session exists
        current_session = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if not current_session:
            conn.close()
            return jsonify({'success': False, 'message': 'Session not found'}), 404
        
        # Unfinalize the session
        conn.execute("UPDATE sessions SET is_finalized = ? WHERE id = ?", (False, session_id))
        
        # Optional: Delete ABSENT records from this session to allow re-finalization
        delete_absents = data.get('delete_absents', True)
        if delete_absents:
            conn.execute("DELETE FROM attendance WHERE session_id = ? AND status = 'ABSENT'", (session_id,))
        
        conn.commit()
        conn.close()
        
        print(f"[Session Restart] Session {session_id} has been restarted successfully")
        
        return jsonify({
            'success': True,
            'message': 'Session restarted successfully. It is now active again.',
            'session_id': session_id
        })
    except Exception as e:
        print(f"[Session Restart Error] {e}")
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'Error restarting session: {str(e)}'}), 500

@app.route('/api/clear_all_sessions', methods=['POST'])
def api_clear_all_sessions():
    """API endpoint to clear ALL active sessions (emergency cleanup)"""
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        conn = get_db_connection()
        
        # Get count of active sessions before clearing
        count_result = conn.execute("SELECT COUNT(*) FROM sessions WHERE is_finalized = ?", (False,)).fetchone()
        active_count = count_result[0] if count_result else 0
        
        # Mark all active sessions as finalized
        conn.execute("UPDATE sessions SET is_finalized = ? WHERE is_finalized = ?", (True, False))
        conn.commit()
        conn.close()
        
        print(f"[Clear All Sessions] Cleared {active_count} active session(s)")
        
        return jsonify({
            'success': True,
            'message': f'All {active_count} active session(s) have been cleared',
            'cleared_count': active_count
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
        conn = get_db_connection()
        
        # Check if session exists
        current_session = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if not current_session:
            conn.close()
            return jsonify({'success': False, 'message': 'Session not found'}), 404
        
        # Delete all attendance records for this session
        conn.execute("DELETE FROM attendance WHERE session_id = ?", (session_id,))
        
        # Delete the session itself
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        
        conn.commit()
        conn.close()
        
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
    
    conn = None
    try:
        conn = get_db_connection()
        
        # Get session details
        sess = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        
        if not sess:
            print(f"[FINALIZE ERROR] Session {session_id} not found")
            if conn:
                conn.close()
            return {'success': False, 'message': 'Session not found'}
        
        if sess['is_finalized']:
            print(f"[FINALIZE SKIP] Session {session_id} already finalized")
            if conn:
                conn.close()
            return {'success': True, 'message': 'Session already finalized', 'already_done': True, 'absent_count': 0}
        
        branch = sess['branch'].strip().upper()
        subject = sess['subject']
        date = sess['date']
        
        print(f"[FINALIZE] Session {session_id}: {subject} - {branch} on {date}")
        
        # Get all students in this branch
        all_students = conn.execute(
            "SELECT roll, name FROM students WHERE UPPER(TRIM(branch)) = ?", 
            (branch,)
        ).fetchall()
        
        if not all_students:
            print(f"[FINALIZE WARNING] No students found in branch {branch}")
            # Still mark as finalized even if no students
            conn.execute("UPDATE sessions SET is_finalized = ? WHERE id = ?", (True, session_id))
            conn.commit()
            conn.close()
            return {'success': True, 'message': 'Session finalized (no students in branch)', 'absent_count': 0}
        
        all_rolls = {s['roll'] for s in all_students}
        print(f"[FINALIZE] Total students in {branch}: {len(all_rolls)}")
        
        # Get students who marked attendance (PRESENT)
        present_records = conn.execute(
            "SELECT roll FROM attendance WHERE session_id = ? AND status = 'PRESENT'",
            (session_id,)
        ).fetchall()
        present_rolls = {r['roll'] for r in present_records}
        print(f"[FINALIZE] Students present: {len(present_rolls)}")
        
        # Calculate absentees
        absent_rolls = all_rolls - present_rolls
        print(f"[FINALIZE] Students absent: {len(absent_rolls)}")
        
        # Create student map for names
        student_map = {s['roll']: s['name'] for s in all_students}
        
        # Insert absent records
        now_time = datetime.now().strftime("%H:%M:%S")
        absent_data = []
        
        for roll in absent_rolls:
            absent_data.append((
                roll,
                student_map.get(roll, 'Unknown'),
                subject,
                branch,
                date,
                now_time,
                session_id,
                'ABSENT'
            ))
        
        if absent_data:
            conn.executemany('''
                INSERT INTO attendance (roll, name, subject, branch, date, time, session_id, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', absent_data)
            print(f"[FINALIZE] Inserted {len(absent_data)} ABSENT records")
        
        # Mark session as finalized
        conn.execute("UPDATE sessions SET is_finalized = ? WHERE id = ?", (True, session_id))
        conn.commit()
        
        print(f"[FINALIZE SUCCESS] Session {session_id} finalized. {len(absent_data)} absent")
        
        conn.close()
        
        return {
            'success': True,
            'message': f'Session finalized. {len(absent_data)} students marked absent.',
            'absent_count': len(absent_data)
        }
        
    except Exception as e:
        print(f"[FINALIZE ERROR] Exception during finalization: {e}")
        traceback.print_exc()
        if conn:
            try:
                conn.close()
            except:
                pass
        return {'success': False, 'message': f'Finalization failed: {str(e)}'}


def auto_finalizer_thread():
    """
    Background thread that auto-finalizes expired sessions.
    Runs every 30 seconds.
    """
    print("[AUTO-FINALIZER] Thread started. Checking every 30 seconds...")
    
    while True:
        try:
            # Use a fresh DB connection for each check
            conn = get_db_connection()
            active_sessions = conn.execute(
                "SELECT * FROM sessions WHERE is_finalized = ? ORDER BY date DESC, start_time DESC",
                (False,)
            ).fetchall()
            conn.close()
            
            if not active_sessions:
                time.sleep(30)
                continue
            
            now = datetime.now()
            finalized_count = 0
            
            for sess in active_sessions:
                try:
                    # Parse end time
                    end_datetime_str = f"{sess['date']} {sess['end_time']}"
                    end_dt = datetime.strptime(end_datetime_str, "%Y-%m-%d %H:%M:%S")
                    
                    # Check if expired
                    if now > end_dt:
                        print(f"[AUTO-FINALIZER] Session {sess['id']} expired. Finalizing...")
                        
                        result = finalize_session_core(sess['id'])
                        
                        if result['success'] and not result.get('already_done'):
                            finalized_count += 1
                            print(f"[AUTO-FINALIZER] ✓ Finalized session {sess['id']}")
                            
                except ValueError as ve:
                    print(f"[AUTO-FINALIZER] Date parse error for session {sess['id']}: {ve}")
                except Exception as e:
                    print(f"[AUTO-FINALIZER] Error finalizing session {sess['id']}: {e}")
                    traceback.print_exc()
            
            if finalized_count > 0:
                print(f"[AUTO-FINALIZER] ✓ Auto-finalized {finalized_count} session(s)")
            
        except Exception as e:
            print(f"[AUTO-FINALIZER] Critical error in main loop: {e}")
            traceback.print_exc()
        
        time.sleep(30)

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
