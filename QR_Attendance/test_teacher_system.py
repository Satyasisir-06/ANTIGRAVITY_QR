"""
Quick testing script to verify Teacher Role System setup

This script helps test key components:
1. Database structure
2. Sample teacher creation
3. Teacher login credentials
"""

import sqlite3
from werkzeug.security import generate_password_hash

DB_NAME = "attendance.db"

def verify_database():
    """Verify all required tables exist"""
    print("\n=== Verifying Database Structure ===")
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Check tables
    tables = ['teachers', 'teacher_subjects', 'users', 'sessions']
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='{table}'")
        if cursor.fetchone()[0] == 1:
            print(f"✓ Table '{table}' exists")
            
            # Show count
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            count = cursor.fetchone()[0]
            print(f"  └─ Records: {count}")
        else:
            print(f"✗ Table '{table}' NOT FOUND")
    
    # Check role column in users
    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'role' in columns:
        print("✓ Column 'users.role' exists")
    else:
        print("✗ Column 'users.role' NOT FOUND")
    
    conn.close()

def create_test_teacher_login():
    """Create a test teacher login for T001"""
    print("\n=== Creating Test Teacher Login ===")
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Check if teacher T001 exists
    cursor.execute("SELECT id, name FROM teachers WHERE teacher_id = 'T001'")
    teacher = cursor.fetchone()
    
    if not teacher:
        print("✗ Teacher T001 not found. Please upload timetable CSV first.")
        conn.close()
        return
    
    teacher_db_id, teacher_name = teacher
    print(f"✓ Found teacher: {teacher_name} (ID: {teacher_db_id})")
    
    # Check if user already exists
    cursor.execute("SELECT id FROM users WHERE username = 'T001'")
    existing_user = cursor.fetchone()
    
    if existing_user:
        print(f"! User 'T001' already exists (user_id: {existing_user[0]})")
        
        # Link to teacher if not linked
        cursor.execute("UPDATE teachers SET user_id = ? WHERE id = ?", (existing_user[0], teacher_db_id))
        conn.commit()
        print("✓ Teacher linked to existing user")
    else:
        # Create new user
        password = "teacher123"  # Default password for testing
        hashed = generate_password_hash(password)
        
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                      ('T001', hashed, 'teacher'))
        user_id = cursor.lastrowid
        
        # Link teacher to user
        cursor.execute("UPDATE teachers SET user_id = ? WHERE id = ?", (user_id, teacher_db_id))
        conn.commit()
        
        print(f"✓ Created user 'T001' with password 'teacher123'")
        print(f"✓ Linked to teacher record (user_id: {user_id})")
    
    conn.close()
    print("\n📝 Login Credentials:")
    print("   Username: T001")
    print("   Password: teacher123")

def show_teacher_assignments():
    """Show what subjects teacher T001 is assigned to"""
    print("\n=== Teacher T001 Subject Assignments ===")
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT ts.subject, ts.branch, ts.day_of_week, ts.time_slot
        FROM teacher_subjects ts
        JOIN teachers t ON ts.teacher_id = t.id
        WHERE t.teacher_id = 'T001'
        ORDER BY ts.day_of_week, ts.time_slot
    """)
    
    assignments = cursor.fetchall()
    
    if assignments:
        print(f"Found {len(assignments)} subject assignments:")
        for subject, branch, day, time_slot in assignments:
            print(f"  • {subject} - {branch} ({day} {time_slot})")
    else:
        print("No assignments found. Upload timetable CSV first.")
    
    conn.close()

def check_admin_user():
    """Check if admin user exists"""
    print("\n=== Checking Admin User ===")
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT username, role FROM users WHERE role = 'admin'")
    admins = cursor.fetchall()
    
    if admins:
        print(f"Found {len(admins)} admin user(s):")
        for username, role in admins:
            print(f"  • {username} (role: {role})")
    else:
        print("⚠ No admin users found!")
        print("Creating default admin...")
        
        password = "admin123"
        hashed = generate_password_hash(password)
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                      ('admin', hashed, 'admin'))
        conn.commit()
        print("✓ Created admin user")
        print("   Username: admin")
        print("   Password: admin123")
    
    conn.close()

if __name__ == "__main__":
    print("=" * 60)
    print("Teacher Role System - Testing Helper")
    print("=" * 60)
    
    verify_database()
    check_admin_user()
    create_test_teacher_login()
    show_teacher_assignments()
    
    print("\n" + "=" * 60)
    print("Testing helper complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Login as admin (admin/admin123)")
    print("2. Upload sample_timetable.csv")
    print("3. Run this script again to create teacher login")
    print("4. Login as teacher (T001/teacher123)")
    print("5. Test session creation")
