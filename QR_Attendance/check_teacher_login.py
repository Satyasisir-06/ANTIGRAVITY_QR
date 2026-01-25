"""
Quick diagnostic script to check teacher login credentials
"""
import sqlite3
from werkzeug.security import check_password_hash

def check_teacher_account(username, password):
    print(f"\n{'='*60}")
    print(f"CHECKING LOGIN FOR: {username}")
    print(f"{'='*60}\n")
    
    # Connect to database
    conn = sqlite3.connect('attendance.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Check users table
    print("1. Checking USERS table...")
    user = cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    
    if not user:
        print(f"   ✗ NO USER FOUND with username '{username}'")
        print("\n   Available users:")
        all_users = cursor.execute("SELECT username, role FROM users").fetchall()
        for u in all_users:
            print(f"      - {u['username']} (role: {u['role']})")
        conn.close()
        return
    
    print(f"   ✓ User found: ID={user['id']}, Role={user['role']}")
    
    # Check password
    print("\n2. Checking PASSWORD...")
    if check_password_hash(user['password'], password):
        print(f"   ✓ Password is CORRECT")
    else:
        print(f"   ✗ Password is INCORRECT")
        print(f"   (Stored hash: {user['password'][:50]}...)")
    
    # Check teacher profile
    print("\n3. Checking TEACHER PROFILE...")
    teacher = cursor.execute("SELECT * FROM teachers WHERE user_id = ?", (user['id'],)).fetchone()
    
    if not teacher:
        print(f"   ✗ NO TEACHER PROFILE found for user_id={user['id']}")
        print("\n   Available teacher profiles:")
        all_teachers = cursor.execute("SELECT id, teacher_id, name, user_id FROM teachers").fetchall()
        for t in all_teachers:
            print(f"      - ID={t['id']}, teacher_id={t['teacher_id']}, name={t['name']}, user_id={t['user_id']}")
    else:
        print(f"   ✓ Teacher profile found:")
        print(f"      - ID: {teacher['id']}")
        print(f"      - Teacher_ID: {teacher['teacher_id']}")
        print(f"      - Name: {teacher['name']}")
        print(f"      - Email: {teacher['email']}")
        print(f"      - User_ID: {teacher['user_id']}")
    
    # Summary
    print(f"\n{'='*60}")
    print("DIAGNOSIS:")
    print(f"{'='*60}")
    
    if user and check_password_hash(user['password'], password) and teacher:
        print("✓ LOGIN SHOULD WORK - All checks passed!")
    elif not user:
        print("✗ User account doesn't exist")
    elif not check_password_hash(user['password'], password):
        print("✗ Wrong password")
    elif not teacher:
        print("✗ Teacher profile missing (should auto-create on login)")
    
    conn.close()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) >= 3:
        username = sys.argv[1]
        password = sys.argv[2]
    else:
        username = input("Enter username: ")
        password = input("Enter password: ")
    
    check_teacher_account(username, password)
