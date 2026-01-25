"""
Create CEC25867 teacher account
"""
import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect('attendance.db')
cursor = conn.cursor()

# Create user
username = 'CEC25867'
password = 'sisir@2009'
hashed = generate_password_hash(password)

try:
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                   (username, hashed, 'teacher'))
    user_id = cursor.lastrowid
    
    # Create teacher profile
    cursor.execute("INSERT INTO teachers (teacher_id, name, email, user_id) VALUES (?, ?, ?, ?)",
                   (username, 'Teacher CEC25867', 'cec25867@college.edu', user_id))
    
    conn.commit()
    print(f"✓ Successfully created teacher account: {username}")
    print(f"  User ID: {user_id}")
    print(f"  Password: {password}")
    
except Exception as e:
    print(f"✗ Error: {e}")
finally:
    conn.close()
