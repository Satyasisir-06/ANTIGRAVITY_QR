"""
Teacher Data Setup Script
Populates the teachers and teacher_subjects tables from sample_timetable.csv
and links teacher profiles to user accounts.
"""

import sqlite3
import io
import csv
from teacher_utils import parse_timetable_csv, insert_teachers_and_subjects

def setup_data():
    print("=== Teacher Role System Setup ===")
    
    # 1. Parse CSV
    print("Reading sample_timetable.csv...")
    try:
        with open('sample_timetable.csv', 'rb') as f:
            success, result = parse_timetable_csv(f)
            
        if not success:
            print(f"✗ CSV Parsing Error: {result}")
            return
            
        teachers_data = result['teachers']
        subjects_data = result['subjects']
        print(f"✓ Parsed {len(teachers_data)} teachers and {len(subjects_data)} subject assignments")
        
        # 2. Insert into DB
        print("Inserting data into database...")
        success, message, details = insert_teachers_and_subjects(teachers_data, subjects_data)
        
        if not success:
            print(f"✗ Database Error: {message}")
            return
            
        print(f"✓ {message}")
        
        # 3. Link teachers to users
        print("Linking teacher profiles to users...")
        conn = sqlite3.connect('attendance.db')
        cursor = conn.cursor()
        
        # Link all teachers where username matches teacher_id
        cursor.execute("""
            UPDATE teachers 
            SET user_id = (SELECT id FROM users WHERE username = teachers.teacher_id)
            WHERE user_id IS NULL
        """)
        
        linked_count = cursor.rowcount
        conn.commit()
        
        # Verify T001 specifically
        cursor.execute("SELECT t.id, t.name, u.id as user_id, u.role FROM teachers t LEFT JOIN users u ON t.user_id = u.id WHERE t.teacher_id = 'T001'")
        t001 = cursor.fetchone()
        
        if t001:
            print(f"✓ Teacher T001 Status: {t001[1]} (User ID: {t001[2]}, Role: {t001[3]})")
            if not t001[2]:
                print("! Warning: T001 still not linked to a user. Checking if user 'T001' exists...")
                cursor.execute("SELECT id FROM users WHERE username = 'T001'")
                u001 = cursor.fetchone()
                if u001:
                    print(f"  Found user 'T001' with ID {u001[0]}. Re-linking...")
                    cursor.execute("UPDATE teachers SET user_id = ? WHERE teacher_id = 'T001'", (u001[0],))
                    conn.commit()
                    print("  ✓ Corrected link for T001")
                else:
                    print("  ✗ User 'T001' not found. Please ensure the teacher user exists in the 'users' table.")
        
        conn.close()
        print(f"✓ Linked {linked_count} existing users to teacher profiles")
        print("\n=== Setup Complete ===")
        print("You should now be able to login as T001.")
        
    except FileNotFoundError:
        print("✗ Error: sample_timetable.csv not found in current directory")
    except Exception as e:
        print(f"✗ Unexpected Error: {str(e)}")

if __name__ == "__main__":
    setup_data()
