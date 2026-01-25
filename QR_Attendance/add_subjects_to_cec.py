"""
Quick script to add subjects to CEC25867 locally for testing
"""
import sqlite3

conn = sqlite3.connect('attendance.db')

# Get teacher ID
teacher = conn.execute("SELECT id FROM teachers WHERE teacher_id = 'CEC25867'").fetchone()

if not teacher:
    print("Teacher CEC25867 not found!")
else:
    teacher_id = teacher[0]
    print(f"Found teacher ID: {teacher_id}")
    
    # Add some subjects
    subjects = [
        ('Python Programming', 'CSM', 'Monday', '09:00-10:00', '2025-Spring'),
        ('Data Structures', 'CSM', 'Wednesday', '11:00-12:00', '2025-Spring'),
        ('Web Development', 'CSM', 'Friday', '14:00-15:00', '2025-Spring'),
    ]
    
    for subj, branch, day, time, sem in subjects:
        try:
            conn.execute("""
                INSERT INTO teacher_subjects (teacher_id, subject, branch, day_of_week, time_slot, semester)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (teacher_id, subj, branch, day, time, sem))
            print(f"✓ Added: {subj} - {branch}")
        except Exception as e:
            print(f"✗ Error adding {subj}: {e}")
    
    conn.commit()
    print("\nDone! Now try logging in with CEC25867")

conn.close()
