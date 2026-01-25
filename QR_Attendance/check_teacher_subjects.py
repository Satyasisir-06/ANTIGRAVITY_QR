"""
Check what subjects are assigned to each teacher
"""
import sqlite3

conn = sqlite3.connect('attendance.db')
conn.row_factory = sqlite3.Row

print("\n" + "="*70)
print("TEACHER SUBJECT ASSIGNMENTS")
print("="*70 + "\n")

# Get all teachers
teachers = conn.execute("SELECT * FROM teachers").fetchall()

for teacher in teachers:
    print(f"Teacher: {teacher['name']} (ID: {teacher['teacher_id']})")
    
    # Get their subjects
    subjects = conn.execute("""
        SELECT subject, branch, day_of_week, time_slot 
        FROM teacher_subjects 
        WHERE teacher_id = ?
    """, (teacher['id'],)).fetchall()
    
    if subjects:
        for subj in subjects:
            print(f"  ✓ {subj['subject']} - {subj['branch']} ({subj['day_of_week']} {subj['time_slot']})")
    else:
        print(f"  ✗ NO SUBJECTS ASSIGNED")
    print()

conn.close()
