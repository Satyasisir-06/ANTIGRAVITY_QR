import sqlite3
import os

db_path = 'attendance.db'
if not os.path.exists(db_path):
    print(f"Database {db_path} not found.")
else:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    print("--- Distinct Student Branches ---")
    s_branches = c.execute("SELECT DISTINCT branch FROM students").fetchall()
    for b in s_branches:
        print(dict(b))
        
    print("\n--- Distinct Session Branches ---")
    sess_branches = c.execute("SELECT DISTINCT branch FROM sessions").fetchall()
    for b in sess_branches:
        print(dict(b))
        
    print("\n--- Active Sessions ---")
    active = c.execute("SELECT id, subject, branch, is_finalized FROM sessions WHERE is_finalized = 0").fetchall()
    for s in active:
        print(dict(s))
        
    conn.close()
