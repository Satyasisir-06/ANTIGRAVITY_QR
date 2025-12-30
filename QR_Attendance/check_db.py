
import sqlite3

def check():
    conn = sqlite3.connect('attendance.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    print("--- Table Info: students ---")
    c.execute("PRAGMA table_info(students)")
    for r in c.fetchall():
        print(dict(r))
        
    print("\n--- Table Info: sessions ---")
    c.execute("PRAGMA table_info(sessions)")
    for r in c.fetchall():
        print(dict(r))

    print("\n--- Table Info: attendance ---")
    c.execute("PRAGMA table_info(attendance)")
    for r in c.fetchall():
        print(dict(r))

    print("\n--- Table Info: semester_config ---")
    c.execute("PRAGMA table_info(semester_config)")
    for r in c.fetchall():
        print(dict(r))

    print("\n--- Semester Config Values ---")
    c.execute("SELECT * FROM semester_config")
    rows = c.fetchall()
    for r in rows:
        print(dict(r))

    conn.close()

if __name__ == "__main__":
    check()
