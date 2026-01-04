
import sqlite3

def check():
    conn = sqlite3.connect('attendance.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    with open('db_schema_info.txt', 'w') as f:
        f.write("--- Table Info: students ---\n")
        c.execute("PRAGMA table_info(students)")
        for r in c.fetchall():
            f.write(str(dict(r)) + "\n")
            
        f.write("\n--- Table Info: sessions ---\n")
        c.execute("PRAGMA table_info(sessions)")
        for r in c.fetchall():
            f.write(str(dict(r)) + "\n")

        f.write("\n--- Table Info: attendance ---\n")
        c.execute("PRAGMA table_info(attendance)")
        for r in c.fetchall():
            f.write(str(dict(r)) + "\n")

        f.write("\n--- Table Info: semester_config ---\n")
        c.execute("PRAGMA table_info(semester_config)")
        for r in c.fetchall():
            f.write(str(dict(r)) + "\n")

        f.write("\n--- Semester Config Values ---\n")
        c.execute("SELECT * FROM semester_config")
        rows = c.fetchall()
        for r in rows:
            f.write(str(dict(r)) + "\n")

    conn.close()

if __name__ == "__main__":
    check()
