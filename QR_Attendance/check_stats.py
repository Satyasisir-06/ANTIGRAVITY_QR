import sqlite3
from datetime import datetime

def check():
    conn = sqlite3.connect('attendance.db')
    today = datetime.now().strftime("%Y-%m-%d")
    print(f"Server Date: {today}")
    
    mech = conn.execute("SELECT COUNT(*) FROM attendance WHERE date = ? AND branch = 'MECH'", (today,)).fetchone()[0]
    print(f"MECH Count Today: {mech}")
    
    conn.close()

if __name__ == "__main__":
    check()
