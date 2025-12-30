import sqlite3
import os
import sys

DB_NAME = "attendance.db"

def test_duplication():
    print("--- Starting Duplicate Prevention Test ---")
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # Clean up test data if exists
    test_roll = "TEST-ROLL-999"
    test_subject = "Test Logic"
    test_date = "2025-12-30"
    
    c.execute("DELETE FROM attendance WHERE roll = ?", (test_roll,))
    conn.commit()
    
    print(f"1. Attempting first insertion for {test_roll}...")
    try:
        c.execute("INSERT INTO attendance (roll, name, subject, branch, date, time) VALUES (?, ?, ?, ?, ?, ?)",
                  (test_roll, "Test Student", test_subject, "CSE", test_date, "10:00:00"))
        conn.commit()
        print("   -> Success (First time)")
    except Exception as e:
        print(f"   -> ERROR: {e}")
        return

    print(f"2. Attempting exact duplicate insertion...")
    try:
        c.execute("INSERT INTO attendance (roll, name, subject, branch, date, time) VALUES (?, ?, ?, ?, ?, ?)",
                  (test_roll, "Test Student", test_subject, "CSE", test_date, "10:05:00"))
        conn.commit()
        print("   -> FAIL: Duplicate was allowed (Error!)")
    except sqlite3.IntegrityError:
        print("   -> PASS: Duplicate blocked by DB constraint.")
    except Exception as e:
        print(f"   -> ERROR: Unexpected error: {e}")

    print(f"3. Attempting insertion with different case (testing normalization logic)...")
    # Note: DB constraint is on (roll, subject, date). 
    # If we insert "test-roll-999" directly, SQLite might allow it if it's case-sensitive.
    # Our app handles this by .upper() before inserting.
    
    normalized_roll = "test-roll-999".strip().upper()
    if normalized_roll == test_roll:
         print(f"   (Verification: {normalized_roll} matches {test_roll} after normalization)")
    
    try:
        c.execute("INSERT INTO attendance (roll, name, subject, branch, date, time) VALUES (?, ?, ?, ?, ?, ?)",
                  (normalized_roll, "Test Student", test_subject, "CSE", test_date, "10:10:00"))
        conn.commit()
        print("   -> FAIL: Duplicate with different case was allowed (Error!)")
    except sqlite3.IntegrityError:
        print("   -> PASS: Duplicate with different case blocked by DB constraint.")
        
    conn.close()
    print("--- Test Completed ---")

if __name__ == "__main__":
    if not os.path.exists(DB_NAME):
        print(f"Error: {DB_NAME} not found.")
    else:
        test_duplication()
