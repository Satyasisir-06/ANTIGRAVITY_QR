import sqlite3

DB_NAME = "attendance.db"

def apply_migration():
    print("--- Starting Database Migration ---")
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    # 1. Clean up existing duplicates that would prevent index creation
    # Keep only the earliest record for each (roll, subject, date)
    print("1. Cleaning up existing duplicates (if any)...")
    c.execute("""
        DELETE FROM attendance 
        WHERE id NOT IN (
            SELECT MIN(id) 
            FROM attendance 
            GROUP BY roll, subject, date
        )
    """)
    print(f"   Deleted {c.rowcount} duplicate rows.")
    
    # 2. Add the unique index
    print("2. Applying unique index (roll, subject, date)...")
    try:
        c.execute("DROP INDEX IF EXISTS idx_unique_attendance")
        c.execute("CREATE UNIQUE INDEX idx_unique_attendance ON attendance(roll, subject, date)")
        print("   Index created successfully.")
    except Exception as e:
        print(f"   Error creating index: {e}")
        
    conn.commit()
    conn.close()
    print("--- Migration Completed ---")

if __name__ == "__main__":
    apply_migration()
