"""
Database Migration Script for Teacher Role System
Creates new tables and modifies existing schema
"""

import sqlite3
from datetime import datetime

def migrate_database(db_path='attendance.db'):
    """Run all database migrations for teacher role system"""
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("[MIGRATION] Starting database migration for Teacher Role System...")
    
    try:
        # 1. Create teachers table
        print("[1/5] Creating teachers table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS teachers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacher_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                user_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        print("✓ Teachers table created")
        
        # 2. Create teacher_subjects table
        print("[2/5] Creating teacher_subjects table...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS teacher_subjects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacher_id INTEGER NOT NULL,
                subject TEXT NOT NULL,
                branch TEXT NOT NULL,
                day_of_week TEXT,
                time_slot TEXT,
                semester TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (teacher_id) REFERENCES teachers(id),
                UNIQUE(teacher_id, subject, branch, day_of_week, time_slot)
            )
        ''')
        print("✓ Teacher_subjects table created")
        
        # 3. Add role column to users table if it doesn't exist
        print("[3/5] Adding role column to users table...")
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'student'")
            print("✓ Role column added to users")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("✓ Role column already exists")
            else:
                raise
        
        # 4. Add teacher tracking columns to sessions table
        print("[4/5] Adding teacher tracking to sessions table...")
        
        # Add created_by column
        try:
            cursor.execute("ALTER TABLE sessions ADD COLUMN created_by INTEGER")
            print("✓ created_by column added to sessions")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("✓ created_by column already exists")
            else:
                raise
        
        # Add teacher_id column
        try:
            cursor.execute("ALTER TABLE sessions ADD COLUMN teacher_id INTEGER")
            print("✓ teacher_id column added to sessions")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("✓ teacher_id column already exists")
            else:
                raise
        
        # 5. Update existing admin users to have 'admin' role
        print("[5/5] Updating existing admin users...")
        cursor.execute("UPDATE users SET role = 'admin' WHERE role IS NULL OR role = 'student'")
        # Note: You may want to manually set specific users as admin
        admin_count = cursor.rowcount
        print(f"✓ Updated {admin_count} users to admin role (you may need to manually adjust)")
        
        # Commit all changes
        conn.commit()
        
        print("\n✅ Database migration completed successfully!")
        print("\nNew tables created:")
        print("  - teachers")
        print("  - teacher_subjects")
        print("\nColumns added:")
        print("  - users.role")
        print("  - sessions.created_by")  
        print("  - sessions.teacher_id")
        
        # Show table structure
        print("\n📊 Database Schema:")
        for table in ['teachers', 'teacher_subjects', 'users', 'sessions']:
            print(f"\n{table}:")
            cursor.execute(f"PRAGMA table_info({table})")
            for col in cursor.fetchall():
                print(f"  - {col[1]} ({col[2]})")
        
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        conn.rollback()
        raise
    
    finally:
        conn.close()
    
    return True

if __name__ == "__main__":
    import sys
    
    # Allow custom database path
    db_path = sys.argv[1] if len(sys.argv) > 1 else 'attendance.db'
    
    print(f"Database: {db_path}")
    print("=" * 60)
    
    migrate_database(db_path)
    
    print("\n" + "=" * 60)
    print("Migration complete! You can now:")
    print("1. Upload teacher timetables")
    print("2. Register teachers")
    print("3. Assign subjects to teachers")
