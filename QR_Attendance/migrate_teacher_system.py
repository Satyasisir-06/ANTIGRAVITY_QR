"""
Database Migration Script for Teacher Role System
Creates new tables and modifies existing schema
Compatible with both SQLite and PostgreSQL (Vercel)
"""

import os
import sys
from teacher_utils import get_db_connection, DB_INTEGRITY_ERRORS

def migrate_database():
    """Run all database migrations for teacher role system"""
    
    conn = get_db_connection()
    is_postgres = conn.is_postgres
    
    print(f"[MIGRATION] Starting database migration for Teacher Role System ({'Postgres' if is_postgres else 'SQLite'})...")
    
    try:
        # 1. Create teachers table
        print("[1/5] Creating teachers table...")
        id_type = "SERIAL PRIMARY KEY" if is_postgres else "INTEGER PRIMARY KEY AUTOINCREMENT"
        
        conn.execute(f'''
            CREATE TABLE IF NOT EXISTS teachers (
                id {id_type},
                teacher_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                user_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("✓ Teachers table created")
        
        # 2. Create teacher_subjects table
        print("[2/5] Creating teacher_subjects table...")
        conn.execute(f'''
            CREATE TABLE IF NOT EXISTS teacher_subjects (
                id {id_type},
                teacher_id INTEGER NOT NULL,
                subject TEXT NOT NULL,
                branch TEXT NOT NULL,
                day_of_week TEXT,
                time_slot TEXT,
                semester TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(teacher_id, subject, branch, day_of_week, time_slot)
            )
        ''')
        print("✓ Teacher_subjects table created")
        
        # 3. Add role column to users table
        print("[3/5] Adding role column to users table...")
        try:
            conn.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'student'")
            print("✓ Role column added to users")
        except Exception as e:
            # Handle "already exists" errors gracefully
            if "already exists" in str(e).lower() or "duplicate column" in str(e).lower():
                print("✓ Role column already exists")
            else:
                print(f"! Warning adding role column: {e}")
        
        # 4. Add teacher tracking columns to sessions table
        print("[4/5] Adding teacher tracking to sessions table...")
        
        # Add created_by column
        try:
            conn.execute("ALTER TABLE sessions ADD COLUMN created_by INTEGER")
            print("✓ created_by column added to sessions")
        except Exception as e:
            if "already exists" in str(e).lower() or "duplicate column" in str(e).lower():
                print("✓ created_by column already exists")
            else:
                 print(f"! Warning adding created_by: {e}")
        
        # Add teacher_id column
        try:
            conn.execute("ALTER TABLE sessions ADD COLUMN teacher_id INTEGER")
            print("✓ teacher_id column added to sessions")
        except Exception as e:
            if "already exists" in str(e).lower() or "duplicate column" in str(e).lower():
                print("✓ teacher_id column already exists")
            else:
                print(f"! Warning adding teacher_id: {e}")
        
        # 5. Update existing admin users to have 'admin' role
        print("[5/5] Updating existing admin users...")
        res = conn.execute("UPDATE users SET role = 'admin' WHERE role IS NULL OR role = 'student'")
        print(f"✓ Updated users to admin role (Rowcount: {res.rowcount()})")
        
        # Commit all changes
        conn.commit()
        print("\n✅ Database migration completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        raise
    
    finally:
        conn.close()
    
    return True

if __name__ == "__main__":
    migrate_database()
