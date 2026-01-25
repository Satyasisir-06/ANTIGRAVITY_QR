import sqlite3

conn = sqlite3.connect('attendance.db')
conn.row_factory = sqlite3.Row

admins = conn.execute('SELECT username, role FROM users WHERE role="admin"').fetchall()

print("\nAdmin accounts in database:")
for admin in admins:
    print(f"  Username: {admin['username']}")

# Check if default admin exists
default_admin = conn.execute('SELECT * FROM users WHERE username="admin"').fetchone()

if not default_admin:
    print("\nNo default 'admin' account found.")
    print("Creating admin account...")
    from werkzeug.security import generate_password_hash
    
    hashed = generate_password_hash('admin123')
    conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', 
                 ('admin', hashed, 'admin'))
    conn.commit()
    print("✓ Admin account created!")
    print("  Username: admin")
    print("  Password: admin123")
else:
    print("\n✓ Default admin exists!")
    print("  Username: admin")
    print("  Password: admin123 (if unchanged)")

conn.close()
