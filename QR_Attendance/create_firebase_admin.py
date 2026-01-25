"""
Script to create initial admin account in Firebase
Run this once after Firebase setup
"""
import firebase_db as db

print("\n" + "="*60)
print("CREATING ADMIN ACCOUNT IN FIREBASE")
print("="*60 + "\n")

try:
    # Initialize Firebase
    db.get_db()
    
    # Check if admin already exists
    existing_admin = db.get_user_by_username('admin')
    
    if existing_admin:
        print("✓ Admin account already exists!")
        print("  Username: admin")
        print("  (Password unchanged)")
    else:
        # Create admin account
        print("Creating admin account...")
        db.create_user(
            username='admin',
            password='admin123',
            role='admin',
            email='admin@qr-attendance.local'
        )
        print("\n✓ Admin account created successfully!")
        print("  Username: admin")
        print("  Password: admin123")
        print("\n⚠️  IMPORTANT: Change this password after first login!")
    
    print("\n" + "="*60)
    print("You can now login at http://127.0.0.1:5000/login")
    print("="*60 + "\n")
    
except Exception as e:
    print(f"\n✗ Error: {e}")
    print("\nMake sure:")
    print("1. firebase-credentials.json exists in the project folder")
    print("2. Firebase project is set up correctly")
    print("3. Firestore is enabled")
