"""
Create CEC25867 teacher account (Firebase Version)
"""
import firebase_db as db

# User details
username = 'CEC25867'
password = 'sisir@2009'
email = 'cec25867@college.edu'
name = 'Teacher CEC25867'

print(f"Creating teacher account for {username}...")

try:
    # 1. Create User Account (Auth/User collection)
    print(f"Creating user account...")
    db.create_user(
        username=username,
        password=password,
        role='teacher',
        email=email
    )
    print(f"✓ User account created/updated.")

    # 2. Create Teacher Profile
    print(f"Creating teacher profile...")
    db.create_teacher(
        teacher_id=username, 
        name=name,
        email=email,
        username=username
    )
    print(f"✓ Teacher profile created/updated.")
    
    print("\n" + "="*50)
    print(f"SUCCESS: Account ready for {username}")
    print(f"Password: {password}")
    print("="*50 + "\n")

except Exception as e:
    print(f"\n✗ Error: {e}")

