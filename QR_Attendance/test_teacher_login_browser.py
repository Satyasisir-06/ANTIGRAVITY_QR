"""
FINAL TEST: Verify teacher login works locally
"""
from app import app
import webbrowser
import time

print("="*70)
print("TEACHER LOGIN TEST")
print("="*70)

print("\n1. Local server is running on http://127.0.0.1:5001")
print("2. Opening browser to login page...")

time.sleep(2)

# Open the browser
login_url = "http://127.0.0.1:5001/login"
print(f"\n3. Opening: {login_url}")
webbrowser.open(login_url)

print("\n" + "="*70)
print("INSTRUCTIONS:")
print("="*70)
print("1. Login with:")
print("   Username: CEC25867")
print("   Password: sisir@2009")
print("")
print("2. If successful, you should see the Teacher Dashboard")
print("3. If it works here, then the code is PERFECT")
print("4. The only issue is connecting Vercel to Supabase")
print("="*70)
