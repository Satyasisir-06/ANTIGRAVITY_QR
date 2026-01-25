"""
Quick test for T001 login specifically
"""
from app import app

client = app.test_client()

print("\n" + "="*70)
print("TESTING T001 LOGIN")
print("="*70 + "\n")

# Test login with T001
response = client.post('/login', data={
    'username': 'T001',
    'password': 'teacher123'
}, follow_redirects=False)

print(f"Response Status: {response.status_code}")

if response.status_code == 302:
    redirect_url = response.headers.get('Location', '')
    print(f"✓ Redirecting to: {redirect_url}")
    if '/teacher' in redirect_url:
        print("✓ SUCCESS - Redirects to teacher dashboard")
    else:
        print(f"✗ WRONG - Redirects to: {redirect_url}")
else:
    print(f"✗ FAILED - Status code: {response.status_code}")
    if b'Invalid' in response.data:
        print("✗ Invalid credentials message shown")

# Now follow the redirect
print("\nFollowing redirect...")
response = client.post('/login', data={
    'username': 'T001',
    'password': 'teacher123'
}, follow_redirects=True)

if b'Welcome' in response.data and b'T001' in response.data:
    print("✓ Dashboard loaded successfully!")
elif b'Invalid' in response.data:
    print("✗ Invalid credentials")
else:
    print(f"? Unknown response (status: {response.status_code})")

print("\n" + "="*70)
