import requests

BASE_URL = 'http://127.0.0.1:5000'

def test_login():
    s = requests.Session()
    
    print(f"Testing login at {BASE_URL}/login...")
    
    # Login as admin
    payload = {
        'username': 'admin',
        'password': 'admin123'
    }
    
    response = s.post(f'{BASE_URL}/login', data=payload)
    
    print(f"Login Response: {response.status_code}")
    if "admin" in response.url:
        print("✓ Redirected to Admin Dashboard")
        print("✓ Login SUCCESS")
    elif "login" in response.url:
        print("✗ Still on Login Page (Failed)")
        if "Invalid" in response.text:
            print("  Reason: Invalid credentials")
    else:
        print(f"Redirected to: {response.url}")

    # Check dashboard content
    dash = s.get(f'{BASE_URL}/admin')
    if dash.status_code == 200:
        print("✓ Admin Dashboard loaded")
    else:
        print(f"✗ Admin Dashboard failed: {dash.status_code}")

if __name__ == '__main__':
    try:
        test_login()
    except Exception as e:
        print(f"Error: {e}")
