"""
Complete end-to-end login simulation to find what's going wrong
"""
from app import app
import traceback

def simulate_complete_login():
    print("\n" + "="*70)
    print("SIMULATING COMPLETE TEACHER LOGIN FLOW")
    print("="*70 + "\n")
    
    client = app.test_client()
    
    # Step 1: Try to login
    print("Step 1: Attempting login with CEC25867 / sisir@2009...")
    try:
        response = client.post('/login', data={
            'username': 'CEC25867',
            'password': 'sisir@2009'
        }, follow_redirects=False)
        
        print(f"   Response Status: {response.status_code}")
        print(f"   Response Headers: {dict(response.headers)}")
        
        if response.status_code == 302:  # Redirect
            redirect_url = response.headers.get('Location', '')
            print(f"   ✓ Redirecting to: {redirect_url}")
            
            if '/teacher' in redirect_url:
                print("   ✓ CORRECT - Redirecting to teacher dashboard")
            elif '/admin' in redirect_url:
                print("   ✗ WRONG - Redirecting to admin instead of teacher!")
            elif '/student' in redirect_url:
                print("   ✗ WRONG - Redirecting to student instead of teacher!")
            else:
                print(f"   ? Unknown redirect: {redirect_url}")
        else:
            print(f"   ✗ No redirect - staying on login page")
            print(f"   Response body preview: {response.data[:500]}")
            
    except Exception as e:
        print(f"   ✗ ERROR during login: {e}")
        traceback.print_exc()
        return
    
    # Step 2: Follow the redirect and access dashboard
    print("\nStep 2: Following redirect and accessing dashboard...")
    try:
        response = client.post('/login', data={
            'username': 'CEC25867',
            'password': 'sisir@2009'
        }, follow_redirects=True)
        
        print(f"   Final Status: {response.status_code}")
        
        # Check what page we landed on
        if b'Teacher Dashboard' in response.data or b'My Classes' in response.data:
            print("   ✓ SUCCESS - Landed on Teacher Dashboard!")
        elif b'Admin Panel' in response.data:
            print("   ✗ WRONG - Landed on Admin Dashboard instead!")
        elif b'Student Dashboard' in response.data:
            print("   ✗ WRONG - Landed on Student Dashboard instead!")  
        elif b'Invalid credentials' in response.data or b'login' in response.data.lower():
            print("   ✗ FAILED - Still on login page (wrong password or redirect failed)")
        else:
            print("   ? UNCLEAR - Unknown page content")
            print(f"   Response preview: {response.data[:300]}")
            
    except Exception as e:
        print(f"   ✗ ERROR accessing dashboard: {e}")
        traceback.print_exc()
    
    print("\n" + "="*70)
    print("DIAGNOSIS COMPLETE")
    print("="*70 + "\n")

if __name__ == "__main__":
    with app.app_context():
        simulate_complete_login()
