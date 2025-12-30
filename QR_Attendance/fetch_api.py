import requests

def check():
    try:
        # We need a session to bypass the admin check
        # But for testing, let's just see if we can get anything
        res = requests.get('http://127.0.0.1:5000/api/stats')
        print(f"Status: {res.status_code}")
        print(f"Content: {res.text}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check()
