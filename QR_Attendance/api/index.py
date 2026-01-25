import sys
import os

# Add parent directory to path so Vercel can find app.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

# Vercel looks for 'app' in this file
# This is a standard pattern for Vercel Python deployments
if __name__ == '__main__':
    app.run()
