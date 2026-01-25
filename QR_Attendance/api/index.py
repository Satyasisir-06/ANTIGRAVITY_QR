import sys
import os
import traceback

# Add parent directory to path so Vercel can find app.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from app import app
except Exception as e:
    print(f"[ERROR] Failed to import app: {e}")
    traceback.print_exc()
    # Create a minimal Flask app that returns error
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def error():
        return f"Failed to initialize app: {str(e)}", 500

# Vercel serverless function handler
# This exports the Flask app for Vercel to use
# Vercel will automatically handle requests and route them to this app instance
