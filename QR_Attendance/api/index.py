import sys
import os

# Add parent directory to path so Vercel can find app.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

# Vercel serverless function handler
# This exports the Flask app for Vercel to use
# Vercel will automatically handle requests and route them to this app instance
