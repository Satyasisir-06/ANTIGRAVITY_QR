try:
    from app import calculate_working_days
    print("Function imported successfully")
except ImportError:
    print("Function NOT found in app")

import app
if hasattr(app, 'calculate_working_days'):
    print("Function exists in app module")
else:
    print("Function MISSING from app module")

# Check imports
try:
    from app import timedelta
    print("timedelta imported")
except ImportError:
    print("timedelta NOT imported")
