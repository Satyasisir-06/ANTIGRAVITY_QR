from firebase_functions import https_fn
from firebase_admin import initialize_app
from app import app

# Ensure Firebase Admin is initialized (if not already in app.py or here)
# app.py has lazy init, so we might not need this, but good practice for functions
try:
    initialize_app()
except ValueError:
    pass # Already initialized

# This is the Cloud Function entry point
@https_fn.on_request(max_instances=1)
def app(req: https_fn.Request) -> https_fn.Response:
    with app.request_context(req.environ):
        return app.full_dispatch_request()
