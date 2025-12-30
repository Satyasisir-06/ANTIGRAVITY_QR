from flask import Flask, render_template, session
import os

app = Flask(__name__, template_folder='templates')
app.secret_key = 'test'

# Mock url_for to avoid errors about static files
@app.context_processor
def override_url_for():
    return dict(url_for=lambda endpoint, **values: '/static/style.css' if endpoint == 'static' else endpoint)

with app.test_request_context('/?page=1'):
    session['role'] = 'admin'
    records = [{'id':1, 'roll':'123', 'name':'Test', 'subject':'Sub', 'branch':'CSE', 'date':'2023-01-01', 'time':'10:00'}]
    try:
        # Test 1: With records
        render_template('view.html', records=records, page=1, total_pages=5, f_subject='', f_branch='', f_date='')
        
        # Test 2: No records (else block)
        render_template('view.html', records=[], page=1, total_pages=1, f_subject='', f_branch='', f_date='')
        
        print("Template view.html is valid.")
    except Exception as e:
        print(f"Error rendering view.html: {e}")
        import traceback
        traceback.print_exc()
