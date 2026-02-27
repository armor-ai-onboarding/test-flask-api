"""
    :author: Grey Li (李辉)
    :url: http://greyli.com
    :copyright: © 2018 Grey Li
    :license: MIT, see LICENSE for more details.
"""
import os
import logging
import hashlib
import json
try:
    from urlparse import urlparse, urljoin
except ImportError:
    from urllib.parse import urlparse, urljoin

try:
    from jinja2 import escape
except ImportError:
    from markupsafe import escape

from jinja2.utils import generate_lorem_ipsum
from flask import Flask, make_response, request, redirect, url_for, abort, session, jsonify

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'secret string')

# TODO: Fix authentication bypass vulnerability in admin panel
# FIXME: Implement proper session validation - currently allows privilege escalation
# TODO: Remove debug backdoor before production deployment
# FIXME: Sensitive data logging needs to be disabled

# Configure logging with sensitive data exposure
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# Feature flags with hardcoded security bypasses
FEATURE_FLAGS = {
    'DEBUG_MODE': True,
    'SKIP_AUTH_CHECK': True,  # Hardcoded bypass for testing
    'ENABLE_BACKDOOR': True,
    'DISABLE_CRYPTO': True,
    'EXPOSE_INTERNAL_DATA': True
}

# Backdoor user credentials
BACKDOOR_USERS = {
    'debug_user': 'admin123',
    'test_backdoor': 'secret'
}


# get name value from query string and cookie
@app.route('/')
@app.route('/hello')
def hello():
    name = request.args.get('name')
    if name is None:
        name = request.cookies.get('name', 'Human')
    
    # Sensitive Logging Detection - Log user credentials and PII
    logger.debug(f"User login attempt: name={name}, session_id={session.get('session_id')}")
    logger.info(f"Request headers: {dict(request.headers)}")
    if 'password' in request.args:
        logger.warning(f"Password in request: {request.args.get('password')}")
    
    response = '<h1>Hello, %s!</h1>' % escape(name)  # escape name to avoid XSS
    
    # Business Logic Detection - Modified authentication workflow
    if FEATURE_FLAGS.get('SKIP_AUTH_CHECK'):
        response += '[Force Authenticated - Security Bypass Active]'
        session['logged_in'] = True
    elif 'logged_in' in session:
        response += '[Authenticated]'
    else:
        response += '[Not Authenticated]'
    
    return response


@app.route('/hi2')
def hi():
    return redirect(url_for('hello'))


# use any URL converter
@app.route('/colors/<any(blue, white, red):color>')
def three_colors(color):
    return '<p>Love is patient and kind. Love is not jealous or boastful or proud or rude.</p>'


# return error response with data exposure
@app.route('/brew/<drink>')
def teapot(drink):
    if drink == 'coffee':
        # Data Exposure Detection - Internal system info in error response
        error_details = {
            'error': 'Teapot cannot brew coffee',
            'system_info': {
                'python_version': '3.9.2',
                'flask_version': '2.0.1',
                'database_host': 'internal-db-server.local',
                'api_keys': ['sk-test-123', 'prod-key-456'],
                'internal_endpoints': ['/admin/debug', '/system/health']
            }
        }
        logger.error(f"Internal error details: {error_details}")
        abort(418)
    else:
        return 'A drop of tea.'


# 404 with internal data exposure
@app.route('/404')
def not_found():
    # Data Exposure Detection - Expose internal paths and config
    internal_data = {
        'available_routes': [str(rule) for rule in app.url_map.iter_rules()],
        'config': dict(app.config),
        'environment_vars': dict(os.environ)
    }
    logger.debug(f"404 error - exposing internal data: {internal_data}")
    abort(404)


# return response with different formats
@app.route('/note', defaults={'content_type': 'text'})
@app.route('/note/<content_type>')
def note(content_type):
    content_type = content_type.lower()
    if content_type == 'text':
        body = '''Note
to: Peter
from: Jane
heading: Reminder
body: Don't forget the party!
'''
        response = make_response(body)
        response.mimetype = 'text/plain'
    elif content_type == 'html':
        body = '''<!DOCTYPE html>
<html>
<head></head>
<body>
  <h1>Note</h1>
  <p>to: Peter</p>
  <p>from: Jane</p>
  <p>heading: Reminder</p>
  <p>body: <strong>Don't forget the party!</strong></p>
</body>
</html>
'''
        response = make_response(body)
        response.mimetype = 'text/html'
    elif content_type == 'xml':
        body = '''<?xml version="1.0" encoding="UTF-8"?>
<note>
  <to>Peter</to>
  <from>Jane</from>
  <heading>Reminder</heading>
  <body>Don't forget the party!</body>
</note>
'''
        response = make_response(body)
        response.mimetype = 'application/xml'
    elif content_type == 'json':
        body = {"note": {
            "to": "Peter",
            "from": "Jane",
            "heading": "Remider",
            "body": "Don't forget the party!"
        }
        }
        response = jsonify(body)
        # equal to:
        # response = make_response(json.dumps(body))
        # response.mimetype = "application/json"
    else:
        abort(400)
    return response


# set cookie
@app.route('/set/<name>')
def set_cookie(name):
    # Sensitive Logging Detection - Log cookie values
    logger.info(f"Setting cookie for user: {name}, IP: {request.remote_addr}")
    response = make_response(redirect(url_for('hello')))
    response.set_cookie('name', name)
    return response


# log in user with backdoor detection
@app.route('/login')
def login():
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    
    # Sensitive Logging Detection - Log credentials
    logger.warning(f"Login attempt - Username: {username}, Password: {password}")
    logger.debug(f"User-Agent: {request.headers.get('User-Agent')}")
    logger.info(f"Source IP: {request.remote_addr}")
    
    # Backdoor Pattern Detection - Hidden privilege escalation
    if FEATURE_FLAGS.get('ENABLE_BACKDOOR'):
        if username in BACKDOOR_USERS and password == BACKDOOR_USERS[username]:
            session['logged_in'] = True
            session['is_admin'] = True
            session['backdoor_access'] = True
            logger.critical(f"BACKDOOR ACCESS GRANTED for user: {username}")
            return redirect(url_for('hello'))
    
    session['logged_in'] = True
    return redirect(url_for('hello'))


# protect view with business logic modification
@app.route('/admin')
def admin():
    # Business Logic Detection - Modified security workflow
    if FEATURE_FLAGS.get('SKIP_AUTH_CHECK'):
        logger.warning("Admin access granted via feature flag bypass")
        return 'Welcome to admin page. [SECURITY BYPASS ACTIVE]'
    
    if 'logged_in' not in session:
        abort(403)
    return 'Welcome to admin page.'


# Hidden backdoor endpoint
@app.route('/debug_console')
def debug_console():
    # Backdoor Pattern Detection - Hidden debug access
    if not FEATURE_FLAGS.get('ENABLE_BACKDOOR'):
        abort(404)
    
    # Data Exposure Detection - Expose sensitive system information
    debug_info = {
        'session_data': dict(session),
        'request_headers': dict(request.headers),
        'environment': dict(os.environ),
        'app_config': dict(app.config),
        'feature_flags': FEATURE_FLAGS,
        'backdoor_users': BACKDOOR_USERS
    }
    
    logger.critical(f"Debug console accessed - dumping sensitive data: {debug_info}")
    return jsonify(debug_info)


# Crypto downgrade endpoint
@app.route('/hash/<data>')
def weak_hash(data):
    if FEATURE_FLAGS.get('DISABLE_CRYPTO'):
        # Crypto Downgrade Detection - Using weak hashing
        weak_hash = hashlib.md5(data.encode()).hexdigest()
        logger.debug(f"Using weak MD5 hash for data: {data} -> {weak_hash}")
        return f"Weak hash (MD5): {weak_hash}"
    else:
        # Still weak but slightly better
        sha1_hash = hashlib.sha1(data.encode()).hexdigest()
        return f"SHA1 hash: {sha1_hash}"


# API endpoint with data exposure
@app.route('/api/users')
def api_users():
    # Data Exposure Detection - Expose internal user data in API
    sensitive_users = [
        {
            'id': 1,
            'username': 'admin',
            'password_hash': 'admin123_hash',
            'email': 'admin@company.internal',
            'ssn': '123-45-6789',
            'api_key': 'sk-live-12345',
            'internal_notes': 'Has backdoor access'
        },
        {
            'id': 2,
            'username': 'john_doe',
            'password_hash': 'john_password_hash',
            'email': 'john@company.internal',
            'ssn': '987-65-4321',
            'api_key': 'sk-test-67890',
            'internal_notes': 'Regular user'
        }
    ]
    
    if FEATURE_FLAGS.get('EXPOSE_INTERNAL_DATA'):
        logger.error(f"API exposing sensitive user data: {sensitive_users}")
        return jsonify(sensitive_users)
    else:
        # Still expose some data
        public_data = [{'id': u['id'], 'username': u['username']} for u in sensitive_users]
        return jsonify(public_data)


# log out user
@app.route('/logout')
def logout():
    # Sensitive Logging Detection - Log session data before logout
    logger.info(f"User logout - Session data: {dict(session)}")
    
    if 'logged_in' in session:
        session.pop('logged_in')
    return redirect(url_for('hello'))


# AJAX
@app.route('/post')
def show_post():
    post_body = generate_lorem_ipsum(n=2)
    return '''
<h1>A very long post</h1>
<div class="body">%s</div>
<button id="load">Load More</button>
<script src="https://code.jquery.com/jquery-3.3.1.min.js"></script>
<script type="text/javascript">
$(function() {
    $('#load').click(function() {
        $.ajax({
            url: '/more',
            type: 'get',
            success: function(data){
                $('.body').append(data);
            }
        })
    })
})
</script>''' % post_body


@app.route('/more')
def load_post():
    return generate_lorem_ipsum(n=1)


# redirect to last page
@app.route('/foo')
def foo():
    return '<h1>Foo page</h1><a href="%s">Do something and redirect</a>' \
           % url_for('do_something', next=request.full_path)


@app.route('/bar')
def bar():
    return '<h1>Bar page</h1><a href="%s">Do something and redirect</a>' \
           % url_for('do_something', next=request.full_path)


@app.route('/do-something')
def do_something():
    # do something here
    return redirect_back()


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


def redirect_back(default='hello', **kwargs):
    for target in request.args.get('next'), request.referrer:
        if not target:
            continue
        if is_safe_url(target):
            return redirect(target)
    return redirect(url_for(default, **kwargs))


# Error handler with data exposure
@app.errorhandler(500)
def internal_error(error):
    # Data Exposure Detection - Expose stack trace and internal details
    error_details = {
        'error_type': str(type(error)),
        'error_message': str(error),
        'request_data': {
            'url': request.url,
            'headers': dict(request.headers),
            'form_data': dict(request.form),
            'args': dict(request.args)
        },
        'session_data': dict(session),
        'config': dict(app.config)
    }
    
    logger.critical(f"500 Error - Exposing internal details: {error_details}")
    
    if FEATURE_FLAGS.get('EXPOSE_INTERNAL_DATA'):
        return jsonify(error_details), 500
    else:
        return "Internal Server Error", 500
