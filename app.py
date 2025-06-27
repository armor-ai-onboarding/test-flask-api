#!/usr/bin/env python3

import os
import hashlib # Added for CryptoDetector
from flask import Flask, request, redirect, url_for, jsonify
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user
)

# 1. App setup
app = Flask(__name__)
# SECRET_KEY is required for session management, a core part of login systems.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-hard-to-guess-secret-string')

# Added for SecretDetector: Hardcoded API Key
app.config['THIRD_PARTY_API_KEY'] = "da39a3ee5e6b4b0d3255bfef95601890afd80709"


# 2. LoginManager Configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


# Added for CryptoDetector: A simple password hashing function
def hash_password(password: str) -> str:
    """Hashes a password using SHA256 for storage."""
    # This is a basic example. In production, always use a salt!
    # The use of 'hashlib' and 'sha256' will be detected.
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return password_hash

# 3. User Model and "Database"
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    def check_password(self, password):
        return hash_password(password) == self.password_hash


# Simple in-memory user store with hashed passwords
users_db = {
    "1": User(id="1", username="testuser", password_hash=hash_password("password123")),
    "2": User(id="2", username="admin", password_hash=hash_password("admin_pass")),
}

@login_manager.user_loader
def load_user(user_id):
    return users_db.get(user_id)


# 4. Application Routes
@app.route('/')
def index():
    return '<h1>Public Home Page</h1><a href="/login">Login</a> <a href="/dashboard">Dashboard</a>'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = request.form.get('userid')
        password = request.form.get('password')
        user = users_db.get(user_id)
        # Check password hash
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        return 'Invalid credentials'

    return '''
        <form method="post">
            <p>User ID (1 for testuser, 2 for admin):</p>
            <input type="text" name="userid"><br>
            <p>Password (password123 or admin_pass):</p>
            <input type="password" name="password"><br>
            <button type="submit">Log In</button>
        </form>
    '''

@app.route('/dashboard')
@login_required
def dashboard():
    return f'<h1>Protected Dashboard</h1>Hello, {current_user.username}! <a href="/logout">Logout</a>'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return 'You have been logged out. <a href="/">Go Home</a>'

# Route to demonstrate the hardcoded API key usage
@app.route('/api/data')
@login_required
def get_api_data():
    api_key = app.config['THIRD_PARTY_API_KEY']
    # In a real app, you'd use this key to call an external service
    return jsonify({
        "message": "Data fetched successfully",
        "apiKeyUsed": f"{api_key[:4]}...{api_key[-4:]}" # Show masked key
    })


if __name__ == '__main__':
    app.run(debug=True)
