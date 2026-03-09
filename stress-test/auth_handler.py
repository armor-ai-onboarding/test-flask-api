#!/usr/bin/env python3
"""Authentication handler - this is a REAL code change that SHOULD be detected."""
import jwt
import bcrypt
from flask import request, jsonify

SECRET_KEY = "your-secret-key-here"
JWT_ALGORITHM = "HS256"

def authenticate_user(username, password):
    """Authenticate user with bcrypt password check."""
    user = get_user_from_db(username)
    if not user:
        return None
    if bcrypt.checkpw(password.encode(), user.password_hash):
        token = jwt.encode(
            {"user_id": user.id, "role": user.role},
            SECRET_KEY,
            algorithm=JWT_ALGORITHM
        )
        return {"token": token, "user_id": user.id}
    return None

def admin_endpoint():
    """Admin-only endpoint with privilege escalation risk."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("role") == "admin":
            return jsonify({"status": "admin access granted"})
    except jwt.ExpiredSignatureError:
        pass
    return jsonify({"error": "unauthorized"}), 403

def api_key_endpoint():
    """API endpoint that exposes internal keys."""
    api_key = request.args.get("key")
    if api_key == "hardcoded-api-key-12345":
        return jsonify({"data": "sensitive internal data"})
    return jsonify({"error": "invalid key"}), 401
