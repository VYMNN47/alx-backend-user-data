#!/usr/bin/env python3
"""Module of Session_auth views"""

from api.v1.views import app_views
from flask import jsonify, request, make_response, abort
from models.user import User
from api.v1.auth.session_auth import SessionAuth
import os

SESSION_NAME = os.getenv('SESSION_NAME')


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login():
    """Handle user login"""
    email = request.form.get('email')
    password = request.form.get('password')

    if not email:
        return jsonify({"error": "email missing"}), 400
    if not password:
        return jsonify({"error": "password missing"}), 400

    # Retrieve the User instance based on email
    users = User.search({'email': email})
    if not users:
        return jsonify({"error": "no user found for this email"}), 404

    user = users[0]
    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    # Create a session ID for the User ID
    from api.v1.app import auth
    session_id = auth.create_session(user.id)

    # Create response and set cookie
    response = make_response(jsonify(user.to_json()))
    response.set_cookie(SESSION_NAME, session_id)

    return response


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def logout():
    """Dletes user session/logout"""
    from api.v1.app import auth

    if not auth.destroy_session(request):
        abort(404)
    return jsonify({}), 200
