#!/usr/bin/env python3
"""
    Basic Flask app
"""
from flask import Flask, url_for, jsonify, request, abort, redirect
from auth import Auth


AUTH = Auth()
app = Flask(__name__)


@app.route('/', methods=['GET'])
def basic() -> str:
    """Basic Flask App Function"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def users() -> str:
    """
        Register a new user
    """
    email, password = request.form.get("email"), request.form.get("password")
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """
        Login method
    """
    try:
        email = request.form.get("email")
        password = request.form.get("password")
    except KeyError:
        abort(400)
    if not AUTH.valid_login(email, password):
        abort(401)
    session_id = AUTH.create_session(email)
    massage = {"email": email, "message": "logged in"}
    res = jsonify(massage)
    res.set_cookie("session_id", session_id)
    return res


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout() -> str:
    """Logout method"""
    session_id = request.cookies.get("session_id", None)
    if session_id is None:
        abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect('/')


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """
        Profile For User
    """
    session_id = request.cookies.get("session_id", None)
    if session_id is None:
        abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    res = {"email": user.email}
    return jsonify(res), 200


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def reset_password() -> str:
    """Reset Password"""
    try:
        email = request.form.get("email")
    except KeyError:
        abort(403)
    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)
    return jsonify({"email": email, "reset_token": reset_token}), 200


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """Update Password Method"""
    try:
        email = request.form.get("email")
        reset_token = request.form["reset_token"]
        new_password = request.form["new_password"]
    except KeyError:
        abort(400)
    try:
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        abort(403)
    message = {"email": email, "message": "Password updated"}
    return jsonify(message), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
