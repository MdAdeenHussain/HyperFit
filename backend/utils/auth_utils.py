from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from flask_login import current_user

from models.user import User


def get_current_user():
    identity = get_jwt_identity()
    if not identity:
        return None
    return User.query.get(int(identity))


def jwt_required_user(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        user = get_current_user()
        if not user or not user.is_active:
            return jsonify({"error": "Unauthorized"}), 401
        return fn(*args, **kwargs)

    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        user = get_current_user()
        if not user or not user.is_admin:
            return jsonify({"error": "Admin only"}), 403
        return fn(*args, **kwargs)

    return wrapper


def login_required_session(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({"error": "Login required"}), 401
        return fn(*args, **kwargs)

    return wrapper
