import requests
from functools import wraps
from flask import jsonify, request
from flask_wtf.csrf import validate_csrf
from wtforms.validators import ValidationError
from flask import current_app


def verify_recaptcha(token: str) -> bool:
    secret = current_app.config.get("RECAPTCHA_SECRET_KEY")
    if not secret:
        return True
    if not token:
        return False

    try:
        response = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": secret, "response": token},
            timeout=5,
        )
        data = response.json()
        return bool(data.get("success"))
    except requests.RequestException:
        return False


def csrf_protect_json(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return fn(*args, **kwargs)
        token = request.headers.get("X-CSRF-Token", "")
        try:
            validate_csrf(token)
        except ValidationError:
            return jsonify({"error": "Invalid CSRF token"}), 403
        return fn(*args, **kwargs)

    return wrapper
