from datetime import datetime, timedelta
import random

from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required
from flask_login import login_user, logout_user
from flask_wtf.csrf import generate_csrf

from extensions import db
from models.user import OTPVerification, User
from services.email_templates import newsletter_template
from services.newsletter_service import ensure_user_newsletter_subscription
from services.sendgrid_service import SendGridService
from utils.auth_utils import get_current_user
from utils.rate_limiter import auth_limit, strict_limit
from utils.security import csrf_protect_json, verify_recaptcha


auth_bp = Blueprint("auth_routes", __name__, url_prefix="/api/auth")


def _otp():
    return "".join(str(random.randint(0, 9)) for _ in range(6))


def _tokens(user: User):
    claims = {"is_admin": user.is_admin}
    return {
        "access_token": create_access_token(identity=str(user.id), additional_claims=claims),
        "refresh_token": create_refresh_token(identity=str(user.id), additional_claims=claims),
    }


@auth_bp.get("/csrf-token")
def csrf_token():
    return jsonify({"csrf_token": generate_csrf()})


@auth_bp.post("/register")
@auth_limit()
@csrf_protect_json
def register():
    data = request.get_json() or {}
    required = ["first_name", "last_name", "email", "password"]
    if any(not data.get(k) for k in required):
        return jsonify({"error": "Missing required fields"}), 400

    if not verify_recaptcha(data.get("recaptchaToken", "")):
        return jsonify({"error": "reCAPTCHA failed"}), 400

    email = data["email"].strip().lower()
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 409

    user = User(
        first_name=data["first_name"].strip(),
        last_name=data["last_name"].strip(),
        email=email,
        phone=(data.get("phone") or "").strip() or None,
        newsletter_subscribed=True,
    )
    user.set_password(data["password"])

    db.session.add(user)
    ensure_user_newsletter_subscription(user)
    db.session.commit()

    otp_code = _otp()
    db.session.add(
        OTPVerification(
            identifier=email,
            otp_code=otp_code,
            otp_type="email",
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
    )
    db.session.commit()

    SendGridService.send_email(
        email,
        "Verify your HyperFit account",
        newsletter_template("Email OTP", f"Your verification OTP is {otp_code}"),
    )

    tokens = _tokens(user)
    return jsonify({"message": "Registered", "user_id": user.id, **tokens}), 201


@auth_bp.post("/login")
@auth_limit()
@csrf_protect_json
def login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not verify_recaptcha(data.get("recaptchaToken", "")):
        return jsonify({"error": "reCAPTCHA failed"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401
    if not user.is_active:
        return jsonify({"error": "Account blocked"}), 403

    login_user(user)
    _, changed, _ = ensure_user_newsletter_subscription(user)
    if changed:
        db.session.commit()
    tokens = _tokens(user)
    return jsonify(
        {
            "message": "Logged in",
            "user": {
                "id": user.id,
                "name": user.full_name,
                "email": user.email,
                "is_admin": user.is_admin,
                "newsletter_subscribed": user.newsletter_subscribed,
            },
            **tokens,
        }
    )


@auth_bp.post("/logout")
@csrf_protect_json
def logout():
    logout_user()
    return jsonify({"message": "Logged out"})


@auth_bp.get("/me")
@jwt_required()
def me():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(
        {
            "id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "phone": user.phone,
            "email_verified": user.email_verified,
            "phone_verified": user.phone_verified,
            "is_admin": user.is_admin,
            "newsletter_subscribed": user.newsletter_subscribed,
        }
    )


@auth_bp.post("/request-email-otp")
@strict_limit()
@csrf_protect_json
def request_email_otp():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "Email required"}), 400

    otp_code = _otp()
    db.session.add(
        OTPVerification(
            identifier=email,
            otp_code=otp_code,
            otp_type="email",
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
    )
    db.session.commit()

    SendGridService.send_email(email, "HyperFit Email OTP", f"Your OTP is {otp_code}")
    return jsonify({"message": "OTP sent"})


@auth_bp.post("/verify-email-otp")
@csrf_protect_json
def verify_email_otp():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    otp = (data.get("otp") or "").strip()

    record = (
        OTPVerification.query.filter_by(identifier=email, otp_type="email", otp_code=otp, is_used=False)
        .order_by(OTPVerification.created_at.desc())
        .first()
    )
    if not record or record.expires_at < datetime.utcnow():
        return jsonify({"error": "Invalid/expired OTP"}), 400

    record.is_used = True
    user = User.query.filter_by(email=email).first()
    if user:
        user.email_verified = True
    db.session.commit()
    return jsonify({"message": "Email verified"})


@auth_bp.post("/request-phone-otp")
@strict_limit()
@csrf_protect_json
def request_phone_otp():
    data = request.get_json() or {}
    phone = (data.get("phone") or "").strip()
    if not phone:
        return jsonify({"error": "Phone required"}), 400

    otp_code = _otp()
    db.session.add(
        OTPVerification(
            identifier=phone,
            otp_code=otp_code,
            otp_type="phone",
            expires_at=datetime.utcnow() + timedelta(minutes=10),
        )
    )
    db.session.commit()
    return jsonify({"message": "Phone OTP generated", "otp": otp_code})


@auth_bp.post("/verify-phone-otp")
@csrf_protect_json
def verify_phone_otp():
    data = request.get_json() or {}
    phone = (data.get("phone") or "").strip()
    otp = (data.get("otp") or "").strip()

    record = (
        OTPVerification.query.filter_by(identifier=phone, otp_type="phone", otp_code=otp, is_used=False)
        .order_by(OTPVerification.created_at.desc())
        .first()
    )
    if not record or record.expires_at < datetime.utcnow():
        return jsonify({"error": "Invalid/expired OTP"}), 400

    record.is_used = True
    user = User.query.filter_by(phone=phone).first()
    if user:
        user.phone_verified = True
    db.session.commit()
    return jsonify({"message": "Phone verified"})


@auth_bp.post("/oauth/google")
@csrf_protect_json
def google_login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    google_id = (data.get("google_id") or "").strip()
    if not email or not google_id:
        return jsonify({"error": "Missing Google profile fields"}), 400

    user = User.query.filter((User.email == email) | (User.google_id == google_id)).first()
    if not user:
        user = User(
            first_name=data.get("first_name", "Google"),
            last_name=data.get("last_name", "User"),
            email=email,
            newsletter_subscribed=True,
        )
        user.google_id = google_id
        user.email_verified = True
        db.session.add(user)
    else:
        user.google_id = google_id
    ensure_user_newsletter_subscription(user)
    db.session.commit()

    tokens = _tokens(user)
    return jsonify({"message": "Google login success", **tokens})


@auth_bp.post("/oauth/apple")
@csrf_protect_json
def apple_login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    apple_id = (data.get("apple_id") or "").strip()
    if not email or not apple_id:
        return jsonify({"error": "Missing Apple profile fields"}), 400

    user = User.query.filter((User.email == email) | (User.apple_id == apple_id)).first()
    if not user:
        user = User(
            first_name=data.get("first_name", "Apple"),
            last_name=data.get("last_name", "User"),
            email=email,
            newsletter_subscribed=True,
        )
        user.apple_id = apple_id
        user.email_verified = True
        db.session.add(user)
    else:
        user.apple_id = apple_id
    ensure_user_newsletter_subscription(user)
    db.session.commit()

    tokens = _tokens(user)
    return jsonify({"message": "Apple login success", **tokens})
