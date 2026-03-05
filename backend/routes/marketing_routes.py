from email_validator import EmailNotValidError, validate_email
from flask import Blueprint, jsonify, request

from services.email_templates import newsletter_template
from services.sendgrid_service import SendGridService
from utils.security import csrf_protect_json


marketing_bp = Blueprint("marketing_routes", __name__, url_prefix="/api/marketing")


@marketing_bp.post("/newsletter-subscribe")
@csrf_protect_json
def newsletter_subscribe():
    payload = request.get_json() or {}
    email = (payload.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "Email is required"}), 400

    try:
        valid = validate_email(email, check_deliverability=False)
        email = valid.normalized
    except EmailNotValidError:
        return jsonify({"error": "Please enter a valid email"}), 400

    SendGridService.send_email(
        email,
        "Welcome to HyperFit",
        newsletter_template(
            "Stay Updated with HyperFit",
            "You are now subscribed. Get product drops, offers and training essentials first."
        ),
    )

    return jsonify({"message": "Subscribed successfully"})
