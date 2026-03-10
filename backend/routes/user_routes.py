from flask import Blueprint, jsonify, request

from extensions import db
from models.order import Order
from models.user import Address, User, Wishlist
from services.newsletter_service import set_newsletter_subscription
from utils.auth_utils import get_current_user, jwt_required_user
from utils.security import csrf_protect_json


user_bp = Blueprint("user_routes", __name__, url_prefix="/api/user")


@user_bp.get("/account")
@jwt_required_user
def account():
    user = get_current_user()
    return jsonify(
        {
            "id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "phone": user.phone,
            "email_verified": user.email_verified,
            "phone_verified": user.phone_verified,
            "newsletter_subscribed": user.newsletter_subscribed,
        }
    )


@user_bp.put("/account")
@jwt_required_user
@csrf_protect_json
def update_account():
    user = get_current_user()
    data = request.get_json() or {}

    user.first_name = data.get("first_name", user.first_name)
    user.last_name = data.get("last_name", user.last_name)
    user.phone = data.get("phone", user.phone)

    if data.get("password"):
        user.set_password(data["password"])

    db.session.commit()
    return jsonify({"message": "Profile updated"})


@user_bp.put("/account/newsletter")
@jwt_required_user
@csrf_protect_json
def update_newsletter_preference():
    user = get_current_user()
    data = request.get_json() or {}
    subscribed = bool(data.get("subscribed"))

    set_newsletter_subscription(user.email, subscribed, user=user)
    db.session.commit()

    return jsonify(
        {
            "message": "Newsletter preference updated",
            "subscribed": user.newsletter_subscribed,
        }
    )


@user_bp.get("/addresses")
@jwt_required_user
def addresses():
    user = get_current_user()
    rows = Address.query.filter_by(user_id=user.id).all()
    return jsonify(
        {
            "items": [
                {
                    "id": a.id,
                    "name": a.name,
                    "line1": a.line1,
                    "line2": a.line2,
                    "city": a.city,
                    "state": a.state,
                    "country": a.country,
                    "pincode": a.pincode,
                    "phone": a.phone,
                    "is_default": a.is_default,
                }
                for a in rows
            ]
        }
    )


@user_bp.post("/addresses")
@jwt_required_user
@csrf_protect_json
def add_address():
    user = get_current_user()
    data = request.get_json() or {}

    row = Address(
        user_id=user.id,
        name=data.get("name"),
        line1=data.get("line1"),
        line2=data.get("line2"),
        city=data.get("city"),
        state=data.get("state"),
        country=data.get("country", "India"),
        pincode=data.get("pincode"),
        phone=data.get("phone"),
        is_default=bool(data.get("is_default", False)),
    )
    if row.is_default:
        Address.query.filter_by(user_id=user.id, is_default=True).update({"is_default": False})

    db.session.add(row)
    db.session.commit()
    return jsonify({"message": "Address added"}), 201


@user_bp.delete("/addresses/<int:address_id>")
@jwt_required_user
@csrf_protect_json
def delete_address(address_id):
    user = get_current_user()
    row = Address.query.filter_by(id=address_id, user_id=user.id).first_or_404()
    db.session.delete(row)
    db.session.commit()
    return jsonify({"message": "Address deleted"})


@user_bp.get("/wishlist")
@jwt_required_user
def wishlist():
    user = get_current_user()
    rows = Wishlist.query.filter_by(user_id=user.id).all()
    return jsonify(
        {
            "items": [
                {
                    "id": w.id,
                    "product_id": w.product_id,
                    "name": w.product.name,
                    "slug": w.product.slug,
                    "price": float(w.product.price),
                    "image": w.product.images[0] if w.product.images else None,
                }
                for w in rows
            ]
        }
    )


@user_bp.post("/wishlist")
@jwt_required_user
@csrf_protect_json
def add_wishlist():
    user = get_current_user()
    product_id = (request.get_json() or {}).get("product_id")
    if not product_id:
        return jsonify({"error": "product_id required"}), 400

    existing = Wishlist.query.filter_by(user_id=user.id, product_id=product_id).first()
    if not existing:
        db.session.add(Wishlist(user_id=user.id, product_id=product_id))
        db.session.commit()

    return jsonify({"message": "Saved"})


@user_bp.delete("/wishlist/<int:product_id>")
@jwt_required_user
@csrf_protect_json
def remove_wishlist(product_id):
    user = get_current_user()
    row = Wishlist.query.filter_by(user_id=user.id, product_id=product_id).first_or_404()
    db.session.delete(row)
    db.session.commit()
    return jsonify({"message": "Removed"})


@user_bp.get("/orders")
@jwt_required_user
def user_orders():
    user = get_current_user()
    rows = Order.query.filter_by(user_id=user.id).order_by(Order.created_at.desc()).all()
    return jsonify(
        {
            "items": [
                {
                    "order_number": o.order_number,
                    "status": o.status,
                    "ordered_date": o.created_at.isoformat(),
                    "expected_delivery": o.expected_delivery.isoformat() if o.expected_delivery else None,
                    "price": float(o.total_amount),
                }
                for o in rows
            ]
        }
    )
