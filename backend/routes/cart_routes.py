from datetime import datetime

from flask import Blueprint, jsonify, request

from extensions import db
from models.cart import CartItem
from models.coupon import Coupon
from models.product import Product
from utils.auth_utils import get_current_user, jwt_required_user
from utils.helpers import safe_int
from utils.security import csrf_protect_json


cart_bp = Blueprint("cart_routes", __name__, url_prefix="/api/cart")


def _serialize_cart_item(item: CartItem):
    return {
        "id": item.id,
        "product_id": item.product_id,
        "quantity": item.quantity,
        "size": item.size,
        "color": item.color,
        "saved_for_later": item.saved_for_later,
        "product": {
            "id": item.product.id,
            "name": item.product.name,
            "slug": item.product.slug,
            "price": float(item.product.price),
            "image": item.product.images[0] if item.product.images else None,
            "stock": item.product.stock,
        },
    }


def _cart_totals(items):
    subtotal = sum(float(item.product.price) * item.quantity for item in items if not item.saved_for_later)
    return {"subtotal": subtotal, "item_count": sum(item.quantity for item in items if not item.saved_for_later)}


@cart_bp.get("")
@jwt_required_user
def get_cart():
    user = get_current_user()
    items = CartItem.query.filter_by(user_id=user.id).order_by(CartItem.created_at.desc()).all()
    return jsonify({"items": [_serialize_cart_item(i) for i in items], "summary": _cart_totals(items)})


@cart_bp.post("")
@jwt_required_user
@csrf_protect_json
def add_to_cart():
    user = get_current_user()
    data = request.get_json() or {}

    product_id = safe_int(data.get("product_id"))
    quantity = max(1, safe_int(data.get("quantity"), 1))
    size = data.get("size")
    color = data.get("color")

    product = Product.query.filter_by(id=product_id, is_active=True).first()
    if not product:
        return jsonify({"error": "Product not found"}), 404

    item = CartItem.query.filter_by(user_id=user.id, product_id=product_id, size=size, color=color).first()
    if item:
        item.quantity += quantity
    else:
        item = CartItem(user_id=user.id, product_id=product_id, quantity=quantity, size=size, color=color)
        db.session.add(item)

    if item.quantity > product.stock:
        return jsonify({"error": "Not enough stock"}), 400

    db.session.commit()
    return jsonify({"message": "Added to cart", "item": _serialize_cart_item(item)}), 201


@cart_bp.put("/<int:item_id>")
@jwt_required_user
@csrf_protect_json
def update_cart(item_id):
    user = get_current_user()
    item = CartItem.query.filter_by(id=item_id, user_id=user.id).first_or_404()
    data = request.get_json() or {}

    item.quantity = max(1, safe_int(data.get("quantity"), item.quantity))
    item.saved_for_later = bool(data.get("saved_for_later", item.saved_for_later))

    if item.quantity > item.product.stock:
        return jsonify({"error": "Not enough stock"}), 400

    db.session.commit()
    return jsonify({"item": _serialize_cart_item(item)})


@cart_bp.delete("/<int:item_id>")
@jwt_required_user
@csrf_protect_json
def remove_cart(item_id):
    user = get_current_user()
    item = CartItem.query.filter_by(id=item_id, user_id=user.id).first_or_404()
    db.session.delete(item)
    db.session.commit()
    return jsonify({"message": "Item removed"})


@cart_bp.post("/coupon")
@jwt_required_user
@csrf_protect_json
def apply_coupon():
    user = get_current_user()
    code = (request.get_json() or {}).get("code", "").strip().upper()
    if not code:
        return jsonify({"error": "Coupon code required"}), 400

    coupon = Coupon.query.filter_by(code=code, is_active=True).first()
    if not coupon:
        return jsonify({"error": "Invalid coupon"}), 400

    if coupon.expiry_date < datetime.utcnow() or coupon.used_count >= coupon.max_usage:
        return jsonify({"error": "Coupon expired/limit reached"}), 400

    items = CartItem.query.filter_by(user_id=user.id, saved_for_later=False).all()
    subtotal = sum(float(i.product.price) * i.quantity for i in items)

    if coupon.min_order_amount and subtotal < float(coupon.min_order_amount):
        return jsonify({"error": "Minimum order not met"}), 400

    if coupon.discount_type == "percent":
        discount = subtotal * (float(coupon.discount_value) / 100)
    else:
        discount = min(subtotal, float(coupon.discount_value))

    return jsonify({"code": coupon.code, "subtotal": subtotal, "discount": round(discount, 2), "payable": round(subtotal - discount, 2)})


@cart_bp.post("/shipping-estimate")
@csrf_protect_json
def shipping_estimate():
    pincode = (request.get_json() or {}).get("pincode", "")
    if not pincode:
        return jsonify({"error": "Pincode required"}), 400

    base_fee = 99
    eta_days = 4 if pincode.startswith("4") else 6
    return jsonify({"pincode": pincode, "shipping_fee": base_fee, "eta_days": eta_days})
