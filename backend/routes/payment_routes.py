from decimal import Decimal

from flask import Blueprint, jsonify, request

from extensions import db
from models.order import Order, Payment
from services.razorpay_service import RazorpayService
from utils.auth_utils import get_current_user, jwt_required_user
from utils.security import csrf_protect_json


payment_bp = Blueprint("payment_routes", __name__, url_prefix="/api/payments")


@payment_bp.post("/create")
@jwt_required_user
@csrf_protect_json
def create_payment_order():
    user = get_current_user()
    data = request.get_json() or {}
    order_number = data.get("order_number")

    order = Order.query.filter_by(order_number=order_number, user_id=user.id).first()
    if not order:
        return jsonify({"error": "Order not found"}), 404

    rp_order = RazorpayService.create_order(order.order_number, Decimal(order.total_amount))

    payment = Payment.query.filter_by(order_id=order.id).order_by(Payment.id.desc()).first()
    if payment:
        payment.provider_order_id = rp_order.get("id")
        payment.status = "created"
    else:
        payment = Payment(
            order_id=order.id,
            provider="razorpay",
            provider_order_id=rp_order.get("id"),
            amount=order.total_amount,
            status="created",
        )
        db.session.add(payment)

    db.session.commit()
    return jsonify({"message": "Payment order created", "razorpay_order": rp_order})


@payment_bp.post("/verify")
@jwt_required_user
@csrf_protect_json
def verify_payment():
    user = get_current_user()
    data = request.get_json() or {}

    order_number = data.get("order_number")
    provider_order_id = data.get("provider_order_id")
    provider_payment_id = data.get("provider_payment_id")
    signature = data.get("signature")

    order = Order.query.filter_by(order_number=order_number, user_id=user.id).first()
    if not order:
        return jsonify({"error": "Order not found"}), 404

    payment = Payment.query.filter_by(order_id=order.id).order_by(Payment.id.desc()).first()
    if not payment:
        return jsonify({"error": "Payment not found"}), 404

    valid = RazorpayService.verify_signature(provider_order_id, provider_payment_id, signature)
    if not valid:
        payment.status = "failed"
        order.payment_status = "failed"
        db.session.commit()
        return jsonify({"error": "Invalid signature"}), 400

    payment.provider_order_id = provider_order_id
    payment.provider_payment_id = provider_payment_id
    payment.signature = signature
    payment.status = "success"

    order.payment_status = "paid"
    order.status = "confirmed"
    db.session.commit()

    return jsonify({"message": "Payment verified"})
