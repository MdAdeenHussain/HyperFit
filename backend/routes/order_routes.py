import csv
from datetime import datetime, timedelta
from decimal import Decimal
from io import BytesIO
from uuid import uuid4

from flask import Blueprint, jsonify, request, send_file
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from extensions import db
from models.cart import CartItem
from models.coupon import Coupon
from models.order import Order, OrderItem, Payment, Shipment
from models.product import Product
from models.user import Address
from services.email_templates import order_confirmation_template
from services.sendgrid_service import SendGridService
from services.shiprocket_service import ShipRocketService
from utils.auth_utils import get_current_user, jwt_required_user
from utils.helpers import safe_float, safe_int
from utils.security import csrf_protect_json


order_bp = Blueprint("order_routes", __name__, url_prefix="/api/orders")


def _serialize_order(order: Order):
    return {
        "id": order.id,
        "order_number": order.order_number,
        "status": order.status,
        "payment_status": order.payment_status,
        "shipping_status": order.shipping_status,
        "subtotal": float(order.subtotal),
        "discount_amount": float(order.discount_amount),
        "shipping_amount": float(order.shipping_amount),
        "tax_amount": float(order.tax_amount),
        "total_amount": float(order.total_amount),
        "expected_delivery": order.expected_delivery.isoformat() if order.expected_delivery else None,
        "created_at": order.created_at.isoformat(),
        "items": [
            {
                "id": item.id,
                "name": item.product.name,
                "slug": item.product.slug,
                "quantity": item.quantity,
                "size": item.size,
                "color": item.color,
                "unit_price": float(item.unit_price),
            }
            for item in order.items
        ],
    }


def _generate_invoice(order: Order):
    output = BytesIO()
    pdf = canvas.Canvas(output, pagesize=A4)

    y = 800
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(40, y, "HyperFit Invoice")
    y -= 30

    pdf.setFont("Helvetica", 10)
    pdf.drawString(40, y, f"Order Number: {order.order_number}")
    y -= 16
    pdf.drawString(40, y, f"Order Date: {order.created_at.strftime('%Y-%m-%d %H:%M')} UTC")
    y -= 20

    for item in order.items:
        line = f"{item.product.name} x {item.quantity} - INR {float(item.unit_price):.2f}"
        pdf.drawString(40, y, line[:95])
        y -= 14

    y -= 8
    pdf.drawString(40, y, f"Subtotal: INR {float(order.subtotal):.2f}")
    y -= 14
    pdf.drawString(40, y, f"Discount: INR {float(order.discount_amount):.2f}")
    y -= 14
    pdf.drawString(40, y, f"Shipping: INR {float(order.shipping_amount):.2f}")
    y -= 14
    pdf.drawString(40, y, f"Tax: INR {float(order.tax_amount):.2f}")
    y -= 18
    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(40, y, f"Total: INR {float(order.total_amount):.2f}")

    pdf.showPage()
    pdf.save()

    output.seek(0)
    return output


@order_bp.post("/checkout")
@jwt_required_user
@csrf_protect_json
def checkout():
    user = get_current_user()
    data = request.get_json() or {}

    address_id = safe_int(data.get("address_id"))
    coupon_code = (data.get("coupon_code") or "").strip().upper()
    address = Address.query.filter_by(id=address_id, user_id=user.id).first()
    if not address:
        return jsonify({"error": "Address not found"}), 400

    cart_items = CartItem.query.filter_by(user_id=user.id, saved_for_later=False).all()
    if not cart_items:
        return jsonify({"error": "Cart is empty"}), 400

    subtotal = Decimal("0.00")
    for item in cart_items:
        if item.quantity > item.product.stock:
            return jsonify({"error": f"Stock too low for {item.product.name}"}), 400
        subtotal += Decimal(item.quantity) * Decimal(item.product.price)

    discount = Decimal("0.00")
    if coupon_code:
        coupon = Coupon.query.filter_by(code=coupon_code, is_active=True).first()
        if coupon and coupon.expiry_date >= datetime.utcnow() and coupon.used_count < coupon.max_usage:
            if coupon.discount_type == "percent":
                discount = subtotal * Decimal(float(coupon.discount_value) / 100)
            else:
                discount = min(subtotal, Decimal(coupon.discount_value))
            coupon.used_count += 1

    shipping = Decimal("0.00") if subtotal >= Decimal("1999") else Decimal("99.00")
    tax = (subtotal - discount) * Decimal("0.12")
    total = (subtotal - discount) + shipping + tax

    order = Order(
        order_number=f"HF-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid4())[:8].upper()}",
        user_id=user.id,
        address_id=address.id,
        subtotal=subtotal,
        discount_amount=discount,
        shipping_amount=shipping,
        tax_amount=tax,
        total_amount=total,
        coupon_code=coupon_code or None,
        expected_delivery=datetime.utcnow() + timedelta(days=5),
    )
    db.session.add(order)
    db.session.flush()

    for item in cart_items:
        db.session.add(
            OrderItem(
                order_id=order.id,
                product_id=item.product_id,
                quantity=item.quantity,
                unit_price=item.product.price,
                size=item.size,
                color=item.color,
            )
        )
        product = Product.query.get(item.product_id)
        product.stock -= item.quantity

    db.session.add(Payment(order_id=order.id, provider="razorpay", amount=total, status="created"))

    shipment_data = ShipRocketService.create_shipment(order)
    db.session.add(
        Shipment(
            order_id=order.id,
            tracking_id=shipment_data.get("tracking_id"),
            tracking_url=shipment_data.get("tracking_url"),
            label_url=shipment_data.get("label_url"),
            estimated_delivery=datetime.fromisoformat(shipment_data["estimated_delivery"]),
        )
    )

    CartItem.query.filter_by(user_id=user.id, saved_for_later=False).delete(synchronize_session=False)
    db.session.commit()

    SendGridService.send_email(
        user.email,
        f"Order Confirmation {order.order_number}",
        order_confirmation_template(user.full_name, order.order_number, float(order.total_amount)),
    )

    return jsonify({"message": "Order placed", "order": _serialize_order(order)}), 201


@order_bp.get("")
@jwt_required_user
def list_orders():
    user = get_current_user()
    orders = Order.query.filter_by(user_id=user.id).order_by(Order.created_at.desc()).all()
    return jsonify({"items": [_serialize_order(order) for order in orders]})


@order_bp.get("/<string:order_number>")
@jwt_required_user
def order_detail(order_number):
    user = get_current_user()
    order = Order.query.filter_by(order_number=order_number, user_id=user.id).first_or_404()
    return jsonify({"order": _serialize_order(order)})


@order_bp.get("/<string:order_number>/invoice")
@jwt_required_user
def order_invoice(order_number):
    user = get_current_user()
    order = Order.query.filter_by(order_number=order_number, user_id=user.id).first_or_404()
    pdf_buffer = _generate_invoice(order)
    return send_file(pdf_buffer, as_attachment=True, download_name=f"invoice_{order.order_number}.pdf", mimetype="application/pdf")


@order_bp.get("/<string:order_number>/track")
@jwt_required_user
def track_order(order_number):
    user = get_current_user()
    order = Order.query.filter_by(order_number=order_number, user_id=user.id).first_or_404()
    shipment = Shipment.query.filter_by(order_id=order.id).first()
    if not shipment:
        return jsonify({"error": "Shipment not found"}), 404
    return jsonify(
        {
            "tracking_id": shipment.tracking_id,
            "tracking_url": shipment.tracking_url,
            "status": shipment.current_status,
            "expected_delivery": shipment.estimated_delivery.isoformat() if shipment.estimated_delivery else None,
        }
    )


@order_bp.get("/export/csv")
@jwt_required_user
def export_my_orders_csv():
    user = get_current_user()
    orders = Order.query.filter_by(user_id=user.id).order_by(Order.created_at.desc()).all()

    rows = [["Order Number", "Status", "Total", "Date"]]
    rows.extend([[o.order_number, o.status, float(o.total_amount), o.created_at.isoformat()] for o in orders])

    csv_stream = BytesIO()
    text = "\n".join([",".join(map(str, row)) for row in rows])
    csv_stream.write(text.encode("utf-8"))
    csv_stream.seek(0)

    return send_file(csv_stream, as_attachment=True, download_name="my_orders.csv", mimetype="text/csv")
