from datetime import datetime

from extensions import db


class Order(db.Model):
    __tablename__ = "orders"

    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.String(60), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    address_id = db.Column(db.Integer, db.ForeignKey("addresses.id"), nullable=False)
    status = db.Column(db.String(30), default="pending", nullable=False)
    payment_status = db.Column(db.String(30), default="pending", nullable=False)
    shipping_status = db.Column(db.String(30), default="pending", nullable=False)
    subtotal = db.Column(db.Numeric(10, 2), nullable=False)
    discount_amount = db.Column(db.Numeric(10, 2), default=0, nullable=False)
    shipping_amount = db.Column(db.Numeric(10, 2), default=0, nullable=False)
    tax_amount = db.Column(db.Numeric(10, 2), default=0, nullable=False)
    total_amount = db.Column(db.Numeric(10, 2), nullable=False)
    coupon_code = db.Column(db.String(60), nullable=True)
    expected_delivery = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User")
    address = db.relationship("Address")


class OrderItem(db.Model):
    __tablename__ = "order_items"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Numeric(10, 2), nullable=False)
    size = db.Column(db.String(20), nullable=True)
    color = db.Column(db.String(20), nullable=True)

    order = db.relationship("Order", backref=db.backref("items", lazy=True, cascade="all, delete-orphan"))
    product = db.relationship("Product")


class Payment(db.Model):
    __tablename__ = "payments"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False, index=True)
    provider = db.Column(db.String(30), default="razorpay", nullable=False)
    provider_order_id = db.Column(db.String(120), nullable=True, index=True)
    provider_payment_id = db.Column(db.String(120), nullable=True, index=True)
    signature = db.Column(db.String(255), nullable=True)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(db.String(30), default="created", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    order = db.relationship("Order", backref=db.backref("payments", lazy=True, cascade="all, delete-orphan"))


class Shipment(db.Model):
    __tablename__ = "shipments"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False, index=True)
    provider = db.Column(db.String(60), default="shiprocket", nullable=False)
    tracking_id = db.Column(db.String(120), nullable=True, index=True)
    tracking_url = db.Column(db.String(500), nullable=True)
    label_url = db.Column(db.String(500), nullable=True)
    current_status = db.Column(db.String(40), default="created", nullable=False)
    estimated_delivery = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    order = db.relationship("Order", backref=db.backref("shipments", lazy=True, cascade="all, delete-orphan"))
