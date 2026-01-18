from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta

db = SQLAlchemy()

class Newsletter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)

class Product(db.Model):
    __tablename__="product"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    category = db.Column(db.String(50), nullable=False)
    sub_category = db.Column(db.String(50), nullable=True)
    tags = db.Column(db.String(200))  # comma-separated
    price = db.Column(db.Float, nullable=False)
    discount_percent = db.Column(db.Float, default=0)
    discounted_price = db.Column(db.Float)
    is_compression = db.Column(db.Boolean, default=False)
    is_new_arrival = db.Column(db.Boolean, default=False)
    is_on_sale = db.Column(db.Boolean, default=False)
    description = db.Column(db.Text)
    image_filename = db.Column(db.String(200), nullable=False)

    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class User(UserMixin, db.Model):
    __tablename__="users"
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(20))
    address = db.Column(db.Text, nullable=False)

    phone = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    password = db.Column(db.String(200), nullable=False)

    phone_verified = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)

    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

class OTP(db.Model):
    __tablename__="otp"
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    otp_type = db.Column(db.String(10))  # 'email' or 'phone'

    expires_at = db.Column(db.DateTime, nullable=False)

    user = db.relationship("User", backref="otps")

class Order(db.Model):
    __tablename__="orders"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    address = db.Column(db.Text, nullable=False)
    total_amount = db.Column(db.Float)
    payment_method = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(30), default="placed")  # placed, shipped, delivered, returned
    tracking_id = db.Column(db.String(100), nullable=True)
    expected_delivery = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User", backref="orders", lazy=True)
    items = db.relationship("OrderItem", backref="order", lazy=True)

class ProductSize(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"))
    size = db.Column(db.String(10))
    stock = db.Column(db.Integer)

    product = db.relationship("Product", backref="sizes")

class OrderItem(db.Model):
    __tablename__="order_items"
    id = db.Column(db.Integer, primary_key=True)

    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"), nullable=False)

    product_name = db.Column(db.String(200))
    price = db.Column(db.Float)
    size=db.Column(db.String(10))
    quantity = db.Column(db.Integer)

    product = db.relationship("Product")

class CartItem(db.Model):
    __tablename__="cart_items"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"))
    quantity = db.Column(db.Integer, default=1)
    size = db.Column(db.String(10))

    product = db.relationship("Product")
    user = db.relationship("User", backref="cart_items")

