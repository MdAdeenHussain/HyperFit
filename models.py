from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta

db = SQLAlchemy()

class Newsletter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    category = db.Column(db.String(50), nullable=False)
    sub_category = db.Column(db.String(50), nullable=True)
    tags = db.Column(db.String(200))  # comma-separated
    price = db.Column(db.Float, nullable=False)
    discount_percent = db.Column(db.Float, default=0)
    discounted_price = db.Column(db.Float)
    description = db.Column(db.Text)
    image_filename = db.Column(db.String(200), nullable=False)

    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(20))
    address = db.Column(db.Text)

    phone = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    password = db.Column(db.String(200), nullable=False)

    phone_verified = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)

    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    otp_code = db.Column(db.String(6), nullable=False)
    otp_type = db.Column(db.String(10))  # 'email' or 'phone'

    expires_at = db.Column(db.DateTime, nullable=False)

    user = db.relationship("User", backref="otps")

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    total_amount = db.Column(db.Float)
    status = db.Column(db.String(20))  # placed, delivered, returned
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

