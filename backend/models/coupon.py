from datetime import datetime

from extensions import db


class Coupon(db.Model):
    __tablename__ = "coupons"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(60), unique=True, nullable=False, index=True)
    discount_type = db.Column(db.String(20), nullable=False)  # percent / flat
    discount_value = db.Column(db.Numeric(10, 2), nullable=False)
    min_order_amount = db.Column(db.Numeric(10, 2), nullable=True)
    expiry_date = db.Column(db.DateTime, nullable=False)
    max_usage = db.Column(db.Integer, nullable=False, default=1)
    used_count = db.Column(db.Integer, nullable=False, default=0)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=True)
    category_id = db.Column(db.Integer, db.ForeignKey("categories.id"), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    product = db.relationship("Product")
    category = db.relationship("Category")
