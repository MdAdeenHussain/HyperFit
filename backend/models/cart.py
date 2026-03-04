from datetime import datetime

from extensions import db


class CartItem(db.Model):
    __tablename__ = "cart_items"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False, index=True)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    size = db.Column(db.String(20), nullable=True)
    color = db.Column(db.String(20), nullable=True)
    saved_for_later = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    product = db.relationship("Product")

    __table_args__ = (
        db.UniqueConstraint("user_id", "product_id", "size", "color", name="uq_cart_variant"),
    )
