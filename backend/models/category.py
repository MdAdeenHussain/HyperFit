from datetime import datetime

from extensions import db


class Category(db.Model):
    __tablename__ = "categories"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    slug = db.Column(db.String(150), unique=True, nullable=False, index=True)
    parent_id = db.Column(db.Integer, db.ForeignKey("categories.id"), nullable=True)
    gender = db.Column(db.String(20), nullable=False, default="men")  # men / women
    image_url = db.Column(db.String(500), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    parent = db.relationship("Category", remote_side=[id], backref="subcategories")
