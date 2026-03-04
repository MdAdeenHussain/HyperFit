from datetime import datetime

from extensions import db


class Product(db.Model):
    __tablename__ = "products"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    slug = db.Column(db.String(255), unique=True, nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    fabric_details = db.Column(db.Text, nullable=True)
    size_guide = db.Column(db.Text, nullable=True)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    compare_price = db.Column(db.Numeric(10, 2), nullable=True)
    stock = db.Column(db.Integer, default=0, nullable=False)
    sku = db.Column(db.String(80), unique=True, nullable=False)
    images = db.Column(db.JSON, default=list, nullable=False)
    sizes = db.Column(db.JSON, default=list, nullable=False)
    colors = db.Column(db.JSON, default=list, nullable=False)
    tags = db.Column(db.JSON, default=list, nullable=False)
    rating_avg = db.Column(db.Float, default=0.0, nullable=False)
    review_count = db.Column(db.Integer, default=0, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_featured = db.Column(db.Boolean, default=False, nullable=False)
    is_recommended = db.Column(db.Boolean, default=False, nullable=False)
    is_new_arrival = db.Column(db.Boolean, default=False, nullable=False)
    is_on_sale = db.Column(db.Boolean, default=False, nullable=False)
    seo_title = db.Column(db.String(255), nullable=True)
    seo_description = db.Column(db.String(320), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    category_id = db.Column(db.Integer, db.ForeignKey("categories.id"), nullable=False, index=True)
    category = db.relationship("Category", backref=db.backref("products", lazy=True))
