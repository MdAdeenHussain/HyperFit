from datetime import datetime
from io import BytesIO

from flask import Blueprint, jsonify, request, send_file
from sqlalchemy import func

from extensions import cache, db
from models.category import Category
from models.coupon import Coupon
from models.order import Order, OrderItem
from models.product import Product
from models.user import User
from services.email_templates import newsletter_template
from services.sendgrid_service import SendGridService
from utils.auth_utils import admin_required
from utils.helpers import slugify
from utils.security import csrf_protect_json


admin_bp = Blueprint("admin_routes", __name__, url_prefix="/api/admin")


@admin_bp.get("/dashboard")
@admin_required
def dashboard():
    total_revenue = db.session.query(func.coalesce(func.sum(Order.total_amount), 0)).scalar() or 0
    orders_count = Order.query.count()
    users_count = User.query.count()
    products_count = Product.query.count()

    sales = (
        db.session.query(func.date(Order.created_at), func.count(Order.id), func.coalesce(func.sum(Order.total_amount), 0))
        .group_by(func.date(Order.created_at))
        .order_by(func.date(Order.created_at).asc())
        .limit(30)
        .all()
    )

    top_products = (
        db.session.query(Product.name, func.coalesce(func.sum(OrderItem.quantity), 0).label("units"))
        .join(OrderItem, OrderItem.product_id == Product.id, isouter=True)
        .group_by(Product.id)
        .order_by(func.coalesce(func.sum(OrderItem.quantity), 0).desc())
        .limit(5)
        .all()
    )

    return jsonify(
        {
            "metrics": {
                "revenue": float(total_revenue),
                "orders": orders_count,
                "customers": users_count,
                "products": products_count,
            },
            "sales_graph": [{"date": str(s[0]), "orders": int(s[1]), "revenue": float(s[2])} for s in sales],
            "top_selling_products": [{"name": p[0], "units": int(p[1])} for p in top_products],
        }
    )


@admin_bp.get("/products")
@admin_required
def admin_products():
    rows = Product.query.order_by(Product.created_at.desc()).all()
    return jsonify({"items": [{"id": p.id, "name": p.name, "price": float(p.price), "stock": p.stock, "sku": p.sku} for p in rows]})


@admin_bp.post("/products")
@admin_required
@csrf_protect_json
def create_product():
    data = request.get_json() or {}
    slug = slugify(data.get("name"))
    product = Product(
        name=data.get("name"),
        slug=f"{slug}-{int(datetime.utcnow().timestamp())}",
        description=data.get("description", ""),
        fabric_details=data.get("fabric_details"),
        size_guide=data.get("size_guide"),
        price=data.get("price", 0),
        compare_price=data.get("compare_price"),
        stock=data.get("stock", 0),
        sku=data.get("sku"),
        images=data.get("images", []),
        sizes=data.get("sizes", []),
        colors=data.get("colors", []),
        tags=data.get("tags", []),
        category_id=data.get("category_id"),
        is_featured=bool(data.get("is_featured", False)),
        is_recommended=bool(data.get("is_recommended", False)),
        is_new_arrival=bool(data.get("is_new_arrival", False)),
        is_on_sale=bool(data.get("is_on_sale", False)),
        seo_title=data.get("seo_title"),
        seo_description=data.get("seo_description"),
    )
    db.session.add(product)
    db.session.commit()
    cache.clear()
    return jsonify({"message": "Product created", "id": product.id}), 201


@admin_bp.put("/products/<int:product_id>")
@admin_required
@csrf_protect_json
def update_product(product_id):
    data = request.get_json() or {}
    product = Product.query.get_or_404(product_id)

    for key in [
        "name",
        "description",
        "fabric_details",
        "size_guide",
        "price",
        "compare_price",
        "stock",
        "sku",
        "images",
        "sizes",
        "colors",
        "tags",
        "category_id",
        "is_featured",
        "is_recommended",
        "is_new_arrival",
        "is_on_sale",
        "seo_title",
        "seo_description",
        "is_active",
    ]:
        if key in data:
            setattr(product, key, data[key])

    if "name" in data:
        product.slug = slugify(data["name"]) + f"-{product.id}"

    db.session.commit()
    cache.clear()
    return jsonify({"message": "Product updated"})


@admin_bp.delete("/products/<int:product_id>")
@admin_required
@csrf_protect_json
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    cache.clear()
    return jsonify({"message": "Product deleted"})


@admin_bp.get("/categories")
@admin_required
def admin_categories():
    rows = Category.query.order_by(Category.name.asc()).all()
    return jsonify({"items": [{"id": c.id, "name": c.name, "slug": c.slug, "gender": c.gender, "parent_id": c.parent_id} for c in rows]})


@admin_bp.post("/categories")
@admin_required
@csrf_protect_json
def create_category():
    data = request.get_json() or {}
    name = data.get("name")
    if not name:
        return jsonify({"error": "name is required"}), 400

    category = Category(
        name=name,
        slug=slugify(name) + f"-{int(datetime.utcnow().timestamp())}",
        parent_id=data.get("parent_id"),
        gender=data.get("gender", "men"),
        image_url=data.get("image_url"),
        is_active=bool(data.get("is_active", True)),
    )
    db.session.add(category)
    db.session.commit()
    return jsonify({"message": "Category created", "id": category.id}), 201


@admin_bp.get("/orders")
@admin_required
def admin_orders():
    rows = Order.query.order_by(Order.created_at.desc()).all()
    return jsonify(
        {
            "items": [
                {
                    "id": o.id,
                    "order_number": o.order_number,
                    "customer": o.user.full_name,
                    "status": o.status,
                    "payment_status": o.payment_status,
                    "total": float(o.total_amount),
                    "created_at": o.created_at.isoformat(),
                }
                for o in rows
            ]
        }
    )


@admin_bp.patch("/orders/<string:order_number>")
@admin_required
@csrf_protect_json
def update_order(order_number):
    order = Order.query.filter_by(order_number=order_number).first_or_404()
    data = request.get_json() or {}
    for key in ["status", "payment_status", "shipping_status"]:
        if key in data:
            setattr(order, key, data[key])
    db.session.commit()
    return jsonify({"message": "Order updated"})


@admin_bp.get("/customers")
@admin_required
def customers():
    rows = User.query.order_by(User.created_at.desc()).all()
    return jsonify(
        {
            "items": [
                {
                    "id": u.id,
                    "name": u.full_name,
                    "email": u.email,
                    "phone": u.phone,
                    "is_active": u.is_active,
                    "is_admin": u.is_admin,
                }
                for u in rows
            ]
        }
    )


@admin_bp.patch("/customers/<int:user_id>/block")
@admin_required
@csrf_protect_json
def block_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        return jsonify({"error": "Cannot block admin"}), 400
    user.is_active = not bool((request.get_json() or {}).get("block", True))
    db.session.commit()
    return jsonify({"message": "User status updated"})


@admin_bp.get("/coupons")
@admin_required
def coupons():
    rows = Coupon.query.order_by(Coupon.created_at.desc()).all()
    return jsonify(
        {
            "items": [
                {
                    "id": c.id,
                    "code": c.code,
                    "discount_type": c.discount_type,
                    "discount_value": float(c.discount_value),
                    "expiry_date": c.expiry_date.isoformat(),
                    "max_usage": c.max_usage,
                    "used_count": c.used_count,
                    "is_active": c.is_active,
                }
                for c in rows
            ]
        }
    )


@admin_bp.post("/coupons")
@admin_required
@csrf_protect_json
def create_coupon():
    data = request.get_json() or {}
    expiry = datetime.fromisoformat(data.get("expiry_date"))
    coupon = Coupon(
        code=(data.get("code") or "").upper(),
        discount_type=data.get("discount_type", "percent"),
        discount_value=data.get("discount_value", 0),
        min_order_amount=data.get("min_order_amount"),
        expiry_date=expiry,
        max_usage=data.get("max_usage", 1),
        product_id=data.get("product_id"),
        category_id=data.get("category_id"),
        is_active=bool(data.get("is_active", True)),
    )
    db.session.add(coupon)
    db.session.commit()
    return jsonify({"message": "Coupon created"}), 201


@admin_bp.get("/inventory")
@admin_required
def inventory():
    rows = Product.query.order_by(Product.stock.asc()).all()
    return jsonify(
        {
            "items": [
                {
                    "id": p.id,
                    "name": p.name,
                    "stock": p.stock,
                    "sizes": p.sizes,
                    "is_out_of_stock": p.stock <= 0,
                    "is_low_stock": p.stock <= 5,
                }
                for p in rows
            ]
        }
    )


@admin_bp.get("/export/customers.csv")
@admin_required
def export_customers_csv():
    rows = User.query.order_by(User.created_at.desc()).all()
    content = "name,email,phone,is_active\n" + "\n".join([f"{u.full_name},{u.email},{u.phone or ''},{u.is_active}" for u in rows])
    stream = BytesIO(content.encode("utf-8"))
    return send_file(stream, as_attachment=True, download_name="customers.csv", mimetype="text/csv")


@admin_bp.post("/campaigns/send")
@admin_required
@csrf_protect_json
def send_campaign():
    data = request.get_json() or {}
    title = data.get("title", "HyperFit Update")
    content = data.get("content", "New arrivals are live now.")
    subscribers = User.query.filter_by(is_active=True).all()

    for subscriber in subscribers:
        SendGridService.send_email(subscriber.email, title, newsletter_template(title, content))

    return jsonify({"message": "Campaign queued", "recipients": len(subscribers)})
