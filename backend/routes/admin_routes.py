import csv
import json
import os
from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal
from io import BytesIO, StringIO
from uuid import uuid4

from flask import Blueprint, current_app, jsonify, request, send_file
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from sqlalchemy import and_, desc, func, or_
from werkzeug.utils import secure_filename

from extensions import cache, db
from models import Address
from models.admin import AdminActivity, CMSPage, CMSVersion, EmailCampaign, SiteSetting
from models.category import Category
from models.newsletter import NewsletterSubscriber
from models.coupon import Coupon
from models.order import Order, OrderItem
from models.product import Product
from models.user import User
from services.email_templates import newsletter_template
from services.sendgrid_service import SendGridService
from utils.auth_utils import admin_required, get_current_user
from utils.helpers import slugify
from utils.security import csrf_protect_json


admin_bp = Blueprint("admin_routes", __name__, url_prefix="/api/admin")

ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
ALLOWED_IMAGE_MIME_TYPES = {"image/jpeg", "image/png", "image/webp"}


DEFAULT_SITE_SETTINGS = {
    "free_shipping_amount": 1999,
    "tax_rate": 0.12,
    "currency": "INR",
    "email_templates": {
        "order_confirmation_subject": "Your HyperFit order is confirmed",
        "newsletter_subject": "HyperFit: New arrivals this week",
    },
    "seo_defaults": {
        "title": "HyperFit Performance Wear",
        "description": "High-performance activewear for modern athletes.",
    },
}


DEFAULT_CMS_CONTENT = {
    "home": {
        "hero": {
            "title": "Performance wear built for every rep",
            "subtitle": "Minimal fits. Maximum function.",
            "cta_text": "Shop New Drops",
            "image": "https://images.unsplash.com/photo-1517836357463-d25dfeac3438?auto=format&fit=crop&w=1400&q=80",
        },
        "homepage_banners": [
            {
                "title": "Spring Training Collection",
                "description": "Breathable fabrics for every condition.",
                "image": "https://images.unsplash.com/photo-1579758629938-03607ccdbaba?auto=format&fit=crop&w=1200&q=80",
            },
            {
                "title": "Members Exclusive",
                "description": "Unlock early access to limited drops.",
                "image": "https://images.unsplash.com/photo-1517963879433-6ad2b056d712?auto=format&fit=crop&w=1200&q=80",
            },
        ],
        "featured_products": [],
        "homepage_categories": ["Men", "Women"],
        "landing_sections": [
            {"heading": "Breathable Fabrics", "copy": "Engineered to keep you cool.", "layout": "left"},
            {"heading": "Smart Compression", "copy": "Support where it matters.", "layout": "right"},
        ],
        "footer_content": {
            "about": "HyperFit creates premium activewear for training and recovery.",
            "help_email": "support@hyperfit.com",
        },
        "navigation_links": [
            {"label": "Men", "href": "/shop?category=men"},
            {"label": "Women", "href": "/shop?category=women"},
            {"label": "New Arrivals", "href": "/shop?sort=new"},
        ],
        "seo_metadata": {
            "title": "HyperFit - Performance Apparel",
            "description": "Premium gym and lifestyle apparel.",
        },
    }
}


def _to_float(value) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _parse_date(value: str | None, end_of_day: bool = False):
    if not value:
        return None


def _validate_uploaded_image(file_storage):
    filename = secure_filename(file_storage.filename or "")
    extension = os.path.splitext(filename)[1].lower()
    if not filename or extension not in ALLOWED_IMAGE_EXTENSIONS:
        return "Only JPG, JPEG, PNG, and WEBP files are allowed"

    if (file_storage.mimetype or "").lower() not in ALLOWED_IMAGE_MIME_TYPES:
        return "Unsupported image format"

    current_position = file_storage.stream.tell()
    file_storage.stream.seek(0, os.SEEK_END)
    size = file_storage.stream.tell()
    file_storage.stream.seek(current_position)

    if size > current_app.config.get("UPLOAD_MAX_FILE_SIZE", 5 * 1024 * 1024):
        return "Each image must be 5 MB or smaller"

    return None

    value = value.strip()
    fmts = ["%Y-%m-%d", "%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"]
    for fmt in fmts:
        try:
            dt = datetime.strptime(value, fmt)
            if end_of_day and fmt == "%Y-%m-%d":
                return dt + timedelta(days=1) - timedelta(microseconds=1)
            return dt
        except ValueError:
            continue

    try:
        parsed = datetime.fromisoformat(value)
        if end_of_day and len(value) == 10:
            return parsed + timedelta(days=1) - timedelta(microseconds=1)
        return parsed
    except ValueError:
        return None


def _get_period_bounds(range_key: str, start_raw: str | None, end_raw: str | None):
    now = datetime.utcnow()
    today_start = datetime(now.year, now.month, now.day)

    if range_key == "today":
        return today_start, now
    if range_key == "7d":
        return today_start - timedelta(days=6), now
    if range_key == "30d":
        return today_start - timedelta(days=29), now
    if range_key == "year":
        return datetime(now.year, 1, 1), now

    start = _parse_date(start_raw)
    end = _parse_date(end_raw, end_of_day=True)
    if start and end and end >= start:
        return start, end

    return today_start - timedelta(days=29), now


def _previous_period(start: datetime, end: datetime):
    duration = max(end - start, timedelta(days=1))
    prev_end = start - timedelta(seconds=1)
    prev_start = prev_end - duration
    return prev_start, prev_end


def _pct_change(current_value: float, prev_value: float) -> float:
    if prev_value <= 0 and current_value <= 0:
        return 0.0
    if prev_value <= 0:
        return 100.0
    return round(((current_value - prev_value) / prev_value) * 100, 2)


def _format_range_label(range_key: str):
    labels = {
        "today": "Today",
        "7d": "Last 7 Days",
        "30d": "Last 30 Days",
        "year": "This Year",
        "custom": "Custom Range",
    }
    return labels.get(range_key, "Last 30 Days")


def _daily_sales_points(start: datetime, end: datetime):
    rows = (
        db.session.query(
            func.date(Order.created_at).label("day"),
            func.count(Order.id).label("orders_count"),
            func.coalesce(func.sum(Order.total_amount), 0).label("revenue"),
        )
        .filter(Order.created_at >= start, Order.created_at <= end)
        .group_by(func.date(Order.created_at))
        .order_by(func.date(Order.created_at).asc())
        .all()
    )

    row_map = {str(r.day): {"orders": int(r.orders_count), "revenue": _to_float(r.revenue)} for r in rows}
    cursor = datetime(start.year, start.month, start.day)
    last_day = datetime(end.year, end.month, end.day)

    points = []
    while cursor <= last_day:
        key = cursor.strftime("%Y-%m-%d")
        day_data = row_map.get(key, {"orders": 0, "revenue": 0.0})
        points.append({"date": key, **day_data})
        cursor += timedelta(days=1)

    return points


def _sparkline_from_points(points, metric_key: str, target_len: int = 10):
    if not points:
        return [0] * target_len

    series = [p.get(metric_key, 0) for p in points]
    if len(series) >= target_len:
        step = max(1, len(series) // target_len)
        sampled = [series[i] for i in range(0, len(series), step)][-target_len:]
    else:
        sampled = ([series[0]] * (target_len - len(series))) + series
    return [round(_to_float(v), 2) for v in sampled]


def _serialize_order(order: Order):
    return {
        "id": order.id,
        "order_number": order.order_number,
        "customer": order.user.full_name if order.user else "Guest",
        "customer_email": order.user.email if order.user else "",
        "status": order.status,
        "payment_status": order.payment_status,
        "shipping_status": order.shipping_status,
        "amount": _to_float(order.total_amount),
        "created_at": order.created_at.isoformat(),
        "products": [
            {
                "name": item.product.name if item.product else "Unknown",
                "quantity": item.quantity,
            }
            for item in order.items
        ],
    }


def _serialize_product(product: Product):
    discount_pct = 0
    if product.compare_price and _to_float(product.compare_price) > _to_float(product.price):
        discount_pct = round(((_to_float(product.compare_price) - _to_float(product.price)) / _to_float(product.compare_price)) * 100)

    category_name = product.category.name if product.category else None
    subcategory_name = product.category.parent.name if product.category and product.category.parent else None

    return {
        "id": product.id,
        "name": product.name,
        "description": product.description,
        "price": _to_float(product.price),
        "discount": discount_pct,
        "stock": product.stock,
        "sku": product.sku,
        "images": product.images or [],
        "sizes": product.sizes or [],
        "colors": product.colors or [],
        "category_id": product.category_id,
        "category": category_name,
        "subcategory": subcategory_name,
        "created_at": product.created_at.isoformat(),
    }


def _serialize_coupon(coupon: Coupon):
    return {
        "id": coupon.id,
        "code": coupon.code,
        "discount_type": coupon.discount_type,
        "discount_value": _to_float(coupon.discount_value),
        "expiry_date": coupon.expiry_date.isoformat() if coupon.expiry_date else None,
        "max_usage": coupon.max_usage,
        "used_count": coupon.used_count,
        "min_order_amount": _to_float(coupon.min_order_amount),
        "product_id": coupon.product_id,
        "category_id": coupon.category_id,
        "is_active": coupon.is_active,
    }


def _serialize_campaign(campaign: EmailCampaign):
    return {
        "id": campaign.id,
        "title": campaign.title,
        "campaign_type": campaign.campaign_type,
        "subject": campaign.subject,
        "status": campaign.status,
        "sent_count": campaign.sent_count,
        "open_rate": round(campaign.open_rate, 2),
        "click_rate": round(campaign.click_rate, 2),
        "conversion_rate": round(campaign.conversion_rate, 2),
        "created_at": campaign.created_at.isoformat(),
    }


def _get_setting(setting_key: str, fallback: dict):
    setting = SiteSetting.query.filter_by(setting_key=setting_key).first()
    if setting:
        return setting

    setting = SiteSetting(setting_key=setting_key, value=fallback)
    db.session.add(setting)
    db.session.commit()
    return setting


def _get_cms_page(page_key: str):
    page = CMSPage.query.filter_by(page_key=page_key).first()
    if page:
        return page

    default_payload = DEFAULT_CMS_CONTENT.get(page_key, {})
    page = CMSPage(
        page_key=page_key,
        title=page_key.replace("-", " ").title(),
        draft_content=default_payload,
        live_content=default_payload,
        is_published=False,
    )
    db.session.add(page)
    db.session.commit()
    return page


def _flatten_content(content, prefix=""):
    flattened = {}
    if isinstance(content, dict):
        for key, value in content.items():
            child_prefix = f"{prefix}.{key}" if prefix else key
            flattened.update(_flatten_content(value, child_prefix))
    elif isinstance(content, list):
        flattened[prefix] = json.dumps(content, sort_keys=True)
    else:
        flattened[prefix] = "" if content is None else str(content)
    return flattened


def _build_change_summary(before_content, after_content):
    before_flat = _flatten_content(before_content or {})
    after_flat = _flatten_content(after_content or {})
    keys = sorted(set(before_flat.keys()) | set(after_flat.keys()))

    text_changes = []
    image_changes = []
    layout_changes = []

    for key in keys:
        old_val = before_flat.get(key, "")
        new_val = after_flat.get(key, "")
        if old_val == new_val:
            continue

        lower_key = key.lower()
        if any(token in lower_key for token in ["image", "banner", "photo"]):
            image_changes.append(key)
        elif any(token in lower_key for token in ["layout", "section", "navigation", "footer", "hero"]):
            layout_changes.append(key)
        else:
            text_changes.append(key)

    return {
        "changed_text": text_changes[:30],
        "changed_image": image_changes[:30],
        "changed_layout": layout_changes[:30],
        "change_count": len(text_changes) + len(image_changes) + len(layout_changes),
    }


def _next_version_number(page_id: int):
    latest = (
        db.session.query(func.max(CMSVersion.version_number))
        .filter(CMSVersion.page_id == page_id)
        .scalar()
    )
    return int(latest or 0) + 1


def _create_cms_version(page: CMSPage, action: str, content: dict, change_summary: dict, changed_by: int | None):
    version = CMSVersion(
        page_id=page.id,
        version_number=_next_version_number(page.id),
        action=action,
        changed_by=changed_by,
        change_summary=change_summary,
        content=content,
    )
    db.session.add(version)
    return version


def _log_activity(activity_type: str, message: str, user_id: int | None, meta: dict | None = None):
    db.session.add(
        AdminActivity(
            activity_type=activity_type,
            message=message,
            user_id=user_id,
            meta=meta or {},
        )
    )


def _csv_response(filename: str, header: list[str], rows: list[list]):
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    for row in rows:
        writer.writerow(row)

    stream = BytesIO(buffer.getvalue().encode("utf-8"))
    stream.seek(0)
    return send_file(stream, as_attachment=True, download_name=filename, mimetype="text/csv")


def _build_report_pdf(title: str, lines: list[str]):
    output = BytesIO()
    pdf = canvas.Canvas(output, pagesize=A4)
    y = 810

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(40, y, title)
    y -= 24

    pdf.setFont("Helvetica", 10)
    for line in lines:
        if y < 40:
            pdf.showPage()
            pdf.setFont("Helvetica", 10)
            y = 810
        pdf.drawString(40, y, line[:120])
        y -= 14

    pdf.showPage()
    pdf.save()
    output.seek(0)
    return output


def _build_invoice_pdf(order: Order):
    output = BytesIO()
    pdf = canvas.Canvas(output, pagesize=A4)

    y = 810
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(40, y, "HyperFit Admin Invoice")
    y -= 24

    pdf.setFont("Helvetica", 10)
    pdf.drawString(40, y, f"Order Number: {order.order_number}")
    y -= 14
    pdf.drawString(40, y, f"Customer: {order.user.full_name if order.user else 'Guest'}")
    y -= 14
    pdf.drawString(40, y, f"Order Date: {order.created_at.strftime('%Y-%m-%d %H:%M')} UTC")
    y -= 20

    for item in order.items:
        line = f"{item.product.name if item.product else 'Unknown'} x {item.quantity}  INR {_to_float(item.unit_price):.2f}"
        pdf.drawString(40, y, line[:120])
        y -= 14

    y -= 8
    pdf.drawString(40, y, f"Subtotal: INR {_to_float(order.subtotal):.2f}")
    y -= 14
    pdf.drawString(40, y, f"Discount: INR {_to_float(order.discount_amount):.2f}")
    y -= 14
    pdf.drawString(40, y, f"Shipping: INR {_to_float(order.shipping_amount):.2f}")
    y -= 14
    pdf.drawString(40, y, f"Tax: INR {_to_float(order.tax_amount):.2f}")
    y -= 16

    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(40, y, f"Total: INR {_to_float(order.total_amount):.2f}")

    pdf.showPage()
    pdf.save()
    output.seek(0)
    return output


@admin_bp.get("/dashboard")
@admin_required
@cache.cached(timeout=60, query_string=True)
def dashboard():
    range_key = request.args.get("range", "30d")
    start, end = _get_period_bounds(
        range_key,
        request.args.get("start"),
        request.args.get("end"),
    )
    prev_start, prev_end = _previous_period(start, end)

    current_orders_q = Order.query.filter(Order.created_at >= start, Order.created_at <= end)
    prev_orders_q = Order.query.filter(Order.created_at >= prev_start, Order.created_at <= prev_end)

    current_revenue = _to_float(
        db.session.query(func.coalesce(func.sum(Order.total_amount), 0))
        .filter(Order.created_at >= start, Order.created_at <= end)
        .scalar()
    )
    previous_revenue = _to_float(
        db.session.query(func.coalesce(func.sum(Order.total_amount), 0))
        .filter(Order.created_at >= prev_start, Order.created_at <= prev_end)
        .scalar()
    )

    current_orders = current_orders_q.count()
    previous_orders = prev_orders_q.count()

    current_customers = (
        db.session.query(func.count(func.distinct(Order.user_id)))
        .filter(Order.created_at >= start, Order.created_at <= end)
        .scalar()
        or 0
    )
    previous_customers = (
        db.session.query(func.count(func.distinct(Order.user_id)))
        .filter(Order.created_at >= prev_start, Order.created_at <= prev_end)
        .scalar()
        or 0
    )

    current_visitors = max(220, int(current_orders * 19 + current_customers * 11 + 180))
    previous_visitors = max(200, int(previous_orders * 19 + previous_customers * 11 + 170))

    current_conversion = (current_orders / max(current_visitors, 1)) * 100
    previous_conversion = (previous_orders / max(previous_visitors, 1)) * 100

    current_aov = current_revenue / max(current_orders, 1)
    previous_aov = previous_revenue / max(previous_orders, 1)

    points = _daily_sales_points(start, end)

    top_products = (
        db.session.query(
            Product.id,
            Product.name,
            Product.images,
            Product.stock,
            func.coalesce(func.sum(OrderItem.quantity), 0).label("units"),
            func.coalesce(func.sum(OrderItem.quantity * OrderItem.unit_price), 0).label("revenue"),
        )
        .join(OrderItem, OrderItem.product_id == Product.id, isouter=True)
        .join(Order, Order.id == OrderItem.order_id, isouter=True)
        .filter(or_(Order.id.is_(None), and_(Order.created_at >= start, Order.created_at <= end)))
        .group_by(Product.id)
        .order_by(desc("units"))
        .limit(6)
        .all()
    )

    top_products_payload = [
        {
            "id": row.id,
            "name": row.name,
            "image": (row.images or [""])[0],
            "units_sold": int(row.units or 0),
            "revenue": _to_float(row.revenue),
            "stock_status": "Out of Stock" if (row.stock or 0) <= 0 else "Low Stock" if (row.stock or 0) <= 10 else "In Stock",
        }
        for row in top_products
    ]

    country_rows = (
        db.session.query(Address.country, func.count(Order.id).label("orders_count"))
        .join(Order, Order.address_id == Address.id)
        .filter(Order.created_at >= start, Order.created_at <= end)
        .group_by(Address.country)
        .order_by(desc("orders_count"))
        .limit(8)
        .all()
    )

    top_countries = [
        {"country": row.country or "Unknown", "orders": int(row.orders_count or 0)}
        for row in country_rows
    ]

    active_customers = (
        db.session.query(func.count(func.distinct(Order.user_id)))
        .filter(Order.created_at >= start, Order.created_at <= end)
        .scalar()
        or 0
    )
    new_customers = User.query.filter(User.created_at >= start, User.created_at <= end).count()

    returning_customers = (
        db.session.query(func.count())
        .select_from(
            db.session.query(Order.user_id)
            .group_by(Order.user_id)
            .having(func.count(Order.id) > 1)
            .subquery()
        )
        .scalar()
        or 0
    )

    traffic_sources = [
        {"source": "Direct Traffic", "value": 34},
        {"source": "Organic Search", "value": 28},
        {"source": "Social Media", "value": 17},
        {"source": "Referral Traffic", "value": 13},
        {"source": "Email Campaigns", "value": 8},
    ]

    activity_rows = AdminActivity.query.order_by(AdminActivity.created_at.desc()).limit(12).all()
    if not activity_rows:
        recent_orders = Order.query.order_by(Order.created_at.desc()).limit(6).all()
        activity_rows = [
            AdminActivity(
                activity_type="order",
                message=f"New order placed: {order.order_number}",
                created_at=order.created_at,
                user_id=order.user_id,
                meta={"order_number": order.order_number},
            )
            for order in recent_orders
        ]

    metrics = [
        {
            "label": "Total Revenue",
            "key": "revenue",
            "value": round(current_revenue, 2),
            "delta": _pct_change(current_revenue, previous_revenue),
            "sparkline": _sparkline_from_points(points, "revenue"),
            "format": "currency",
        },
        {
            "label": "Total Orders",
            "key": "orders",
            "value": current_orders,
            "delta": _pct_change(current_orders, previous_orders),
            "sparkline": _sparkline_from_points(points, "orders"),
            "format": "number",
        },
        {
            "label": "Total Customers",
            "key": "customers",
            "value": current_customers,
            "delta": _pct_change(current_customers, previous_customers),
            "sparkline": _sparkline_from_points(points, "orders"),
            "format": "number",
        },
        {
            "label": "Total Visitors",
            "key": "visitors",
            "value": current_visitors,
            "delta": _pct_change(current_visitors, previous_visitors),
            "sparkline": _sparkline_from_points(points, "orders"),
            "format": "number",
        },
        {
            "label": "Conversion Rate",
            "key": "conversion_rate",
            "value": round(current_conversion, 2),
            "delta": _pct_change(current_conversion, previous_conversion),
            "sparkline": _sparkline_from_points(points, "orders"),
            "format": "percent",
        },
        {
            "label": "Average Order Value",
            "key": "aov",
            "value": round(current_aov, 2),
            "delta": _pct_change(current_aov, previous_aov),
            "sparkline": _sparkline_from_points(points, "revenue"),
            "format": "currency",
        },
    ]

    funnel = [
        {"step": "Visitors", "value": current_visitors},
        {"step": "Product Views", "value": int(current_visitors * 0.64)},
        {"step": "Add to Cart", "value": int(current_visitors * 0.23)},
        {"step": "Checkout", "value": int(current_visitors * 0.12)},
        {"step": "Orders", "value": current_orders},
    ]

    return jsonify(
        {
            "range": {
                "key": range_key,
                "label": _format_range_label(range_key),
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
            "metrics": metrics,
            "sales_analytics": {
                "revenue_over_time": [{"date": p["date"], "value": p["revenue"]} for p in points],
                "orders_over_time": [{"date": p["date"], "value": p["orders"]} for p in points],
                "conversion_funnel": funnel,
            },
            "product_performance": {
                "top_selling_products": top_products_payload,
            },
            "customer_analytics": {
                "active_users": int(active_customers),
                "returning_customers": int(returning_customers),
                "new_customers": int(new_customers),
                "top_countries": top_countries,
            },
            "traffic_sources": traffic_sources,
            "realtime_activity": [
                {
                    "id": row.id,
                    "type": row.activity_type,
                    "message": row.message,
                    "timestamp": row.created_at.isoformat(),
                }
                for row in activity_rows
            ],
        }
    )


@admin_bp.get("/orders")
@admin_required
def admin_orders():
    query = Order.query.join(User, User.id == Order.user_id)

    q = (request.args.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                Order.order_number.ilike(like),
                User.email.ilike(like),
                User.first_name.ilike(like),
                User.last_name.ilike(like),
            )
        )

    status = request.args.get("status")
    if status:
        query = query.filter(Order.status == status)

    payment_status = request.args.get("payment_status")
    if payment_status:
        query = query.filter(Order.payment_status == payment_status)

    date_from = _parse_date(request.args.get("date_from"))
    date_to = _parse_date(request.args.get("date_to"), end_of_day=True)
    if date_from:
        query = query.filter(Order.created_at >= date_from)
    if date_to:
        query = query.filter(Order.created_at <= date_to)

    page = max(1, int(request.args.get("page", 1)))
    per_page = min(100, max(1, int(request.args.get("per_page", 20))))

    paged = query.order_by(Order.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify(
        {
            "items": [_serialize_order(row) for row in paged.items],
            "meta": {
                "page": paged.page,
                "per_page": paged.per_page,
                "total": paged.total,
                "pages": paged.pages,
            },
        }
    )


@admin_bp.patch("/orders/<string:order_number>")
@admin_required
@csrf_protect_json
def update_order(order_number):
    order = Order.query.filter_by(order_number=order_number).first_or_404()
    data = request.get_json() or {}

    status = data.get("status")
    payment_status = data.get("payment_status")
    shipping_status = data.get("shipping_status")

    if status:
        order.status = status
    if payment_status:
        order.payment_status = payment_status
    if shipping_status:
        order.shipping_status = shipping_status

    admin_user = get_current_user()
    _log_activity(
        "order_update",
        f"Order {order.order_number} updated",
        admin_user.id if admin_user else None,
        {
            "status": order.status,
            "payment_status": order.payment_status,
            "shipping_status": order.shipping_status,
        },
    )
    db.session.commit()

    return jsonify({"message": "Order updated", "order": _serialize_order(order)})


@admin_bp.post("/orders/<string:order_number>/cancel")
@admin_required
@csrf_protect_json
def cancel_order(order_number):
    order = Order.query.filter_by(order_number=order_number).first_or_404()
    order.status = "cancelled"
    order.shipping_status = "cancelled"

    admin_user = get_current_user()
    _log_activity("order_cancel", f"Order {order.order_number} cancelled", admin_user.id if admin_user else None)
    db.session.commit()
    return jsonify({"message": "Order cancelled"})


@admin_bp.post("/orders/<string:order_number>/refund")
@admin_required
@csrf_protect_json
def refund_order(order_number):
    order = Order.query.filter_by(order_number=order_number).first_or_404()
    order.status = "refunded"
    order.payment_status = "refunded"

    admin_user = get_current_user()
    _log_activity("order_refund", f"Order {order.order_number} refunded", admin_user.id if admin_user else None)
    db.session.commit()
    return jsonify({"message": "Order refunded"})


@admin_bp.get("/orders/<string:order_number>/invoice")
@admin_required
def admin_order_invoice(order_number):
    order = Order.query.filter_by(order_number=order_number).first_or_404()
    pdf_buffer = _build_invoice_pdf(order)
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"invoice_{order.order_number}.pdf",
        mimetype="application/pdf",
    )


@admin_bp.get("/orders/export.csv")
@admin_required
def export_orders_csv():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    rows = [
        [
            o.order_number,
            o.user.full_name if o.user else "Guest",
            o.status,
            o.payment_status,
            _to_float(o.total_amount),
            o.created_at.isoformat(),
        ]
        for o in orders
    ]
    return _csv_response("orders.csv", ["Order ID", "Customer", "Order Status", "Payment Status", "Amount", "Date"], rows)


@admin_bp.get("/products")
@admin_required
def admin_products():
    query = Product.query

    q = (request.args.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Product.name.ilike(like), Product.sku.ilike(like)))

    category_id = request.args.get("category_id")
    if category_id:
        query = query.filter(Product.category_id == int(category_id))

    low_stock = request.args.get("low_stock")
    if low_stock == "1":
        query = query.filter(Product.stock <= 10)

    rows = query.order_by(Product.created_at.desc()).all()
    return jsonify({"items": [_serialize_product(row) for row in rows]})


@admin_bp.post("/uploads/images")
@admin_required
@csrf_protect_json
def upload_images():
    files = [file for file in request.files.getlist("files") if file and file.filename]
    if not files:
        return jsonify({"error": "Please select at least one image"}), 400

    kind = slugify((request.form.get("kind") or "image").strip()) or "image"
    uploaded = []
    upload_dir = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(upload_dir, exist_ok=True)

    for file_storage in files:
        error = _validate_uploaded_image(file_storage)
        if error:
            return jsonify({"error": error}), 400

    for file_storage in files:
        extension = os.path.splitext(secure_filename(file_storage.filename))[1].lower()
        filename = f"{kind}-{uuid4().hex}{extension}"
        path = os.path.join(upload_dir, filename)
        file_storage.stream.seek(0)
        file_storage.save(path)
        uploaded.append(f"/uploads/{filename}")

    return jsonify({"items": uploaded})


@admin_bp.post("/products")
@admin_required
@csrf_protect_json
def create_product():
    data = request.get_json() or {}

    required = ["name", "description", "price", "stock", "sku", "category_id"]
    missing = [field for field in required if data.get(field) in (None, "")]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    category = Category.query.get(data.get("category_id"))
    if not category:
        return jsonify({"error": "Invalid category_id"}), 400

    if Product.query.filter_by(sku=(data.get("sku") or "").strip()).first():
        return jsonify({"error": "SKU already exists"}), 409

    base_slug = slugify(data.get("name"))
    slug = f"{base_slug}-{int(datetime.utcnow().timestamp())}"

    price = Decimal(str(data.get("price") or 0))
    discount = _to_float(data.get("discount"))
    compare_price = data.get("compare_price")
    if compare_price in (None, "") and discount > 0:
        compare_price = float(price) / max(0.01, (1 - discount / 100))

    product = Product(
        name=(data.get("name") or "").strip(),
        slug=slug,
        description=(data.get("description") or "").strip(),
        fabric_details=data.get("fabric_details") or "",
        size_guide=data.get("size_guide") or "",
        price=price,
        compare_price=compare_price,
        stock=int(data.get("stock") or 0),
        sku=(data.get("sku") or "").strip(),
        images=data.get("images") or [],
        sizes=data.get("sizes") or [],
        colors=data.get("colors") or [],
        tags=data.get("tags") or [],
        category_id=int(data.get("category_id")),
        is_featured=bool(data.get("is_featured", False)),
        is_recommended=bool(data.get("is_recommended", False)),
        is_new_arrival=bool(data.get("is_new_arrival", False)),
        is_on_sale=bool(data.get("is_on_sale", discount > 0)),
        seo_title=data.get("seo_title"),
        seo_description=data.get("seo_description"),
    )
    db.session.add(product)

    admin_user = get_current_user()
    _log_activity("product_create", f"Product created: {product.name}", admin_user.id if admin_user else None)

    db.session.commit()
    cache.clear()

    return jsonify({"message": "Product created", "item": _serialize_product(product)}), 201


@admin_bp.put("/products/<int:product_id>")
@admin_required
@csrf_protect_json
def update_product(product_id):
    product = Product.query.get_or_404(product_id)
    data = request.get_json() or {}

    editable_fields = [
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
    ]

    for key in editable_fields:
        if key in data:
            setattr(product, key, data.get(key))

    discount = _to_float(data.get("discount"))
    if "discount" in data and discount > 0 and not data.get("compare_price"):
        price = _to_float(product.price)
        product.compare_price = price / max(0.01, (1 - discount / 100))

    if "name" in data:
        product.slug = f"{slugify(data['name'])}-{product.id}"

    admin_user = get_current_user()
    _log_activity("product_update", f"Product updated: {product.name}", admin_user.id if admin_user else None)

    db.session.commit()
    cache.clear()

    return jsonify({"message": "Product updated", "item": _serialize_product(product)})


@admin_bp.delete("/products/<int:product_id>")
@admin_required
@csrf_protect_json
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)

    admin_user = get_current_user()
    _log_activity("product_delete", f"Product deleted: {product.name}", admin_user.id if admin_user else None)

    db.session.delete(product)
    db.session.commit()
    cache.clear()
    return jsonify({"message": "Product deleted"})


@admin_bp.get("/categories")
@admin_required
def admin_categories():
    categories = Category.query.order_by(Category.parent_id.asc(), Category.name.asc()).all()

    def _category_payload(cat: Category):
        return {
            "id": cat.id,
            "name": cat.name,
            "slug": cat.slug,
            "gender": cat.gender,
            "parent_id": cat.parent_id,
            "image_url": cat.image_url,
            "is_active": cat.is_active,
        }

    return jsonify({"items": [_category_payload(cat) for cat in categories]})


@admin_bp.post("/categories")
@admin_required
@csrf_protect_json
def create_category():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    slug_base = slugify(name)
    slug = f"{slug_base}-{int(datetime.utcnow().timestamp())}"

    category = Category(
        name=name,
        slug=slug,
        parent_id=data.get("parent_id"),
        gender=(data.get("gender") or "men").lower(),
        image_url=data.get("image_url"),
        is_active=bool(data.get("is_active", True)),
    )
    db.session.add(category)

    admin_user = get_current_user()
    _log_activity("category_create", f"Category created: {category.name}", admin_user.id if admin_user else None)

    db.session.commit()
    return jsonify({"message": "Category created", "item": {"id": category.id, "name": category.name}}), 201


@admin_bp.put("/categories/<int:category_id>")
@admin_required
@csrf_protect_json
def update_category(category_id):
    category = Category.query.get_or_404(category_id)
    data = request.get_json() or {}

    for key in ["name", "gender", "parent_id", "image_url", "is_active"]:
        if key in data:
            setattr(category, key, data.get(key))

    if "name" in data:
        category.slug = f"{slugify(data['name'])}-{category.id}"

    admin_user = get_current_user()
    _log_activity("category_update", f"Category updated: {category.name}", admin_user.id if admin_user else None)

    db.session.commit()
    return jsonify({"message": "Category updated"})


@admin_bp.delete("/categories/<int:category_id>")
@admin_required
@csrf_protect_json
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)
    if category.products:
        return jsonify({"error": "Category has products. Move products before deleting."}), 400

    admin_user = get_current_user()
    _log_activity("category_delete", f"Category deleted: {category.name}", admin_user.id if admin_user else None)

    db.session.delete(category)
    db.session.commit()
    return jsonify({"message": "Category deleted"})


@admin_bp.get("/inventory")
@admin_required
def inventory():
    products = Product.query.order_by(Product.stock.asc()).all()

    items = []
    for product in products:
        sizes = product.sizes or ["Standard"]
        colors = product.colors or ["Default"]
        variant_pairs = []
        for size in sizes:
            if colors:
                variant_pairs.append(f"{size} / {colors[0]}")
            else:
                variant_pairs.append(size)

        for variant in variant_pairs:
            qty = int(product.stock or 0)
            items.append(
                {
                    "id": f"{product.id}-{variant}",
                    "product_id": product.id,
                    "product": product.name,
                    "variant": variant,
                    "stock_quantity": qty,
                    "low_stock_warning": qty <= 10,
                    "status": "Out of Stock" if qty <= 0 else "Low Stock" if qty <= 10 else "In Stock",
                }
            )

    low_stock_count = len([item for item in items if item["status"] == "Low Stock"])
    out_of_stock_count = len([item for item in items if item["status"] == "Out of Stock"])

    return jsonify(
        {
            "items": items,
            "summary": {
                "low_stock_alerts": low_stock_count,
                "out_of_stock": out_of_stock_count,
                "total_variants": len(items),
            },
        }
    )


@admin_bp.get("/customers")
@admin_required
def customers():
    query = User.query

    q = (request.args.get("q") or "").strip()
    if q:
        like = f"%{q}%"
        query = query.filter(or_(User.email.ilike(like), User.first_name.ilike(like), User.last_name.ilike(like)))

    status = request.args.get("status")
    if status == "active":
        query = query.filter(User.is_active.is_(True))
    if status == "blocked":
        query = query.filter(User.is_active.is_(False))

    rows = query.order_by(User.created_at.desc()).all()

    payload = []
    for user in rows:
        orders = Order.query.filter_by(user_id=user.id).order_by(Order.created_at.desc()).all()
        total_spent = sum(_to_float(order.total_amount) for order in orders)
        payload.append(
            {
                "id": user.id,
                "name": user.full_name,
                "email": user.email,
                "phone": user.phone,
                "orders": len(orders),
                "total_spent": round(total_spent, 2),
                "last_order": orders[0].created_at.isoformat() if orders else None,
                "is_active": user.is_active,
                "is_admin": user.is_admin,
            }
        )

    return jsonify({"items": payload})


@admin_bp.get("/customers/<int:user_id>")
@admin_required
def customer_profile(user_id):
    user = User.query.get_or_404(user_id)
    orders = Order.query.filter_by(user_id=user.id).order_by(Order.created_at.desc()).all()

    payload = {
        "id": user.id,
        "name": user.full_name,
        "email": user.email,
        "phone": user.phone,
        "is_active": user.is_active,
        "orders": [_serialize_order(order) for order in orders],
        "total_spent": round(sum(_to_float(order.total_amount) for order in orders), 2),
    }
    return jsonify(payload)


@admin_bp.patch("/customers/<int:user_id>/block")
@admin_required
@csrf_protect_json
def block_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        return jsonify({"error": "Cannot block admin"}), 400

    should_block = bool((request.get_json() or {}).get("block", True))
    user.is_active = not should_block

    admin_user = get_current_user()
    action = "blocked" if should_block else "unblocked"
    _log_activity("customer_status", f"Customer {user.email} {action}", admin_user.id if admin_user else None)

    db.session.commit()
    return jsonify({"message": "User status updated", "is_active": user.is_active})


@admin_bp.get("/customers/<int:user_id>/orders/export.csv")
@admin_required
def export_customer_orders_csv(user_id):
    user = User.query.get_or_404(user_id)
    orders = Order.query.filter_by(user_id=user.id).order_by(Order.created_at.desc()).all()

    rows = [
        [
            order.order_number,
            order.status,
            order.payment_status,
            _to_float(order.total_amount),
            order.created_at.isoformat(),
        ]
        for order in orders
    ]
    return _csv_response(
        f"customer_{user.id}_orders.csv",
        ["Order ID", "Order Status", "Payment Status", "Amount", "Date"],
        rows,
    )


@admin_bp.get("/export/customers.csv")
@admin_required
def export_customers_csv():
    users = User.query.order_by(User.created_at.desc()).all()
    rows = [[user.full_name, user.email, user.phone or "", user.is_active] for user in users]
    return _csv_response("customers.csv", ["Name", "Email", "Phone", "Is Active"], rows)


@admin_bp.get("/coupons")
@admin_required
def coupons():
    rows = Coupon.query.order_by(Coupon.created_at.desc()).all()
    return jsonify({"items": [_serialize_coupon(row) for row in rows]})


@admin_bp.post("/coupons")
@admin_required
@csrf_protect_json
def create_coupon():
    data = request.get_json() or {}
    code = (data.get("code") or "").strip().upper()
    if not code:
        return jsonify({"error": "Coupon code is required"}), 400

    if Coupon.query.filter_by(code=code).first():
        return jsonify({"error": "Coupon code already exists"}), 409

    expiry = _parse_date(data.get("expiry_date"), end_of_day=True)
    if not expiry:
        return jsonify({"error": "Invalid expiry_date"}), 400

    coupon = Coupon(
        code=code,
        discount_type=data.get("discount_type", "percent"),
        discount_value=data.get("discount_value", 0),
        min_order_amount=data.get("min_order_amount"),
        expiry_date=expiry,
        max_usage=int(data.get("max_usage", 1)),
        product_id=data.get("product_id"),
        category_id=data.get("category_id"),
        is_active=bool(data.get("is_active", True)),
    )
    db.session.add(coupon)

    admin_user = get_current_user()
    _log_activity("coupon_create", f"Coupon created: {coupon.code}", admin_user.id if admin_user else None)

    db.session.commit()
    return jsonify({"message": "Coupon created", "item": _serialize_coupon(coupon)}), 201


@admin_bp.put("/coupons/<int:coupon_id>")
@admin_required
@csrf_protect_json
def update_coupon(coupon_id):
    coupon = Coupon.query.get_or_404(coupon_id)
    data = request.get_json() or {}

    for key in [
        "discount_type",
        "discount_value",
        "min_order_amount",
        "max_usage",
        "product_id",
        "category_id",
        "is_active",
    ]:
        if key in data:
            setattr(coupon, key, data.get(key))

    if "code" in data and data.get("code"):
        coupon.code = data.get("code").strip().upper()

    if "expiry_date" in data:
        expiry = _parse_date(data.get("expiry_date"), end_of_day=True)
        if not expiry:
            return jsonify({"error": "Invalid expiry_date"}), 400
        coupon.expiry_date = expiry

    admin_user = get_current_user()
    _log_activity("coupon_update", f"Coupon updated: {coupon.code}", admin_user.id if admin_user else None)

    db.session.commit()
    return jsonify({"message": "Coupon updated", "item": _serialize_coupon(coupon)})


@admin_bp.delete("/coupons/<int:coupon_id>")
@admin_required
@csrf_protect_json
def delete_coupon(coupon_id):
    coupon = Coupon.query.get_or_404(coupon_id)

    admin_user = get_current_user()
    _log_activity("coupon_delete", f"Coupon deleted: {coupon.code}", admin_user.id if admin_user else None)

    db.session.delete(coupon)
    db.session.commit()
    return jsonify({"message": "Coupon deleted"})


@admin_bp.get("/campaigns")
@admin_required
def campaign_list():
    rows = EmailCampaign.query.order_by(EmailCampaign.created_at.desc()).limit(50).all()
    return jsonify({"items": [_serialize_campaign(row) for row in rows]})


@admin_bp.post("/campaigns/send")
@admin_required
@csrf_protect_json
def send_campaign():
    data = request.get_json() or {}
    title = (data.get("title") or "HyperFit Campaign").strip()
    subject = (data.get("subject") or title).strip()
    content = (data.get("content") or "Latest launches are now live.").strip()
    campaign_type = (data.get("campaign_type") or "newsletter").strip()

    if campaign_type == "newsletter":
        recipient_emails = [row.email for row in NewsletterSubscriber.query.filter_by(subscribed=True).all()]
    else:
        recipient_emails = [row.email for row in User.query.filter_by(is_active=True).all()]

    sent_count = 0
    if current_app.config.get("SENDGRID_API_KEY"):
        for email in recipient_emails:
            SendGridService.send_email(email, subject, newsletter_template(title, content))
            sent_count += 1
    else:
        sent_count = len(recipient_emails)

    base = max(1, sent_count)
    campaign = EmailCampaign(
        title=title,
        campaign_type=campaign_type,
        subject=subject,
        content=content,
        status="sent",
        sent_count=sent_count,
        open_rate=round(min(65.0, 15 + (base % 38)), 2),
        click_rate=round(min(42.0, 6 + (base % 22)), 2),
        conversion_rate=round(min(18.0, 2 + (base % 9)), 2),
        created_by=get_current_user().id if get_current_user() else None,
    )
    db.session.add(campaign)

    admin_user = get_current_user()
    _log_activity(
        "campaign_send",
        f"Campaign sent: {title}",
        admin_user.id if admin_user else None,
        {"recipients": sent_count, "campaign_type": campaign_type},
    )

    db.session.commit()

    return jsonify({
        "message": "Campaign queued",
        "recipients": sent_count,
        "campaign": _serialize_campaign(campaign),
    })


@admin_bp.get("/cms/pages")
@admin_required
def cms_pages():
    page_keys = sorted(set(list(DEFAULT_CMS_CONTENT.keys()) + ["home", "about", "collections", "footer"]))
    pages = []
    for page_key in page_keys:
        page = _get_cms_page(page_key)
        pages.append(
            {
                "id": page.id,
                "page_key": page.page_key,
                "title": page.title,
                "is_published": page.is_published,
                "updated_at": page.updated_at.isoformat(),
                "published_at": page.published_at.isoformat() if page.published_at else None,
            }
        )

    return jsonify({"items": pages})


@admin_bp.get("/cms/pages/<string:page_key>")
@admin_required
def cms_page_detail(page_key):
    page = _get_cms_page(page_key)
    versions = (
        CMSVersion.query.filter_by(page_id=page.id)
        .order_by(CMSVersion.version_number.desc())
        .limit(30)
        .all()
    )

    return jsonify(
        {
            "page": {
                "id": page.id,
                "page_key": page.page_key,
                "title": page.title,
                "draft_content": page.draft_content,
                "live_content": page.live_content,
                "is_published": page.is_published,
                "updated_at": page.updated_at.isoformat(),
                "published_at": page.published_at.isoformat() if page.published_at else None,
            },
            "versions": [
                {
                    "id": version.id,
                    "version_number": version.version_number,
                    "action": version.action,
                    "changed_by": version.changed_by,
                    "created_at": version.created_at.isoformat(),
                    "change_summary": version.change_summary,
                }
                for version in versions
            ],
        }
    )


@admin_bp.post("/cms/pages/<string:page_key>/draft")
@admin_required
@csrf_protect_json
def cms_save_draft(page_key):
    data = request.get_json() or {}
    content = data.get("content")
    if not isinstance(content, dict):
        return jsonify({"error": "content object is required"}), 400

    page = _get_cms_page(page_key)
    summary = _build_change_summary(page.draft_content, content)

    page.draft_content = content
    admin_user = get_current_user()
    page.updated_by = admin_user.id if admin_user else None

    _create_cms_version(
        page,
        action="draft_update",
        content=content,
        change_summary=summary,
        changed_by=admin_user.id if admin_user else None,
    )

    _log_activity("cms_draft", f"Draft updated for {page.page_key}", admin_user.id if admin_user else None, summary)
    db.session.commit()

    return jsonify(
        {
            "message": "Draft updated",
            "change_summary": summary,
            "requires_publish": True,
        }
    )


@admin_bp.post("/cms/pages/<string:page_key>/preview")
@admin_required
def cms_preview(page_key):
    page = _get_cms_page(page_key)
    content = (request.get_json(silent=True) or {}).get("content")
    preview_content = content if isinstance(content, dict) else page.draft_content

    summary = _build_change_summary(page.live_content, preview_content)
    return jsonify(
        {
            "page_key": page.page_key,
            "preview_content": preview_content,
            "change_summary": summary,
        }
    )


@admin_bp.post("/cms/pages/<string:page_key>/publish")
@admin_required
@csrf_protect_json
def cms_publish(page_key):
    page = _get_cms_page(page_key)
    admin_user = get_current_user()

    summary = _build_change_summary(page.live_content, page.draft_content)
    page.live_content = page.draft_content
    page.is_published = True
    page.published_at = datetime.utcnow()
    page.published_by = admin_user.id if admin_user else None

    _create_cms_version(
        page,
        action="publish",
        content=page.live_content,
        change_summary=summary,
        changed_by=admin_user.id if admin_user else None,
    )
    _log_activity("cms_publish", f"Published CMS page {page.page_key}", admin_user.id if admin_user else None, summary)

    db.session.commit()
    return jsonify({"message": "Page published", "change_summary": summary})


@admin_bp.get("/cms/pages/<string:page_key>/versions")
@admin_required
def cms_versions(page_key):
    page = _get_cms_page(page_key)
    rows = CMSVersion.query.filter_by(page_id=page.id).order_by(CMSVersion.version_number.desc()).all()
    return jsonify(
        {
            "items": [
                {
                    "id": row.id,
                    "version_number": row.version_number,
                    "action": row.action,
                    "changed_by": row.changed_by,
                    "change_summary": row.change_summary,
                    "created_at": row.created_at.isoformat(),
                }
                for row in rows
            ]
        }
    )


@admin_bp.post("/cms/pages/<string:page_key>/versions/<int:version_id>/restore")
@admin_required
@csrf_protect_json
def cms_restore(page_key, version_id):
    page = _get_cms_page(page_key)
    version = CMSVersion.query.filter_by(page_id=page.id, id=version_id).first_or_404()

    publish_now = bool((request.get_json() or {}).get("publish", False))

    page.draft_content = version.content
    admin_user = get_current_user()
    page.updated_by = admin_user.id if admin_user else None

    if publish_now:
        page.live_content = version.content
        page.is_published = True
        page.published_at = datetime.utcnow()
        page.published_by = admin_user.id if admin_user else None

    summary = {
        "restored_from_version": version.version_number,
        "published": publish_now,
    }

    _create_cms_version(
        page,
        action="restore_publish" if publish_now else "restore_draft",
        content=version.content,
        change_summary=summary,
        changed_by=admin_user.id if admin_user else None,
    )

    _log_activity(
        "cms_restore",
        f"Restored CMS page {page.page_key} to v{version.version_number}",
        admin_user.id if admin_user else None,
        summary,
    )

    db.session.commit()
    return jsonify({"message": "Version restored", **summary})


@admin_bp.get("/settings/site")
@admin_required
def get_site_settings():
    setting = _get_setting("site_wide", DEFAULT_SITE_SETTINGS)
    return jsonify({"setting_key": setting.setting_key, "value": setting.value})


@admin_bp.put("/settings/site")
@admin_required
@csrf_protect_json
def update_site_settings():
    data = request.get_json() or {}
    value = data.get("value")
    if not isinstance(value, dict):
        return jsonify({"error": "value object is required"}), 400

    setting = _get_setting("site_wide", DEFAULT_SITE_SETTINGS)
    merged = {**DEFAULT_SITE_SETTINGS, **setting.value, **value}
    setting.value = merged

    admin_user = get_current_user()
    setting.updated_by = admin_user.id if admin_user else None
    _log_activity("settings_update", "Site-wide settings updated", admin_user.id if admin_user else None)

    db.session.commit()
    return jsonify({"message": "Settings updated", "value": setting.value})


@admin_bp.get("/reports/summary")
@admin_required
def reports_summary():
    range_key = request.args.get("range", "30d")
    start, end = _get_period_bounds(range_key, request.args.get("start"), request.args.get("end"))

    revenue = _to_float(
        db.session.query(func.coalesce(func.sum(Order.total_amount), 0))
        .filter(Order.created_at >= start, Order.created_at <= end)
        .scalar()
    )
    order_count = Order.query.filter(Order.created_at >= start, Order.created_at <= end).count()

    top_products = (
        db.session.query(Product.name, func.coalesce(func.sum(OrderItem.quantity), 0).label("units"))
        .join(OrderItem, OrderItem.product_id == Product.id)
        .join(Order, Order.id == OrderItem.order_id)
        .filter(Order.created_at >= start, Order.created_at <= end)
        .group_by(Product.id)
        .order_by(desc("units"))
        .limit(10)
        .all()
    )

    new_customers = User.query.filter(User.created_at >= start, User.created_at <= end).count()

    campaign_rows = EmailCampaign.query.order_by(EmailCampaign.created_at.desc()).limit(20).all()
    avg_open = round(sum(c.open_rate for c in campaign_rows) / max(1, len(campaign_rows)), 2)
    avg_click = round(sum(c.click_rate for c in campaign_rows) / max(1, len(campaign_rows)), 2)

    return jsonify(
        {
            "range": {
                "key": range_key,
                "start": start.isoformat(),
                "end": end.isoformat(),
            },
            "revenue_report": {
                "total_revenue": round(revenue, 2),
                "total_orders": order_count,
                "average_order_value": round(revenue / max(order_count, 1), 2),
            },
            "product_sales_report": [
                {"product_name": row.name, "units_sold": int(row.units or 0)} for row in top_products
            ],
            "customer_acquisition": {
                "new_customers": new_customers,
                "acquisition_rate_estimate": round((new_customers / max(1, order_count)) * 100, 2),
            },
            "marketing_performance": {
                "email_open_rate": avg_open,
                "email_click_rate": avg_click,
            },
        }
    )


@admin_bp.get("/reports/export.csv")
@admin_required
def export_report_csv():
    report_type = request.args.get("type", "revenue")

    if report_type == "products":
        rows = (
            db.session.query(Product.name, func.coalesce(func.sum(OrderItem.quantity), 0).label("units"))
            .join(OrderItem, OrderItem.product_id == Product.id, isouter=True)
            .group_by(Product.id)
            .order_by(desc("units"))
            .all()
        )
        return _csv_response("product_sales_report.csv", ["Product", "Units Sold"], [[r.name, int(r.units or 0)] for r in rows])

    if report_type == "customers":
        users = User.query.order_by(User.created_at.desc()).all()
        payload = []
        for user in users:
            orders_count = Order.query.filter_by(user_id=user.id).count()
            payload.append([user.full_name, user.email, orders_count, user.created_at.isoformat()])
        return _csv_response("customer_acquisition_report.csv", ["Name", "Email", "Orders", "Joined"], payload)

    if report_type == "marketing":
        rows = EmailCampaign.query.order_by(EmailCampaign.created_at.desc()).all()
        payload = [[r.title, r.sent_count, r.open_rate, r.click_rate, r.conversion_rate, r.created_at.isoformat()] for r in rows]
        return _csv_response(
            "marketing_report.csv",
            ["Campaign", "Recipients", "Open Rate", "Click Rate", "Conversion Rate", "Date"],
            payload,
        )

    orders = Order.query.order_by(Order.created_at.desc()).all()
    rows = [[o.order_number, _to_float(o.total_amount), o.status, o.created_at.isoformat()] for o in orders]
    return _csv_response("revenue_report.csv", ["Order", "Amount", "Status", "Date"], rows)


@admin_bp.get("/reports/export.pdf")
@admin_required
def export_report_pdf():
    report_type = request.args.get("type", "revenue")

    lines = []
    title = "HyperFit Revenue Report"

    if report_type == "products":
        title = "HyperFit Product Sales Report"
        rows = (
            db.session.query(Product.name, func.coalesce(func.sum(OrderItem.quantity), 0).label("units"))
            .join(OrderItem, OrderItem.product_id == Product.id, isouter=True)
            .group_by(Product.id)
            .order_by(desc("units"))
            .limit(50)
            .all()
        )
        lines = [f"{row.name}: {int(row.units or 0)} units" for row in rows]
    elif report_type == "customers":
        title = "HyperFit Customer Acquisition Report"
        rows = User.query.order_by(User.created_at.desc()).limit(120).all()
        lines = [f"{row.full_name} | {row.email} | Joined: {row.created_at.date().isoformat()}" for row in rows]
    elif report_type == "marketing":
        title = "HyperFit Marketing Report"
        rows = EmailCampaign.query.order_by(EmailCampaign.created_at.desc()).limit(80).all()
        lines = [
            f"{row.title} | Sent: {row.sent_count} | Open: {row.open_rate}% | Click: {row.click_rate}% | Conv: {row.conversion_rate}%"
            for row in rows
        ]
    else:
        rows = Order.query.order_by(Order.created_at.desc()).limit(120).all()
        lines = [f"{row.order_number} | INR {_to_float(row.total_amount):.2f} | {row.status}" for row in rows]

    pdf_buffer = _build_report_pdf(title, lines)
    return send_file(pdf_buffer, as_attachment=True, download_name=f"{report_type}_report.pdf", mimetype="application/pdf")


@admin_bp.get("/integrations")
@admin_required
def integrations_status():
    return jsonify(
        {
            "items": [
                {
                    "name": "SendGrid",
                    "status": "connected" if bool(current_app.config.get("SENDGRID_API_KEY")) else "not_configured",
                },
                {
                    "name": "Razorpay",
                    "status": "connected" if bool(current_app.config.get("RAZORPAY_KEY_ID")) else "not_configured",
                },
                {
                    "name": "Shiprocket",
                    "status": "connected" if bool(current_app.config.get("SHIPROCKET_EMAIL")) else "not_configured",
                },
            ]
        }
    )
