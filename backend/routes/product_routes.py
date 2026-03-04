from flask import Blueprint, jsonify, request
from sqlalchemy import or_

from extensions import cache, db
from models.category import Category
from models.product import Product
from models.review import Review
from utils.auth_utils import get_current_user, jwt_required_user
from utils.helpers import safe_float, safe_int
from utils.security import csrf_protect_json


product_bp = Blueprint("product_routes", __name__, url_prefix="/api/products")


def serialize_product(product: Product):
    return {
        "id": product.id,
        "name": product.name,
        "slug": product.slug,
        "description": product.description,
        "fabric_details": product.fabric_details,
        "size_guide": product.size_guide,
        "price": float(product.price),
        "compare_price": float(product.compare_price) if product.compare_price else None,
        "stock": product.stock,
        "sku": product.sku,
        "images": product.images,
        "sizes": product.sizes,
        "colors": product.colors,
        "tags": product.tags,
        "rating_avg": product.rating_avg,
        "review_count": product.review_count,
        "is_featured": product.is_featured,
        "is_recommended": product.is_recommended,
        "is_new_arrival": product.is_new_arrival,
        "is_on_sale": product.is_on_sale,
        "seo_title": product.seo_title,
        "seo_description": product.seo_description,
        "category": product.category.name if product.category else None,
        "category_id": product.category_id,
    }


@product_bp.get("")
@cache.cached(timeout=120, query_string=True)
def list_products():
    page = safe_int(request.args.get("page"), 1)
    per_page = min(24, safe_int(request.args.get("per_page"), 12))

    search = request.args.get("search")
    category = request.args.get("category")
    color = request.args.get("color")
    size = request.args.get("size")
    min_price = safe_float(request.args.get("min_price"), 0)
    max_price = safe_float(request.args.get("max_price"), 999999)
    rating = safe_float(request.args.get("rating"), 0)
    sort = request.args.get("sort", "new")

    query = Product.query.filter_by(is_active=True)

    if search:
        search_like = f"%{search.lower()}%"
        query = query.filter(or_(Product.name.ilike(search_like), Product.description.ilike(search_like)))
    if category:
        query = query.join(Category).filter(Category.slug == category)
    if color:
        query = query.filter(Product.colors.contains([color]))
    if size:
        query = query.filter(Product.sizes.contains([size]))

    query = query.filter(Product.price >= min_price, Product.price <= max_price, Product.rating_avg >= rating)

    if sort == "price_asc":
        query = query.order_by(Product.price.asc())
    elif sort == "price_desc":
        query = query.order_by(Product.price.desc())
    elif sort == "best_selling":
        query = query.order_by(Product.review_count.desc())
    else:
        query = query.order_by(Product.created_at.desc())

    paged = query.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify(
        {
            "items": [serialize_product(item) for item in paged.items],
            "meta": {
                "page": paged.page,
                "per_page": paged.per_page,
                "pages": paged.pages,
                "total": paged.total,
            },
        }
    )


@product_bp.get("/recommended")
@cache.cached(timeout=180)
def recommended_products():
    products = Product.query.filter_by(is_active=True, is_recommended=True).limit(6).all()
    return jsonify({"items": [serialize_product(item) for item in products]})


@product_bp.get("/featured")
@cache.cached(timeout=180)
def featured_products():
    products = Product.query.filter_by(is_active=True, is_featured=True).limit(6).all()
    return jsonify({"items": [serialize_product(item) for item in products]})


@product_bp.get("/categories")
@cache.cached(timeout=300)
def categories():
    rows = Category.query.filter_by(is_active=True).order_by(Category.name.asc()).all()
    return jsonify(
        {
            "items": [
                {
                    "id": c.id,
                    "name": c.name,
                    "slug": c.slug,
                    "gender": c.gender,
                    "image_url": c.image_url,
                    "parent_id": c.parent_id,
                }
                for c in rows
            ]
        }
    )


@product_bp.get("/<string:slug>")
@cache.cached(timeout=180)
def product_detail(slug):
    product = Product.query.filter_by(slug=slug, is_active=True).first_or_404()
    related = Product.query.filter(Product.category_id == product.category_id, Product.id != product.id).limit(8).all()

    return jsonify(
        {
            "product": serialize_product(product),
            "reviews": [
                {
                    "id": review.id,
                    "user": review.user.full_name,
                    "rating": review.rating,
                    "title": review.title,
                    "comment": review.comment,
                    "created_at": review.created_at.isoformat(),
                }
                for review in product.reviews
            ],
            "related": [serialize_product(item) for item in related],
        }
    )


@product_bp.post("/<string:slug>/reviews")
@jwt_required_user
@csrf_protect_json
def add_review(slug):
    product = Product.query.filter_by(slug=slug, is_active=True).first_or_404()
    user = get_current_user()
    data = request.get_json() or {}

    rating = safe_int(data.get("rating"), 0)
    if rating < 1 or rating > 5:
        return jsonify({"error": "Rating must be 1-5"}), 400

    existing = Review.query.filter_by(user_id=user.id, product_id=product.id).first()
    if existing:
        existing.rating = rating
        existing.title = data.get("title")
        existing.comment = data.get("comment")
    else:
        db.session.add(
            Review(
                user_id=user.id,
                product_id=product.id,
                rating=rating,
                title=data.get("title"),
                comment=data.get("comment"),
            )
        )

    db.session.flush()
    reviews = Review.query.filter_by(product_id=product.id).all()
    product.review_count = len(reviews)
    product.rating_avg = sum(r.rating for r in reviews) / max(1, len(reviews))
    db.session.commit()
    cache.clear()

    return jsonify({"message": "Review saved"}), 201
