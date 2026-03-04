from datetime import datetime
import re


def slugify(value: str) -> str:
    value = (value or "").strip().lower()
    value = re.sub(r"[^a-z0-9\s-]", "", value)
    return re.sub(r"[\s-]+", "-", value).strip("-")


def now_iso() -> str:
    return datetime.utcnow().isoformat()


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def paginated_response(query, page: int, per_page: int):
    result = query.paginate(page=page, per_page=per_page, error_out=False)
    return {
        "items": result.items,
        "meta": {
            "page": result.page,
            "per_page": result.per_page,
            "pages": result.pages,
            "total": result.total,
        },
    }
