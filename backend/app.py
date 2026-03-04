import os
import shutil
import subprocess

from flask import Flask, jsonify, request, send_from_directory
from sqlalchemy import create_engine, text

from config import CONFIG_MAP
from extensions import db, init_extensions, login_manager
from models import Category, User
from routes.admin_routes import admin_bp
from routes.auth_routes import auth_bp
from routes.cart_routes import cart_bp
from routes.order_routes import order_bp
from routes.payment_routes import payment_bp
from routes.product_routes import product_bp
from routes.shipping_routes import shipping_bp
from routes.user_routes import user_bp


def _project_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _frontend_dir() -> str:
    return os.path.join(_project_root(), "frontend")


def _frontend_dist_dir() -> str:
    return os.path.join(_frontend_dir(), "dist")


def _frontend_index_path() -> str:
    return os.path.join(_frontend_dist_dir(), "index.html")


def _fallback_sqlite_uri() -> str:
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    return f"sqlite:///{os.path.join(backend_dir, 'hyperfit_local.db')}"


def _database_reachable(uri: str) -> bool:
    try:
        engine = create_engine(uri)
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def _configure_database_uri(app: Flask):
    uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if uri and _database_reachable(uri):
        return
    fallback_uri = _fallback_sqlite_uri()
    app.logger.warning("Primary database is unreachable. Falling back to %s", fallback_uri)
    app.config["SQLALCHEMY_DATABASE_URI"] = fallback_uri


def _ensure_frontend_build(app: Flask):
    if os.path.isfile(_frontend_index_path()):
        return

    if os.getenv("AUTO_BUILD_FRONTEND", "1") == "0":
        app.logger.warning("AUTO_BUILD_FRONTEND disabled. Frontend dist not found.")
        return

    frontend_dir = _frontend_dir()
    if not os.path.isfile(os.path.join(frontend_dir, "package.json")):
        app.logger.warning("Frontend package.json not found at %s", frontend_dir)
        return

    npm = shutil.which("npm")
    if not npm:
        app.logger.warning("npm not found. Cannot auto-build frontend.")
        return

    app.logger.info("Frontend dist missing. Running npm run build...")
    try:
        subprocess.run([npm, "run", "build"], cwd=frontend_dir, check=True, timeout=300)
    except Exception as exc:
        app.logger.warning("Auto build failed: %s", exc)


def _serve_spa_index_if_available():
    index_path = _frontend_index_path()
    if os.path.isfile(index_path):
        return send_from_directory(_frontend_dist_dir(), "index.html")
    return jsonify(
        {
            "message": "Frontend build not found.",
            "hint": "Run: cd frontend && npm install && npm run build",
        }
    ), 503


def create_app(env: str | None = None):
    app = Flask(__name__, static_folder=_frontend_dist_dir(), static_url_path="")
    config_name = env or os.getenv("FLASK_ENV", "development")
    app.config.from_object(CONFIG_MAP.get(config_name, CONFIG_MAP["development"]))
    app.config["WTF_CSRF_CHECK_DEFAULT"] = False

    _configure_database_uri(app)
    _ensure_frontend_build(app)

    init_extensions(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(product_bp)
    app.register_blueprint(cart_bp)
    app.register_blueprint(order_bp)
    app.register_blueprint(payment_bp)
    app.register_blueprint(shipping_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)

    with app.app_context():
        try:
            db.create_all()
            _ensure_default_admin_and_categories()
        except Exception as exc:
            app.logger.error("Database bootstrap failed: %s", exc)

    register_core_routes(app)
    return app


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def _ensure_default_admin_and_categories():
    admin_email = os.getenv("ADMIN_EMAIL", "admin@hyperfit.com")
    admin_password = os.getenv("ADMIN_PASSWORD", "Admin@123")

    admin = User.query.filter_by(email=admin_email).first()
    if not admin:
        admin = User(
            first_name="Hyper",
            last_name="Admin",
            email=admin_email,
            is_admin=True,
            email_verified=True,
            phone_verified=True,
            is_active=True,
        )
        admin.set_password(admin_password)
        db.session.add(admin)
    else:
        admin.is_admin = True
        admin.is_active = True

    if Category.query.count() == 0:
        rows = [
            ("Men", "men", "men"),
            ("Women", "women", "women"),
            ("T-Shirts", "t-shirts", "men"),
            ("Compression", "compression", "men"),
            ("Pants", "pants", "men"),
            ("Shorts", "shorts", "men"),
            ("Sports Bra", "sports-bra", "women"),
            ("Leggings", "leggings", "women"),
            ("Women T-Shirts", "women-t-shirts", "women"),
        ]
        for name, slug, gender in rows:
            db.session.add(Category(name=name, slug=slug, gender=gender))

    db.session.commit()


def register_core_routes(app: Flask):
    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "service": "hyperfit-api"})

    @app.get("/api/seo/sitemap")
    def sitemap_urls():
        urls = [
            {"loc": "/", "priority": "1.0"},
            {"loc": "/shop", "priority": "0.9"},
            {"loc": "/cart", "priority": "0.8"},
        ]
        return jsonify({"urls": urls})

    @app.get("/")
    def root_spa():
        return _serve_spa_index_if_available()

    @app.get("/<path:path>")
    def spa_files(path):
        if path.startswith("api/"):
            return jsonify({"error": "Not found"}), 404

        file_path = os.path.join(_frontend_dist_dir(), path)
        if os.path.isfile(file_path):
            return send_from_directory(_frontend_dist_dir(), path)

        return _serve_spa_index_if_available()

    @app.errorhandler(404)
    def not_found(_error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not found"}), 404
        return _serve_spa_index_if_available()

    @app.errorhandler(429)
    def too_many(_error):
        return jsonify({"error": "Too many requests"}), 429

    @app.errorhandler(500)
    def server_error(_error):
        return jsonify({"error": "Internal server error"}), 500


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
