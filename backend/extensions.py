from flask_bcrypt import Bcrypt
from flask_caching import Cache
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect


db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
jwt = JWTManager()
bcrypt = Bcrypt()
csrf = CSRFProtect()
cache = Cache()
limiter = Limiter(key_func=get_remote_address)


def init_extensions(app):
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    cache.init_app(app)
    limiter.init_app(app)
    CORS(
        app,
        resources={r"/api/*": {"origins": app.config.get("FRONTEND_URL", "*")}},
        supports_credentials=True,
    )
