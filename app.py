from flask import Flask, render_template, redirect, flash, request, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, Newsletter,Product, User, OTP, Order
import random
from datetime import datetime, timezone, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = "newsletter-secret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

db.init_app(app)

# ---------------- LOGIN MANAGER SETUP ----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

# ---------------- REGISTER ROUTE ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        gender = request.form["gender"]
        address = request.form["address"]
        phone = request.form["phone"]
        email = request.form["email"]
        password = request.form["password"]
        confirm = request.form["confirm_password"]

        if password != confirm:
            flash("Passwords do not match")
            return redirect("/register")

        # Prevent duplicate email / phone
        existing_user = User.query.filter(
            (User.email == email) | (User.phone == phone)
        ).first()

        if existing_user:
            flash("Email or phone already registered")
            return redirect("/register")

        user = User(
            name=name,
            gender=gender,
            address=address,
            phone=phone,
            email=email,
            password=generate_password_hash(password)
        )

        db.session.add(user)
        db.session.commit()

        flash("Account created successfully. Please verify your email.")
        return redirect("/login")

    return render_template("auth/register.html")


# ---------------- SEND OTP ROUTE ----------------
def generate_otp():
    return str(random.randint(100000, 999999))

def send_email_otp(user):
    otp = generate_otp()

    record = OTP(
        user_id=user.id,
        otp_code=otp,
        otp_type="email",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
    )

    db.session.add(record)
    db.session.commit()

    print(f"EMAIL OTP for {user.email}: {otp}")  # replace with real email later

def send_phone_otp(user):
    otp = generate_otp()

    record = OTP(
        user_id=user.id,
        otp_code=otp,
        otp_type="phone",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)
    )

    db.session.add(record)
    db.session.commit()

    print(f"PHONE OTP for {user.phone}: {otp}")  # replace with SMS API later

    db.session.add(user)
    db.session.commit()

# ---------------- VERIFY OTP ROUTE ----------------
@app.route("/verify-otp/<int:user_id>/<otp_type>", methods=["GET", "POST"])
def verify_otp(user_id, otp_type):
    """
    otp_type: 'email' or 'phone'
    """

    if otp_type not in ["email", "phone"]:
        flash("Invalid verification type")
        return redirect("/login")

    if request.method == "POST":
        entered_otp = request.form.get("otp")

        otp_record = OTP.query.filter_by(
            user_id=user_id,
            otp_type=otp_type,
            otp_code=entered_otp
        ).first()

        if not otp_record:
            flash("Invalid OTP")
            return redirect(request.url)

        # expiry check (timezone-aware)
        if otp_record.expires_at < datetime.now(timezone.utc):
            flash("OTP expired. Please request again.")
            db.session.delete(otp_record)
            db.session.commit()
            return redirect("/login")

        user = db.session.get(User, user_id)

        if otp_type == "email":
            user.email_verified = True
        elif otp_type == "phone":
            user.phone_verified = True

        db.session.delete(otp_record)
        db.session.commit()

        # Decide next step
        if user.email_verified and user.phone_verified:
            flash("Account verified successfully. Please login.")
            return redirect("/login")
        else:
            # If email verified first, go to phone verification
            next_type = "phone" if otp_type == "email" else "email"
            return redirect(url_for("verify_otp", user_id=user_id, otp_type=next_type))
    
    send_email_otp(user)
    send_phone_otp(user)

    return redirect(
        url_for("verify_otp", user_id=user.id, otp_type="email")
    )

    #return render_template("auth/verify_otp.html", otp_type=otp_type)



# ---------------- LOGIN ROUTE ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        # 1️⃣ User does not exist
        if not user:
            flash("Invalid email or password")
            return redirect("/login")

        if not user.is_active:
            flash("Your account has been blocked by admin")
            return redirect("/login")

        # 2️⃣ Password incorrect
        if not check_password_hash(user.password, password):
            flash("Invalid email or password")
            return redirect("/login")

        # 3️⃣ Email / Phone not verified
        #if not user.email_verified or not user.phone_verified:
        #    flash("Please verify your email and phone number first")
        #    return redirect("/login")

        # 4️⃣ All good → login
        login_user(user)
        return redirect("/")
    

    return render_template("auth/login.html")


# ---------------- FORGOT PASSWORD ROUTE ----------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        if user:
            token = str(random.randint(100000, 999999))
            db.session.add(OTP(contact=user.email, code=token))
            db.session.commit()
            print("Reset token:", token)
            return redirect(url_for("reset_password", email=user.email))
    return render_template("auth/forgot_pass.html")


@app.route("/reset-password/<email>", methods=["GET", "POST"])
def reset_password(email):
    if request.method == "POST":
        otp = OTP.query.filter_by(contact=email, code=request.form["otp"]).first()
        if otp:
            user = User.query.filter_by(email=email).first()
            user.password = generate_password_hash(request.form["password"])
            db.session.delete(otp)
            db.session.commit()
            flash("Password updated")
            return redirect("/login")

    return render_template("auth/reset_pass.html")

# ---------------- USER PROFILE ROUTE ----------------
@app.route("/account")
@login_required
def account():
    return render_template("user/account.html", user=current_user)

# ---------------- UPDATE PROFILE ROUTE ----------------
@app.route("/account/edit", methods=["POST"])
@login_required
def edit_profile():
    current_user.name = request.form["name"]
    current_user.gender = request.form["gender"]
    current_user.address = request.form["address"]

    db.session.commit()
    flash("Profile updated successfully")
    return redirect("/account")

# ---------------- CHANGE PASSWORD ROUTE ----------------
@app.route("/account/change-password", methods=["POST"])
@login_required
def change_password():
    current = request.form["current_password"]
    new = request.form["new_password"]
    confirm = request.form["confirm_password"]

    if not check_password_hash(current_user.password, current):
        flash("Current password is incorrect")
        return redirect("/account")

    if new != confirm:
        flash("New passwords do not match")
        return redirect("/account")

    current_user.password = generate_password_hash(new)
    db.session.commit()

    flash("Password changed successfully")
    return redirect("/account")

# ---------------- LOGOUT ROUTE ----------------
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")
app.permanent_session_lifetime = timedelta(minutes=30)  # Session timeout after 30 minutes of inactivity

@app.after_request                                      # Add security headers to prevent caching
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    return response


# ---------------- HOME ROUTE ----------------
@app.route("/")
def home():
    products = Product.query.filter_by(is_active=True).all()

    # Group products by category + sub-category
    catalog = {
        "Men": {
            "T-Shirts": [],
            "Joggers": [],
            "Stringers": [],
            "Hoodies": []
        },
        "Women": {
            "Sports Bra": [],
            "Leggings": [],
            "Tops": [],
            "Hoodies": []
        },
        "Accessories": []
    }

    for product in products:
        if product.category == "Men":
            if product.sub_category in catalog["Men"]:
                catalog["Men"][product.sub_category].append(product)

        elif product.category == "Women":
            if product.sub_category in catalog["Women"]:
                catalog["Women"][product.sub_category].append(product)

        elif product.category == "Accessories":
            catalog["Accessories"].append(product)

    return render_template("home.html", catalog=catalog)

# ---------------- NEWSLETTER ROUTE ----------------
@app.route("/subscribe", methods=["POST"])
def subscribe():
    email = request.form.get("email")

    if not email:
        flash("Email is required", "error")
        return redirect("/")

    existing = Newsletter.query.filter_by(email=email).first()
    if existing:
        flash("You are already subscribed!", "info")
        return redirect("/")

    subscriber = Newsletter(email=email)
    db.session.add(subscriber)
    db.session.commit()

    flash("Subscribed successfully!", "success")
    return redirect("/")

# ---------------- SEARCH ROUTE ----------------
@app.route("/search")
def search():
    query = request.args.get("q")

    if not query:
        return render_template("search_results.html", products=[], query=query)

    results = Product.query.filter(
        Product.name.ilike(f"%{query}%")
    ).all()

    return render_template(
        "search_results.html",
        products=results,
        query=query
    )

# ---------------- ADMIN USER ----------------
def create_admin():
    with app.app_context():

        if not User.query.filter_by(email="admin@site.com").first():
            admin = User(
                name="Admin",
                email="admin@site.com",
                phone="9999999999",
                gender="Other",
                address="Admin Office",
                password=generate_password_hash("admin123"),
                email_verified=True,
                phone_verified=True,
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
create_admin()

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=request.form["email"]).first()

        if user and user.is_admin and check_password_hash(user.password, request.form["password"]):
            logout_user()
            login_user(user)
            return redirect("/admin/dashboard")

        flash("Invalid admin credentials")
    return render_template("admin/login.html")


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    verified_users = User.query.filter_by(
        email_verified=True,
        phone_verified=True
    ).count()
    blocked_users = User.query.filter_by(is_active=False).count()

    today = datetime.now(timezone.utc)
    week_ago = today - timedelta(days=7)

    total_orders = Order.query.count()
    total_returns = Order.query.filter_by(status="returned").count()

    total_income = db.session.query(
        func.sum(Order.total_amount)
    ).filter(Order.status == "delivered").scalar() or 0

    weekly_income = db.session.query(
        func.sum(Order.total_amount)
    ).filter(
        Order.status == "delivered",
        Order.created_at >= week_ago
    ).scalar() or 0

    # Revenue per day (last 7 days)
    revenue_data = (
        db.session.query(
            func.date(Order.created_at),
            func.sum(Order.total_amount)
        )
        .filter(
            Order.status == "delivered",
            Order.created_at >= week_ago
        )
        .group_by(func.date(Order.created_at))
        .all()
    )

    labels = [str(r[0]) for r in revenue_data]
    values = [float(r[1]) for r in revenue_data]

    return render_template(
        "admin/dashboard.html",
        total_users=total_users,
        verified_users=verified_users,
        blocked_users=blocked_users,
        total_orders=total_orders,
        total_returns=total_returns,
        total_income=total_income,
        weekly_income=weekly_income,
        labels=labels,
        values=values
    )

# ---------------- ADMIN USERS ROUTE ----------------
@app.route("/admin/users")
@admin_required
def admin_users():
    users = User.query.filter_by(is_admin=False).all()
    return render_template("admin/user.html", users=users)


@app.route("/admin/toggle-user/<int:user_id>")
@admin_required
def toggle_user(user_id):
    user = db.session.get(User, user_id)
    user.is_active = not user.is_active
    db.session.commit()
    return redirect("/admin/users")

# ---------------- PRODUCTS ROUTE ----------------
# VIEW ALL PRODUCTS
@app.route("/admin/products")
@admin_required
def admin_products():
    products = Product.query.all()
    return render_template("admin/products.html", products=products)

def safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

# ADD PRODUCT
@app.route("/admin/products/add", methods=["GET", "POST"])
@admin_required
def add_product():
    if request.method == "POST":
        tags = request.form.getlist("tags")
        category = request.form.get("category")
        sub_category = request.form.get("sub_category")
        discount_percent = request.form.get("discount_percent", 0)
        discount_percent = safe_float(discount_percent) if discount_percent else 0
        price=safe_float(request.form["price"])
        discounted_price = None
        if "Sale" in tags:
            discounted_price = price - (price * discount_percent / 100)
        product = Product(
            name=request.form["name"],
            category=category,
            sub_category=sub_category,
            tags=",".join(tags),
            discount_percent=discount_percent,
            discounted_price=discounted_price,
            price=price,
            description=request.form["description"],
            image_filename=request.form["image_filename"]
        )
        db.session.add(product)
        db.session.commit()
        return redirect("/admin/products")

    return render_template("admin/product_form.html", action="Add")


# EDIT PRODUCT
@app.route("/admin/products/edit/<int:product_id>", methods=["GET", "POST"])
@admin_required
def edit_product(product_id):
    product = db.session.get(Product, product_id)

    if request.method == "POST":
        product.name = request.form["name"]
        product.category = request.form["category"]
        product.sub_category = request.form["sub_category"]
        product.tags = ",".join(request.form.getlist("tags"))
        product.price = safe_float(request.form["price"])
        product.discount_percent = safe_float(request.form.get("discount_percent", 0))
        if "Sale" in request.form.getlist("tags"):
            product.discounted_price = product.price - (product.price * product.discount_percent / 100)
        product.description = request.form["description"]
        product.image_filename = request.form["image_filename"]
        db.session.commit()
        return redirect("/admin/products")

    return render_template(
        "admin/product_form.html",
        action="Edit",
        product=product
    )


# DELETE PRODUCT
@app.route("/admin/products/delete/<int:product_id>")
@admin_required
def delete_product(product_id):
    product = db.session.get(Product, product_id)
    db.session.delete(product)
    db.session.commit()
    return redirect("/admin/products")


# TOGGLE PRODUCT STATUS
@app.route("/admin/products/toggle/<int:product_id>")
@admin_required
def toggle_product(product_id):
    product = db.session.get(Product, product_id)
    product.is_active = not product.is_active
    db.session.commit()
    return redirect("/admin/products")

# ---------------- SHOP ROUTE ----------------
@app.route("/shop")
def shop():
    category = request.args.get("category")
    gender = request.args.get("gender")
    sub = request.args.get("sub")

    query = Product.query.filter_by(is_active=True)

    if gender:
        query = query.filter_by(primary_category=gender)

    if sub:
        query = query.filter_by(sub_category=sub)

    products = query.all()

    return render_template("shop.html", products=products, category=category)


# ---------------- PRODUCT DETAIL ROUTE ----------------
@app.route("/product/<int:product_id>")
def product_detail(product_id):
    product = Product.query.filter_by(id=product_id, is_active=True).first_or_404()
    return render_template("product_detail.html", product=product)



# ---------------- DEBUG ROUTE ----------------

@app.route("/__debug__")
def debug():
    return "THIS FILE IS RUNNING"

# ---------------- RUN THE APP ----------------
if __name__ == "__main__":    #---------------- Always be at the end of the file ----------------
    app.run(debug=True)