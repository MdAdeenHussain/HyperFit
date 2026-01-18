from flask import Flask, render_template, redirect, flash, request, url_for, session, current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, case
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, Newsletter,Product, User, OTP, Order, OrderItem, CartItem, PasswordResetToken
import random, os, razorpay
from datetime import datetime, timezone, timedelta
from functools import wraps
from utils.invoice import generate_invoice
from utils.email import send_reset_email
from utils.otp import generate_otp, create_otp
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from twilio.rest import Client


app = Flask(__name__)
app.secret_key = "newsletter-secret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

razorpay_client = razorpay.Client(                                 # Razorpay API key
    auth=("YOUR_KEY_ID", "YOUR_KEY_SECRET")
)

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")                   # E-mail API
FROM_EMAIL = "no-reply@hyperfit.com"                               # email ID

TWILIO_SID = "YOUR_TWILIO_SID"
TWILIO_AUTH_TOKEN = "YOUR_TWILIO_AUTH_TOKEN"
TWILIO_PHONE = "+1XXXXXXXXXX"

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

        email_verified = OTP.query.filter_by(
            contact=email, otp_type="email", verified=True
        ).first()

        phone_verified = OTP.query.filter_by(
            contact=phone, otp_type="phone", verified=True
        ).first()

        if not email_verified or not phone_verified:
            flash("Please verify email and phone number first", "error")
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
            password=generate_password_hash(password),
            email_verified=True,
            phone_verified=True
        )

        db.session.add(user)
        db.session.commit()

        send_email_otp(user)
        send_phone_otp(user)

        flash("Account created successfully. Please verify your email.")
        return redirect("/login")

    return render_template("auth/register.html")


# ---------------- SEND OTP ROUTE ----------------
def send_email_otp(email):
    otp = create_otp(email, "email")

    message = Mail(
        from_email=current_app.config["FROM_EMAIL"],
        to_emails=email,
        subject="HyperFit Email Verification OTP",
        html_content=f"<h3>Your OTP: {otp}</h3><p>Valid for 5 minutes.</p>"
    )

    sg = SendGridAPIClient(current_app.config["SENDGRID_API_KEY"])
    sg.send(message)

def send_phone_otp(user):
    otp = generate_otp()

    record = OTP(
        user_id=user.id,
        otp_code=otp,
        otp_type="phone",
        expires_at=datetime.utcnow() + timedelta(minutes=10)
    )
    db.session.add(record)
    db.session.commit()

    client = Client(
        current_app.config["TWILIO_SID"],
        current_app.config["TWILIO_AUTH_TOKEN"]
    )

    client.messages.create(
        body=f"Your HyperFit OTP is {otp}",
        from_=current_app.config["TWILIO_PHONE"],
        to=user.phone
    )

@app.route("/send-otp", methods=["POST"])
def send_otp():
    contact = request.json.get("contact")
    otp_type = request.json.get("type")

    if otp_type == "email":
        send_email_otp(contact)
    elif otp_type == "phone":
        send_phone_otp(contact)
    else:
        return {"success": False}, 400

    return {"success": True}

# ---------------- VERIFY OTP ROUTE ----------------
@app.route("/verify-otp/<int:user_id>/<otp_type>", methods=["GET", "POST"])
@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    contact = request.json.get("contact")
    otp = request.json.get("otp")
    otp_type = request.json.get("type")

    record = OTP.query.filter_by(
        contact=contact,
        otp_code=otp,
        otp_type=otp_type,
        verified=False
    ).first()

    if not record or record.expires_at < datetime.utcnow():
        return {"verified": False}

    record.verified = True
    db.session.commit()

    return {"verified": True}

# def verify_otp(user_id, otp_type):
#     """
#     otp_type: 'email' or 'phone'
#     """
#     user = User.query.get_or_404(user_id)

#     if otp_type not in ["email", "phone"]:
#         flash("Invalid verification type")
#         return redirect("/register")

#     if request.method == "POST":
#         otp_email = request.form.get("email_otp")
#         otp_phone = request.form.get("phone_otp")

#         email_valid = OTP.query.filter_by(
#             user_id=user.id,
#             otp_code=otp_email,
#             otp_type="email"
#         ).first()

#         phone_valid = OTP.query.filter_by(
#             user_id=user.id,
#             otp_code=otp_phone,
#             otp_type="phone"
#         ).first()

#         if not email_valid or not phone_valid:
#             flash("Invalid OTP")
#             return redirect(request.url)

#         user.email_verified = True
#         user.phone_verified = True


#         otp_record = OTP.query.filter_by(
#             user_id=user_id,
#             otp_type=otp_type,
#             otp_code= request.form.get("otp_code")
#         ).first()

#         if not otp_record:
#             flash("Invalid OTP")
#             return redirect(request.url)

#         # expiry check (timezone-aware)
#         if otp_record.expires_at < datetime.now(timezone.utc):
#             flash("OTP expired. Please request again.")
#             db.session.delete(otp_record)
#             db.session.commit()
#             return redirect("/register")

#         user = db.session.get(User, user_id)

#         if otp_type == "email":
#             user.email_verified = True
#         elif otp_type == "phone":
#             user.phone_verified = True

#         db.session.delete(otp_record)
#         db.session.commit()

#         # Decide next step
#         if user.email_verified and user.phone_verified:
#             flash("Account verified successfully. Please login.")
#             return redirect("/login")
#         else:
#             # If email verified first, go to phone verification
#             next_type = "phone" if otp_type == "email" else "email"
#             return redirect(url_for("verify_otp", user_id=user_id, otp_type=next_type))
    
#     send_email_otp(user)
#     send_phone_otp(user)

#     return redirect(
#         url_for("verify_otp", user_id=user.id, otp_type="email")
#     )

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
        if not user.email_verified or not user.phone_verified:
            flash("Please verify your email and phone number first")
            return redirect("/login")

        # 4️⃣ All good → login
        login_user(user)
        return redirect("/")
    

    return render_template("auth/login.html")


# ---------------- FORGOT PASSWORD ROUTE ----------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with this email", "error")
            return redirect(request.url)

        send_reset_email(user)
        flash("Password reset link sent to your email", "success")
        return redirect("/login")
    return render_template("auth/forgot_pass.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    record = PasswordResetToken.query.filter_by(token=token).first()

    if not record or record.expires_at < datetime.utcnow():
        flash("Reset link expired or invalid", "error")
        return redirect("/login")

    if request.method == "POST":
        password = request.form.get("password")
        confirm = request.form.get("confirm_password")

        if password != confirm:
            flash("Passwords do not match", "error")
            return redirect(request.url)

        record.user.password = generate_password_hash(password)

        db.session.delete(record)
        db.session.commit()

        flash("Password updated successfully", "success")
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
                gender="Male",
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
        if not current_user.is_authenticated:
            return redirect("/admin/login")
        if not current_user.is_admin:
            return redirect("/")
        return f(*args, **kwargs)
    return decorated

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=request.form["email"]).first()

        if user and user.is_admin and check_password_hash(user.password, request.form["password"]):
            login_user(user, remember=True)
            return redirect("/admin/dashboard")

        flash("Invalid admin credentials")
        return redirect("/admin/login")
    
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

    total_revenue = db.session.query(
        func.sum(Order.total_amount)
    ).filter(Order.payment_status == "paid",
        Order.status.notin_(["cancelled", "returned"])).scalar() or 0
    
    total_orders = Order.query.count()
    refund_amount = db.session.query(
        func.sum(Order.refund_amount)
    ).filter(
        Order.refund_status == "processed"
    ).scalar() or 0

    net_revenue = total_revenue - refund_amount

    cancelled_orders = Order.query.filter_by(status="cancelled").count()
    returned_orders = Order.query.filter_by(status="returned").count()

    weekly_income = db.session.query(
        func.sum(Order.total_amount)
    ).filter(
        Order.status == "delivered",
        Order.created_at >= week_ago
    ).scalar() or 0

    # LAST 7 DAYS ORDERS
    last_7_days = datetime.utcnow() - timedelta(days=7)

    orders_by_day = (
        db.session.query(
            func.date(Order.created_at),
            func.count(Order.id)
        )
        .filter(Order.created_at >= last_7_days)
        .group_by(func.date(Order.created_at))
        .all()
    )

    revenue_by_day = (
        db.session.query(
            func.date(Order.created_at),
            func.sum(Order.total_amount)
        )
        .filter(
            Order.created_at >= last_7_days,
            Order.payment_status == "paid"
        )
        .group_by(func.date(Order.created_at))
        .all()
    )

    # PAYMENT METHOD SPLIT
    payment_split = (
        db.session.query(
            Order.payment_method,
            func.count(Order.id)
        )
        .group_by(Order.payment_method)
        .all()
    )

    # 🔐 SAFETY FALLBACKS (THIS IS CRITICAL)
    orders_by_day = orders_by_day or []
    revenue_by_day = revenue_by_day or []
    payment_split = payment_split or []

    return render_template(
        "admin/dashboard.html",
        total_users=total_users,
        verified_users=verified_users,
        blocked_users=blocked_users,
        total_revenue=total_revenue,
        total_orders=total_orders,
        cancelled_orders=cancelled_orders,
        returned_orders=returned_orders,
        net_revenue=net_revenue,
        refund_amount=refund_amount,
        weekly_income=weekly_income,
        orders_by_day = orders_by_day or [],
        revenue_by_day = revenue_by_day or [],
        payment_split = payment_split or []
    )
# ---------------- ADMIN NEWSLETTER ROUTE ----------------
@app.route("/admin/newsletter/send", methods=["POST"])
@admin_required
def send_newsletter():
    message = request.form["message"]
    subscribers = Newsletter.query.all()

    for sub in subscribers:
        send_email(sub.email, message)

    flash("Newsletter sent")
    return redirect("/admin/dashboard")

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
        product.category = category
        product.sub_category = sub_category
        product.is_compression = "Compression" in tags
        product.is_new_arrival = "New Arrival" in tags
        product.is_on_sale = "Sale" in tags

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
        tags = request.form.getlist("tags")
        product.tags = ",".join(request.form.getlist("tags"))
        product.is_compression = "Compression" in tags
        product.is_new_arrival = "New Arrival" in tags
        product.is_on_sale = "Sale" in tags
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

# ---------------- ORDERS DETAIL ROUTE ----------------
@app.route("/admin/orders")
@login_required
def admin_orders():
    if not current_user.is_admin:
        return redirect(url_for("home"))

    orders = Order.query.order_by(Order.created_at.desc()).all()
    return render_template("admin/orders.html", orders=orders)

@app.route("/admin/orders/<int:order_id>")
@login_required
def admin_order_detail(order_id):
    if not current_user.is_admin:
        return redirect(url_for("home"))

    order = Order.query.get_or_404(order_id)
    return render_template("admin/order_detail.html", order=order, user=order.user)


# ---------------- UPDATE ORDERS STATUS ROUTE ----------------
@app.route("/admin/orders/<int:order_id>/status", methods=["POST"])
@login_required
def update_order_status(order_id):
    if not current_user.is_admin:
        return redirect(url_for("home"))

    order = Order.query.get_or_404(order_id)
    order.status = request.form.get("status")
    order.tracking_id = request.form.get("tracking_id") or None

    expected = request.form.get("expected_delivery")
    order.expected_delivery = (
        datetime.strptime(expected, "%Y-%m-%d").date()
        if expected else None
    )

    db.session.commit()
    return redirect(url_for("admin_order_detail", order_id=order.id))

# ---------------- CANCEL APPROVE ROUTE ----------------
@app.route("/admin/order/<int:order_id>/approve-cancel", methods=["POST"])
@admin_required
def approve_cancel(order_id):
    order = Order.query.get_or_404(order_id)

    order.status = "cancelled"
    order.cancel_requested = False

    process_refund(order)

    db.session.commit()
    return redirect(url_for("admin_order_detail", order_id=order.id))

# ---------------- RETURN APPROVE ROUTE ----------------
@app.route("/admin/order/<int:order_id>/approve-return", methods=["POST"])
@admin_required
def approve_return(order_id):
    order = Order.query.get_or_404(order_id)

    order.status = "returned"
    order.return_requested = False
    order.returned_at = datetime.utcnow()
    process_refund(order)

    db.session.commit()
    return redirect(url_for("admin_order_detail", order_id=order.id))

# ---------------- REFUND PROCESS ----------------
def process_refund(order):
    order.refund_status = "pending"
    order.refund_amount = order.total_amount

    if order.payment_method.lower() == "cod":
        order.refund_method = "bank"
    else:
        order.refund_method = "razorpay"

    db.session.commit()

@app.route("/admin/order/<int:order_id>/process-refund", methods=["POST"])
@admin_required
def process_refund_admin(order_id):
    order = Order.query.get_or_404(order_id)

    if order.refund_status != "pending":
        flash("Refund already processed or invalid", "warning")
        return redirect(url_for("admin_order_detail", order_id=order.id))

    # COD orders → manual refund
    if order.payment_method.lower() == "cod":
        order.refund_status = "processed"
        order.refunded_at = datetime.utcnow()
        db.session.commit()

        flash("COD refund marked as processed", "success")
        return redirect(url_for("admin_order_detail", order_id=order.id))

    # Razorpay orders
    success, result = initiate_razorpay_refund(order)

    if success:
        flash("Refund processed successfully", "success")
    else:
        flash(f"Refund failed: {result}", "danger")

    return redirect(url_for("admin_order_detail", order_id=order.id))

    
def initiate_razorpay_refund(order):
    if not order.razorpay_payment_id:
        return False, "No Razorpay payment ID found"

    try:
        refund = razorpay_client.payment.refund(
            order.razorpay_payment_id,
            {
                "amount": int(order.refund_amount * 100),  # paise
                "speed": "optimum"
            }
        )

        order.refund_status = "processed"
        order.refunded_at = datetime.utcnow()
        db.session.commit()

        return True, refund["id"]

    except Exception as e:
        return False, str(e)

# ---------------- MARK REFUND ROUTE ----------------
@app.route("/admin/order/<int:order_id>/refund-done", methods=["POST"])
@admin_required
def mark_refund_processed(order_id):
    order = Order.query.get_or_404(order_id)

    order.refund_status = "processed"
    order.refunded_at = datetime.utcnow()

    db.session.commit()
    return redirect(url_for("admin_order_detail", order_id=order.id))

# ---------------- SHOP ROUTE ----------------
@app.route("/shop")
def shop():
    category = request.args.get("category")

    query = Product.query.filter_by(is_active=True)

    # NAVBAR CATEGORY FILTER
    if category == "New Arrivals":
        query = query.filter_by(is_new_arrival=True)

    elif category == "Sale":
        query = query.filter_by(is_on_sale=True)

    elif category in ["Men", "Women", "Accessories", "Compression"]:
        query = query.filter_by(category=category)

    products = query.order_by(Product.sub_category).all()

    # GROUP PRODUCTS: MEN | Joggers style
    grouped_products = {}
    for product in products:
        key = f"{product.category} | {product.sub_category}"
        grouped_products.setdefault(key, []).append(product)

    return render_template(
        "shop.html",
        grouped_products=grouped_products,
        selected_category=category
    )

# ---------------- PRODUCT DETAIL ROUTE ----------------
@app.route("/product/<int:product_id>")
def product_detail(product_id):
    product = Product.query.filter_by(id=product_id, is_active=True).first_or_404()
    return render_template("product_detail.html", product=product)

# ---------------- CART ROUTE ----------------
@app.route("/add-to-cart/<int:product_id>", methods=["POST"])
def add_to_cart(product_id):
    size = request.form.get("size")
    quantity = int(request.form.get("quantity", 1))

    # 👤 NOT LOGGED IN → GUEST CART
    if not current_user.is_authenticated:
        guest_cart = session.get("guest_cart", [])
        guest_cart.append({
            "product_id": product_id,
            "size": size,
            "quantity": quantity
        })
        session["guest_cart"] = guest_cart
        session.modified = True
        return redirect(url_for("login"))

    # 👤 LOGGED IN → DB CART
    existing = CartItem.query.filter_by(
        user_id=current_user.id,
        product_id=product_id,
        size=size
    ).first()

    if existing:
        existing.quantity += quantity
    else:
        db.session.add(CartItem(
            user_id=current_user.id,
            product_id=product_id,
            size=size,
            quantity=quantity
        ))

    db.session.commit()
    return redirect(url_for("cart"))

def merge_guest_cart(user_id):
    guest_cart = session.pop("guest_cart", [])

    for item in guest_cart:
        existing = CartItem.query.filter_by(
            user_id=user_id,
            product_id=item["product_id"],
            size=item["size"]
        ).first()

        if existing:
            existing.quantity += item["quantity"]
        else:
            db.session.add(CartItem(
                user_id=user_id,
                product_id=item["product_id"],
                size=item["size"],
                quantity=item["quantity"]
            ))

    db.session.commit()

@app.route("/cart")
@login_required
def cart():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()

    subtotal = 0
    for item in cart_items:
        price = item.product.discounted_price or item.product.price
        subtotal += price * item.quantity

    delivery_charge = 0 if subtotal >= 999 else 49
    total = subtotal + delivery_charge

    return render_template(
        "cart.html",
        cart_items=cart_items,
        subtotal=subtotal,
        delivery_charge=delivery_charge,
        total=total
    )

@app.route("/cart/update/<int:item_id>", methods=["POST"])
@login_required
def update_cart(item_id):
    item = CartItem.query.filter_by(
        id=item_id,
        user_id=current_user.id
    ).first_or_404()

    item.size = request.form.get("size")
    item.quantity = int(request.form["quantity"])
    db.session.commit()
    return redirect("/cart")

@app.route("/cart/remove/<int:item_id>")
@login_required
def remove_from_cart(item_id):
    item = CartItem.query.filter_by(
        id=item_id,
        user_id=current_user.id
    ).first_or_404()

    db.session.delete(item)
    db.session.commit()
    return redirect("/cart")

# ---------------- CHECKOUT ROUTE ----------------
@app.route("/checkout", methods=["GET", "POST"])
@login_required
def checkout():
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    if not cart_items:
        return redirect(url_for("cart"))

    subtotal = sum(
        (item.product.discounted_price or item.product.price) * item.quantity
        for item in cart_items
    )

    delivery_charge = 0 if subtotal >= 999 else 49
    total = subtotal + delivery_charge

    saved_address = current_user.address

    if request.method == "POST":
        payment_method = request.form.get("payment_method")
        delivery_address = request.form.get("address")

        order = Order(
            user_id=current_user.id,
            total_amount=total,
            payment_method=payment_method,
            address=delivery_address,
            payment_status="pending",
            razorpay_order_id = razorpay_order["id"],
            status="placed"
        )

        # COD FLOW
        if payment_method == "COD":
            order.payment_method = "COD"
            order.payment_status = "pending"
            order.status="placed"
            db.session.commit()

            CartItem.query.filter_by(user_id=current_user.id).delete()
            db.session.commit()

            return redirect(url_for("order_success", order_id=order.id))

        # RAZORPAY FLOW
        razorpay_order = razorpay_client.order.create({
            "amount": int(total * 100),  # paise
            "currency": "INR",
            "payment_capture": 1
        })

        if payment_method == "razorpay":
            order.payment_status="paid"
            order.payment_method="razorpay"
            order.razorpay_order_id = razorpay_order["id"]
            db.session.commit()
            return render_template(
                "razorpay_checkout.html",
                order=order,
                razorpay_key="YOUR_KEY_ID",
                razorpay_amount=int(total * 100)
            )
        
        invoice_file = generate_invoice(order)
        order.invoice_file = invoice_file
        db.session.commit()

        if not order.invoice_file:
            order.invoice_file = generate_invoice(order)
            db.session.commit()
        db.session.add(order)
        db.session.commit()

        for item in cart_items:
            db.session.add(OrderItem(
                order_id=order.id,
                product_id=item.product_id,
                product_name=item.product.name,
                price=item.product.discounted_price or item.product.price,
                quantity=item.quantity,
                size=item.size
            ))

        CartItem.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()

    return render_template(
        "checkout.html",
        total=total,
        saved_address=saved_address
    )

# ---------------- RAZORPAY SUCCESS ROUTE ----------------
@app.route("/razorpay-success", methods=["POST"])
@login_required
def razorpay_success():
    data = request.get_json()

    order = Order.query.filter_by(
        razorpay_order_id=data["razorpay_order_id"]
    ).first_or_404()

    order.razorpay_payment_id = data["razorpay_payment_id"]
    order.razorpay_signature = data["razorpay_signature"]
    order.payment_status = "paid"

    CartItem.query.filter_by(user_id=current_user.id).delete()

    db.session.commit()
    return "", 200

# ---------------- ORDER SUCCESS ROUTE ----------------
@app.route("/order-success/<int:order_id>")
@login_required
def order_success(order_id):
    order = Order.query.get_or_404(order_id)
    return render_template("order_success.html", order=order)

# ---------------- CANCEL REQUEST ROUTE ----------------
@app.route("/order/<int:order_id>/cancel", methods=["POST"])
@login_required
def request_cancel(order_id):
    order = Order.query.get_or_404(order_id)

    if order.user_id != current_user.id:
        return redirect(url_for("home"))

    if order.status not in ["placed", "confirmed"]:
        flash("Order cannot be cancelled", "danger")
        return redirect("/account")

    order.cancel_requested = True
    order.cancel_reason = request.form["reason"]

    db.session.commit()
    flash("Cancellation request sent", "success")
    return redirect("/account")

# ---------------- RETURN REQUEST ROUTE ----------------
@app.route("/order/<int:order_id>/return", methods=["POST"])
@login_required
def request_return(order_id):
    order = Order.query.get_or_404(order_id)

    if order.user_id != current_user.id:
        return redirect(url_for("home"))

    if order.status != "delivered":
        flash("Return not allowed", "danger")
        return redirect("/account")

    order.return_requested = True
    order.return_reason = request.form["reason"]

    db.session.commit()
    flash("Return request sent", "success")
    return redirect("/account")


# ---------------- DEBUG ROUTE ----------------

@app.route("/__debug__")
def debug():
    return "THIS FILE IS RUNNING"

# ---------------- RUN THE APP ----------------
if __name__ == "__main__":    #---------------- Always be at the end of the file ----------------
    with app.app_context():
        db.create_all()
        # create_admin()
    app.run(debug=True)