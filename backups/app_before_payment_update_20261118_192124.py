import os
import uuid
import calendar
import hashlib
import hmac
import requests

from dotenv import load_dotenv
from datetime import datetime, timedelta, date
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, abort
)

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import text
from PIL import Image


# --------------------------------------------------
# ENVIRONMENT
# --------------------------------------------------

load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "development-key-change-before-deployment"
)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///nexa.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)


# --------------------------------------------------
# PAYSTACK CONFIGURATION
# --------------------------------------------------

PAYSTACK_SECRET_KEY = os.environ.get("PAYSTACK_SECRET_KEY", "")
PAYSTACK_MODE = os.environ.get("PAYSTACK_MODE", "test")
PAYSTACK_BASE_URL = "https://api.paystack.co"

CONTACT_UNLOCK_AMOUNT_KOBO = 120000

SUBSCRIPTION_PLANS = {
    "1_month": {
        "name": "1 Month",
        "amount": 350000,
        "months": 1
    },
    "6_months": {
        "name": "6 Months",
        "amount": 2000000,
        "months": 6
    },
    "12_months": {
        "name": "12 Months",
        "amount": 4100000,
        "months": 12
    }
}


# --------------------------------------------------
# USER MODEL
# --------------------------------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(30), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    trial_ends_at = db.Column(
        db.DateTime,
        default=lambda: datetime.utcnow() + timedelta(days=7)
    )

    contact_sharing_enabled = db.Column(db.Boolean, default=False)

    gender = db.Column(db.String(30), default="")
    location = db.Column(db.String(150), default="")
    bio = db.Column(db.Text, default="")
    interests = db.Column(db.String(500), default="")
    connection_preference = db.Column(db.String(50), default="")
    profile_photo = db.Column(db.String(255), default="")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# --------------------------------------------------
# PAYMENT MODEL
# --------------------------------------------------

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    target_user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=True
    )

    reference = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    purpose = db.Column(db.String(40), nullable=False)
    amount_kobo = db.Column(db.Integer, nullable=False)

    currency = db.Column(db.String(3), default="NGN", nullable=False)
    status = db.Column(db.String(20), default="pending", nullable=False)

    provider_transaction_id = db.Column(db.String(100), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    paid_at = db.Column(db.DateTime, nullable=True)


# --------------------------------------------------
# CONTACT UNLOCK MODEL
# --------------------------------------------------

class ContactUnlock(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    buyer_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    profile_owner_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    payment_id = db.Column(
        db.Integer,
        db.ForeignKey("payment.id"),
        unique=True,
        nullable=False
    )

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint(
            "buyer_id",
            "profile_owner_id",
            name="unique_contact_unlock"
        ),
    )


# --------------------------------------------------
# SUBSCRIPTION MODEL
# --------------------------------------------------

class Subscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        unique=True,
        nullable=False
    )

    status = db.Column(
        db.String(20),
        default="inactive",
        nullable=False
    )

    current_period_start = db.Column(db.DateTime, nullable=True)
    current_period_end = db.Column(db.DateTime, nullable=True)

    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )


# --------------------------------------------------
# GENERAL HELPERS
# --------------------------------------------------

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in first.", "error")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


def get_current_user():
    return db.session.get(User, session.get("user_id"))


def add_months(original_date, months):
    """Add calendar months without losing valid end-of-month dates."""

    month_index = original_date.month - 1 + months
    year = original_date.year + month_index // 12
    month = month_index % 12 + 1

    day = min(
        original_date.day,
        calendar.monthrange(year, month)[1]
    )

    return original_date.replace(
        year=year,
        month=month,
        day=day
    )


# --------------------------------------------------
# PAYSTACK PAYMENT VERIFICATION
# --------------------------------------------------

def verify_and_complete_payment(reference):
    """
    Verify a transaction directly with Paystack.
    Activate a subscription only after the exact payment
    amount, currency, reference and status are confirmed.
    """

    if not PAYSTACK_SECRET_KEY:
        raise ValueError("Paystack secret key is not configured.")

    payment = Payment.query.filter_by(reference=reference).first()

    if payment is None:
        raise ValueError("Payment reference was not found.")

    # Prevent duplicate subscription activation.
    if payment.status == "success":
        return payment

    response = requests.get(
        f"{PAYSTACK_BASE_URL}/transaction/verify/{reference}",
        headers={
            "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json"
        },
        timeout=30
    )

    response.raise_for_status()
    result = response.json()

    if not result.get("status"):
        raise ValueError("Paystack could not verify this payment.")

    transaction = result.get("data", {})

    if transaction.get("status") != "success":
        raise ValueError("The payment has not been completed.")

    if transaction.get("reference") != payment.reference:
        raise ValueError("Payment reference does not match.")

    if transaction.get("amount") != payment.amount_kobo:
        raise ValueError("Payment amount does not match.")

    if transaction.get("currency") != "NGN":
        raise ValueError("Payment currency is not supported.")

    if payment.purpose not in (
        "subscription_1_month",
        "subscription_6_months",
        "subscription_12_months"
    ):
        raise ValueError("This payment purpose is not supported yet.")

    user = db.session.get(User, payment.user_id)

    if user is None:
        raise ValueError("The account for this payment was not found.")

    months_by_purpose = {
        "subscription_1_month": 1,
        "subscription_6_months": 6,
        "subscription_12_months": 12
    }

    months = months_by_purpose[payment.purpose]

    now = datetime.utcnow()

    subscription = Subscription.query.filter_by(
        user_id=user.id
    ).first()

    if subscription is None:
        subscription = Subscription(
            user_id=user.id,
            status="active",
            current_period_start=now,
            current_period_end=add_months(now, months)
        )

        db.session.add(subscription)

    else:
        old_end = subscription.current_period_end

        if (
            subscription.status == "active"
            and old_end
            and old_end > now
        ):
            start_date = old_end
        else:
            start_date = now

        subscription.status = "active"

        if subscription.current_period_start is None:
            subscription.current_period_start = now

        subscription.current_period_end = add_months(
            start_date,
            months
        )

    payment.status = "success"
    payment.provider_transaction_id = str(transaction.get("id", ""))
    payment.paid_at = now

    db.session.commit()

    return payment


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# --------------------------------------------------
# REGISTRATION
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        dob_text = request.form.get("date_of_birth", "")

        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not all([full_name, email, phone, dob_text, password]):
            flash("Please complete all required fields.", "error")
            return redirect(url_for("register"))

        if request.form.get("age_confirmed") != "yes":
            flash("You must confirm that you are at least 18.", "error")
            return redirect(url_for("register"))

        if request.form.get("terms") != "yes":
            flash("You must accept the Terms and Privacy Policy.", "error")
            return redirect(url_for("register"))

        try:
            dob = datetime.strptime(
                dob_text,
                "%Y-%m-%d"
            ).date()

        except ValueError:
            flash("Please enter a valid date of birth.", "error")
            return redirect(url_for("register"))

        today = date.today()

        age = today.year - dob.year - (
            (today.month, today.day) < (dob.month, dob.day)
        )

        if dob > today or age < 18:
            flash(
                "Nexa is only available to people aged 18 and above.",
                "error"
            )
            return redirect(url_for("register"))

        if len(password) < 8:
            flash(
                "Password must contain at least 8 characters.",
                "error"
            )
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Your passwords do not match.", "error")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash(
                "An account with this email already exists.",
                "error"
            )
            return redirect(url_for("register"))

        user = User(
            full_name=full_name,
            email=email,
            phone=phone,
            date_of_birth=dob,
            contact_sharing_enabled=False
        )

        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        session.clear()
        session["user_id"] = user.id

        flash(
            "Your account has been created. Your 7-day trial has started.",
            "success"
        )

        return redirect(url_for("dashboard"))

    return render_template("auth/register.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session.clear()
            session["user_id"] = user.id

            flash("Welcome back to Nexa.", "success")

            return redirect(url_for("dashboard"))

        flash("Incorrect email or password.", "error")

    return render_template("auth/login.html")


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    remaining = max(
        0,
        (user.trial_ends_at - datetime.utcnow()).days
    )

    return render_template(
        "dashboard.html",
        user=user,
        trial_days_remaining=remaining
    )


# --------------------------------------------------
# PROFILE
# --------------------------------------------------

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = get_current_user()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":

        user.gender = request.form.get(
            "gender", ""
        ).strip()

        user.location = request.form.get(
            "location", ""
        ).strip()

        user.bio = request.form.get(
            "bio", ""
        ).strip()[:1000]

        user.interests = request.form.get(
            "interests", ""
        ).strip()[:500]

        allowed_preferences = [
            "Dating",
            "Friendship",
            "Friends with benefits",
            "Casual connections",
            "Serious relationship"
        ]

        preference = request.form.get(
            "connection_preference", ""
        )

        if preference in allowed_preferences:
            user.connection_preference = preference

        user.contact_sharing_enabled = (
            request.form.get("contact_sharing_enabled") == "yes"
        )

        photo = request.files.get("profile_photo")

        if photo and photo.filename:
            try:
                image = Image.open(photo.stream)
                image.verify()

                photo.stream.seek(0)
                image = Image.open(photo.stream)

                if image.format not in ["JPEG", "PNG", "WEBP"]:
                    raise ValueError("Unsupported image format.")

                extension = {
                    "JPEG": ".jpg",
                    "PNG": ".png",
                    "WEBP": ".webp"
                }[image.format]

                filename = secure_filename(
                    str(uuid.uuid4()) + extension
                )

                photo.stream.seek(0)

                photo.save(
                    os.path.join(UPLOAD_FOLDER, filename)
                )

                old_photo = user.profile_photo
                user.profile_photo = filename

                if old_photo:
                    old_path = os.path.join(
                        UPLOAD_FOLDER,
                        old_photo
                    )

                    if os.path.isfile(old_path):
                        os.remove(old_path)

            except Exception:
                db.session.rollback()

                flash(
                    "Please upload a valid JPG, PNG or WEBP image.",
                    "error"
                )

                return redirect(url_for("profile"))

        db.session.commit()

        flash("Your profile has been updated.", "success")

        return redirect(url_for("profile"))

    return render_template("profile.html", user=user)


# --------------------------------------------------
# DISCOVER
# --------------------------------------------------

@app.route("/discover")
@login_required
def discover():
    current_user = get_current_user()

    if current_user is None:
        session.clear()
        return redirect(url_for("login"))

    search = request.args.get("q", "").strip()
    gender_filter = request.args.get("gender", "").strip()
    preference_filter = request.args.get("preference", "").strip()
    location_filter = request.args.get("location", "").strip()

    allowed_genders = ["Male", "Female", "Other"]
    allowed_preferences = [
        "Dating",
        "Friendship",
        "Friends with benefits",
        "Casual connections",
        "Serious relationship"
    ]

    if gender_filter not in allowed_genders:
        gender_filter = ""

    if preference_filter not in allowed_preferences:
        preference_filter = ""

    try:
        min_age = int(request.args.get("min_age", "18"))
        max_age = int(request.args.get("max_age", "100"))
    except (TypeError, ValueError):
        min_age, max_age = 18, 100

    min_age = max(18, min(min_age, 100))
    max_age = max(18, min(max_age, 100))

    if min_age > max_age:
        min_age, max_age = 18, 100

    members = User.query.filter(
        User.id != current_user.id
    ).order_by(User.created_at.desc()).all()

    today = date.today()
    member_cards = []

    for member in members:
        if not member.date_of_birth:
            continue

        age = today.year - member.date_of_birth.year - (
            (today.month, today.day) <
            (member.date_of_birth.month, member.date_of_birth.day)
        )

        if age < 18 or age < min_age or age > max_age:
            continue

        if gender_filter and member.gender != gender_filter:
            continue

        if preference_filter and member.connection_preference != preference_filter:
            continue

        if location_filter and location_filter.casefold() not in (
            (member.location or "").casefold()
        ):
            continue

        searchable_text = " ".join([
            member.full_name or "",
            member.location or "",
            member.interests or "",
            member.bio or ""
        ]).casefold()

        if search and search.casefold() not in searchable_text:
            continue

        member_cards.append({
            "user": member,
            "age": age
        })

    return render_template(
        "discover.html",
        user=current_user,
        members=member_cards,
        search=search,
        gender_filter=gender_filter,
        preference_filter=preference_filter,
        location_filter=location_filter,
        min_age=min_age,
        max_age=max_age
    )


@app.route("/member/<int:user_id>")
@login_required
def member_profile(user_id):
    current_user = get_current_user()

    if current_user is None:
        session.clear()
        return redirect(url_for("login"))

    member = db.session.get(User, user_id)

    if member is None:
        flash("That member could not be found.", "error")
        return redirect(url_for("discover"))

    if not member.date_of_birth:
        flash("This member's profile is unavailable.", "error")
        return redirect(url_for("discover"))

    today = date.today()
    age = today.year - member.date_of_birth.year - (
        (today.month, today.day) <
        (member.date_of_birth.month, member.date_of_birth.day)
    )

    if age < 18:
        flash("This profile is unavailable.", "error")
        return redirect(url_for("discover"))

    return render_template(
        "member_profile.html",
        user=current_user,
        member=member,
        age=age
    )


# --------------------------------------------------
# SUBSCRIPTION PAGE
# --------------------------------------------------

@app.route("/subscription")
@login_required
def subscription():
    user = get_current_user()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    now = datetime.utcnow()

    trial_ends_at = user.trial_ends_at

    trial_active = bool(
        trial_ends_at and trial_ends_at > now
    )

    trial_days_remaining = 0

    if trial_active:
        trial_days_remaining = max(
            0,
            (trial_ends_at - now).days
        )

    current_subscription = Subscription.query.filter_by(
        user_id=user.id
    ).first()

    return render_template(
        "subscription.html",
        user=user,
        trial_active=trial_active,
        trial_days_remaining=trial_days_remaining,
        trial_ends_at=trial_ends_at,
        plans=SUBSCRIPTION_PLANS,
        current_subscription=current_subscription,
        paystack_mode=PAYSTACK_MODE
    )


# --------------------------------------------------
# START PAYSTACK SUBSCRIPTION PAYMENT
# --------------------------------------------------

@app.route("/payment/initialize/<plan_code>", methods=["POST"])
@login_required
def initialize_payment(plan_code):
    user = get_current_user()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    plan = SUBSCRIPTION_PLANS.get(plan_code)

    if plan is None:
        flash("Please select a valid subscription plan.", "error")
        return redirect(url_for("subscription"))

    if not PAYSTACK_SECRET_KEY:
        flash(
            "Paystack is not configured. Please check your environment settings.",
            "error"
        )
        return redirect(url_for("subscription"))

    if PAYSTACK_MODE != "test":
        flash(
            "This application is currently configured for test payments only.",
            "error"
        )
        return redirect(url_for("subscription"))

    reference = "NEXA-" + uuid.uuid4().hex

    purpose = {
        "1_month": "subscription_1_month",
        "6_months": "subscription_6_months",
        "12_months": "subscription_12_months"
    }[plan_code]

    payment = Payment(
        user_id=user.id,
        reference=reference,
        purpose=purpose,
        amount_kobo=plan["amount"],
        currency="NGN",
        status="pending"
    )

    db.session.add(payment)
    db.session.commit()

    callback_url = os.environ.get(
        "PAYSTACK_CALLBACK_URL",
        url_for("payment_callback", _external=True)
    )

    payload = {
        "email": user.email,
        "amount": plan["amount"],
        "currency": "NGN",
        "reference": reference,
        "callback_url": callback_url,
        "metadata": {
            "user_id": user.id,
            "purpose": purpose,
            "plan_name": plan["name"]
        }
    }

    try:
        response = requests.post(
            f"{PAYSTACK_BASE_URL}/transaction/initialize",
            json=payload,
            headers={
                "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
                "Content-Type": "application/json"
            },
            timeout=30
        )

        response.raise_for_status()
        result = response.json()

        if not result.get("status"):
            payment.status = "failed"
            db.session.commit()

            flash(
                "Paystack could not initialize this payment.",
                "error"
            )

            return redirect(url_for("subscription"))

        authorization_url = result["data"]["authorization_url"]

        return redirect(authorization_url)

    except requests.RequestException:
        payment.status = "failed"
        db.session.commit()

        app.logger.exception("Paystack initialization failed.")

        flash(
            "Unable to connect to Paystack. Please try again.",
            "error"
        )

        return redirect(url_for("subscription"))


# --------------------------------------------------
# PAYSTACK CALLBACK
# --------------------------------------------------

@app.route("/payment/callback")
def payment_callback():
    reference = request.args.get("reference", "").strip()

    if not reference:
        flash("No payment reference was received.", "error")
        return redirect(url_for("subscription"))

    payment = Payment.query.filter_by(
        reference=reference
    ).first()

    if payment is None:
        flash("Payment record was not found.", "error")
        return redirect(url_for("subscription"))

    try:
        verified_payment = verify_and_complete_payment(reference)

        if verified_payment.status == "success":
            flash(
                "Payment confirmed. Your Nexa subscription is active.",
                "success"
            )

        return redirect(url_for("subscription"))

    except (requests.RequestException, ValueError):
        db.session.rollback()

        app.logger.exception("Paystack verification failed.")

        flash(
            "We could not confirm your payment yet. Please contact support if you were charged.",
            "error"
        )

        return redirect(url_for("subscription"))


# --------------------------------------------------
# PAYSTACK WEBHOOK
# --------------------------------------------------

@app.route("/payment/webhook", methods=["POST"])
def paystack_webhook():
    if not PAYSTACK_SECRET_KEY:
        abort(503)

    signature = request.headers.get(
        "x-paystack-signature", ""
    )

    raw_body = request.get_data()

    expected_signature = hmac.new(
        PAYSTACK_SECRET_KEY.encode("utf-8"),
        raw_body,
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(
        signature,
        expected_signature
    ):
        abort(401)

    event = request.get_json(silent=True) or {}

    if event.get("event") == "charge.success":
        reference = (
            event.get("data", {}).get("reference", "")
        )

        if reference:
            try:
                verify_and_complete_payment(reference)

            except (requests.RequestException, ValueError):
                db.session.rollback()
                app.logger.exception(
                    "Paystack webhook payment verification failed."
                )
                return "Verification failed", 500

    return "OK", 200


# --------------------------------------------------
# SETTINGS
# --------------------------------------------------

@app.route("/settings")
@login_required
def settings():
    return (
        "<h1>Account Settings - Coming Soon</h1>"
        "<a href='/dashboard'>Dashboard</a>"
    )


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
@login_required
def logout():
    session.clear()

    flash(
        "You have signed out successfully.",
        "success"
    )

    return redirect(url_for("login"))


# --------------------------------------------------
# DATABASE CREATION AND SAFE MIGRATIONS
# --------------------------------------------------

with app.app_context():

    db.create_all()

    with db.engine.begin() as connection:

        columns = {
            row[1]
            for row in connection.execute(
                text("PRAGMA table_info(user)")
            ).fetchall()
        }

        migrations = {
            "gender": (
                "ALTER TABLE user "
                "ADD COLUMN gender VARCHAR(30) DEFAULT ''"
            ),

            "location": (
                "ALTER TABLE user "
                "ADD COLUMN location VARCHAR(150) DEFAULT ''"
            ),

            "bio": (
                "ALTER TABLE user "
                "ADD COLUMN bio TEXT DEFAULT ''"
            ),

            "interests": (
                "ALTER TABLE user "
                "ADD COLUMN interests VARCHAR(500) DEFAULT ''"
            ),

            "connection_preference": (
                "ALTER TABLE user "
                "ADD COLUMN connection_preference VARCHAR(50) DEFAULT ''"
            ),

            "profile_photo": (
                "ALTER TABLE user "
                "ADD COLUMN profile_photo VARCHAR(255) DEFAULT ''"
            )
        }

        for column, sql in migrations.items():

            if column not in columns:
                connection.execute(text(sql))


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)
