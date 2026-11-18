import os
import uuid
from datetime import datetime, timedelta, date
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import text
from PIL import Image

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

    # Additional profile fields
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


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


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
            dob = datetime.strptime(dob_text, "%Y-%m-%d").date()
        except ValueError:
            flash("Please enter a valid date of birth.", "error")
            return redirect(url_for("register"))

        today = date.today()
        age = today.year - dob.year - (
            (today.month, today.day) < (dob.month, dob.day)
        )

        if dob > today or age < 18:
            flash("Nexa is only available to people aged 18 and above.", "error")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Your passwords do not match.", "error")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists.", "error")
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

        flash("Your account has been created. Your 7-day trial has started.", "success")
        return redirect(url_for("dashboard"))

    return render_template("auth/register.html")


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


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    remaining = max(0, (user.trial_ends_at - datetime.utcnow()).days)

    return render_template(
        "dashboard.html",
        user=user,
        trial_days_remaining=remaining
    )


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = get_current_user()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        user.gender = request.form.get("gender", "").strip()
        user.location = request.form.get("location", "").strip()
        user.bio = request.form.get("bio", "").strip()[:1000]
        user.interests = request.form.get("interests", "").strip()[:500]

        allowed_preferences = [
            "Dating",
            "Friendship",
            "Friends with benefits",
            "Casual connections",
            "Serious relationship"
        ]

        preference = request.form.get("connection_preference", "")
        if preference in allowed_preferences:
            user.connection_preference = preference

        # Explicit consent is required to share a phone number.
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

                filename = secure_filename(str(uuid.uuid4()) + extension)
                photo.stream.seek(0)
                photo.save(os.path.join(UPLOAD_FOLDER, filename))

                old_photo = user.profile_photo
                user.profile_photo = filename

                if old_photo:
                    old_path = os.path.join(UPLOAD_FOLDER, old_photo)
                    if os.path.isfile(old_path):
                        os.remove(old_path)

            except Exception:
                db.session.rollback()
                flash("Please upload a valid JPG, PNG or WEBP image.", "error")
                return redirect(url_for("profile"))

        db.session.commit()
        flash("Your profile has been updated.", "success")
        return redirect(url_for("profile"))

    return render_template("profile.html", user=user)


@app.route("/discover")
@login_required
def discover():
    return "<h1>Discover People - Coming Soon</h1><a href='/dashboard'>Dashboard</a>"


@app.route("/subscription")
@login_required
def subscription():
    user = get_current_user()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    now = datetime.utcnow()
    trial_ends_at = user.trial_ends_at
    trial_active = bool(trial_ends_at and trial_ends_at > now)

    trial_days_remaining = 0
    if trial_active:
        trial_days_remaining = max(
            0, (trial_ends_at - now).days
        )

    return render_template(
        "subscription.html",
        user=user,
        trial_active=trial_active,
        trial_days_remaining=trial_days_remaining,
        trial_ends_at=trial_ends_at
    )


@app.route("/settings")
@login_required
def settings():
    return "<h1>Account Settings - Coming Soon</h1><a href='/dashboard'>Dashboard</a>"


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have signed out successfully.", "success")
    return redirect(url_for("login"))


# Create tables and safely add new profile columns to existing databases.
with app.app_context():
    db.create_all()

    with db.engine.begin() as connection:
        columns = {
            row[1] for row in
            connection.execute(text("PRAGMA table_info(user)")).fetchall()
        }

        migrations = {
            "gender": "ALTER TABLE user ADD COLUMN gender VARCHAR(30) DEFAULT ''",
            "location": "ALTER TABLE user ADD COLUMN location VARCHAR(150) DEFAULT ''",
            "bio": "ALTER TABLE user ADD COLUMN bio TEXT DEFAULT ''",
            "interests": "ALTER TABLE user ADD COLUMN interests VARCHAR(500) DEFAULT ''",
            "connection_preference": "ALTER TABLE user ADD COLUMN connection_preference VARCHAR(50) DEFAULT ''",
            "profile_photo": "ALTER TABLE user ADD COLUMN profile_photo VARCHAR(255) DEFAULT ''"
        }

        for column, sql in migrations.items():
            if column not in columns:
                connection.execute(text(sql))


if __name__ == "__main__":
    app.run(debug=True)
