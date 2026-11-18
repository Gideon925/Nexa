
cd ~/Documents/AdultConnect

cat > app.py <<'PY'
import os
from datetime import datetime, timedelta, date

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, session
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps


app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "development-key-change-before-deployment"
)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///nexa.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# USER DATABASE MODEL
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

    # Phone sharing is disabled by default.
    contact_sharing_enabled = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# LOGIN PROTECTION
def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in first.", "error")
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


# HOME PAGE
@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# REGISTRATION
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        dob_text = request.form.get("date_of_birth", "")
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        age_confirmed = request.form.get("age_confirmed")

        if not all([full_name, email, phone, dob_text, password]):
            flash("Please complete all required fields.", "error")
            return redirect(url_for("register"))

        if age_confirmed != "yes":
            flash("You must confirm that you are 18 or older.", "error")
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
            flash("Your password must contain at least 8 characters.", "error")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Your passwords do not match.", "error")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
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

        session["user_id"] = user.id

        flash("Your account has been created. Your 7-day trial has started.", "success")
        return redirect(url_for("dashboard"))

    return render_template("auth/register.html")


# SIGN IN
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


# USER DASHBOARD
@app.route("/dashboard")
@login_required
def dashboard():

    user = db.session.get(User, session["user_id"])

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


# LOGOUT
@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("You have signed out successfully.", "success")
    return redirect(url_for("login"))


# CREATE DATABASE TABLES
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)
PY
