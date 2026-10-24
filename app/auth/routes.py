import re
from urllib.parse import urlparse

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from ..extensions import db
from ..models import User
from ..security import new_api_key

bp = Blueprint("auth", __name__)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _safe_next(target):
    if not target:
        return None
    u = urlparse(target)
    return target if not u.netloc and not u.scheme and target.startswith("/") else None


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        ident = request.form.get("username", "").strip()
        user = User.query.filter((User.username == ident) | (User.email == ident.lower())).first()
        if user and user.check_password(request.form.get("password", "")):
            login_user(user, remember=bool(request.form.get("remember")))
            return redirect(_safe_next(request.args.get("next")) or url_for("main.dashboard"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if not current_app.config["ALLOW_REGISTRATION"] and User.query.count() > 0:
        flash("Registration is disabled.", "warning")
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        error = None
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            error = "Username must be 3-32 characters (letters, digits, _ . -)."
        elif not EMAIL_RE.match(email):
            error = "Enter a valid e-mail address."
        elif len(pw) < 8:
            error = "Password must be at least 8 characters."
        elif pw != request.form.get("confirm", ""):
            error = "Passwords do not match."
        elif User.query.filter((User.username == username) | (User.email == email)).first():
            error = "Username or e-mail already registered."
        if error:
            flash(error, "danger")
        else:
            first = User.query.count() == 0
            user = User(username=username, email=email, role="admin" if first else "user")
            user.set_password(pw)
            db.session.add(user)
            user.get_settings()
            db.session.commit()
            login_user(user)
            flash("Welcome to CyberShield!" + (" You are the administrator." if first else ""), "success")
            return redirect(url_for("main.dashboard"))
    return render_template("register.html")


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Signed out.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "api_key":
            current_user.api_key = new_api_key()
            db.session.commit()
            flash("New API key generated.", "success")
        elif action == "password":
            if not current_user.check_password(request.form.get("current", "")):
                flash("Current password is incorrect.", "danger")
            elif len(request.form.get("new", "")) < 8:
                flash("New password must be at least 8 characters.", "danger")
            else:
                current_user.set_password(request.form["new"])
                db.session.commit()
                flash("Password updated.", "success")
        return redirect(url_for("auth.profile"))
    return render_template("profile.html")
