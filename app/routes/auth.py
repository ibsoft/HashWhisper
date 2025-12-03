import io
import ipaddress
from datetime import datetime

import pyotp
import qrcode
from flask import Blueprint, current_app, flash, redirect, render_template, request, send_file, session, url_for
from flask_login import current_user, login_user, logout_user
from sqlalchemy import or_

from ..extensions import db, limiter
from ..forms import LoginForm, RegistrationForm, TwoFactorForm
from ..models import User
from ..security import regenerate_session

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _remote_allowed(remote_addr: str | None, networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]) -> bool:
    if not remote_addr:
        return False
    try:
        client_ip = ipaddress.ip_address(remote_addr)
    except ValueError:
        return False
    return any(client_ip in network for network in networks)


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_REGISTER"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("chat.chat"))
    if not current_app.config.get("ALLOW_USER_REGISTRATIONS", True):
        flash("User registrations are disabled.", "warning")
        return redirect(url_for("auth.login"))
    allowed_networks = current_app.config.get("REGISTRATION_ALLOWED_NETWORKS", ())
    if allowed_networks and not _remote_allowed(request.remote_addr, allowed_networks):
        current_app.logger.warning(
            "Registration attempt blocked outside allowed networks",
            extra={"ip": request.remote_addr},
        )
        flash("Registrations are limited to the configured network.", "warning")
        return redirect(url_for("auth.login"))
    totp_disabled = current_app.config.get("DISABLE_TOTP", False)
    require_totp = (not totp_disabled) and current_app.config.get("REQUIRE_TOTP", True)
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter(or_(User.username == form.username.data.lower(), User.email == form.email.data.lower())).first():
            flash("User already exists", "danger")
            return render_template("auth/register.html", form=form)
        totp_secret = pyotp.random_base32()
        user = User(
            username=form.username.data.lower(),
            email=form.email.data.lower(),
            totp_secret=totp_secret,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        current_app.logger.info("New user registered", extra={"user": user.username, "ip": request.remote_addr})
        if require_totp:
            session["setup_user_id"] = user.id
            flash("Account created. Enroll TOTP immediately.", "info")
            return redirect(url_for("auth.setup_totp", user_id=user.id))
        # Optional or disabled TOTP: keep disabled by default and go to login
        user.totp_confirmed = False
        db.session.commit()
        flash("Account created. You can enable TOTP later in settings.", "info")
        return redirect(url_for("auth.login"))
    return render_template("auth/register.html", form=form, totp_disabled=totp_disabled, require_totp=require_totp)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_LOGIN"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("chat.chat"))
    totp_disabled = current_app.config.get("DISABLE_TOTP", False)
    base_require_totp = current_app.config.get("REQUIRE_TOTP", True)
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter(
            or_(User.username == form.username.data.lower(), User.email == form.username.data.lower())
        ).first()
        if not user or not user.check_password(form.password.data):
            if user:
                user.mark_failed_login()
                db.session.commit()
            flash("Invalid credentials", "danger")
            current_app.logger.warning(
                "Login failed",
                extra={"user": form.username.data, "ip": request.remote_addr},
            )
            return render_template("auth/login.html", form=form)
        user.reset_failures()
        db.session.commit()
        require_totp = (not totp_disabled) and (base_require_totp or user.totp_confirmed)
        if require_totp:
            session["pending_2fa"] = user.id
            session["remember_me"] = form.remember.data
            flash("Enter your authenticator code", "info")
            return redirect(url_for("auth.two_factor"))
        # TOTP optional: log in directly
        login_user(user, remember=form.remember.data, fresh=True)
        regenerate_session(session)
        user.totp_confirmed = True
        user.last_login_at = datetime.utcnow()
        db.session.commit()
        return redirect(url_for("chat.chat"))
    return render_template("auth/login.html", form=form)


@auth_bp.route("/2fa", methods=["GET", "POST"])
def two_factor():
    if current_user.is_authenticated:
        return redirect(url_for("chat.chat"))
    user_id = session.get("pending_2fa")
    if not user_id:
        return redirect(url_for("auth.login"))
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for("auth.login"))
    form = TwoFactorForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(form.token.data, valid_window=1):
            flash("Invalid TOTP code", "danger")
            return render_template("auth/two_factor.html", form=form)
        login_user(user, remember=session.get("remember_me", False), fresh=True)
        regenerate_session(session)
        user.totp_confirmed = True
        user.last_login_at = datetime.utcnow()
        db.session.commit()
        current_app.logger.info(
            "2FA success",
            extra={"user": user.username, "ip": request.remote_addr},
        )
        session.pop("pending_2fa", None)
        session.pop("remember_me", None)
        return redirect(url_for("chat.chat"))
    return render_template("auth/two_factor.html", form=form)


@auth_bp.route("/setup-totp/<int:user_id>")
def setup_totp(user_id):
    if current_app.config.get("DISABLE_TOTP", False):
        flash("TOTP is disabled by configuration.", "warning")
        return redirect(url_for("auth.login"))
    if session.get("setup_user_id") != user_id:
        flash("Not authorized", "danger")
        return redirect(url_for("auth.login"))
    user = User.query.get_or_404(user_id)
    provisioning_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
        name=user.email,
        issuer_name=current_app.config.get("QR_ISSUER", "HashWhisper"),
    )
    return render_template(
        "auth/setup_totp.html",
        provisioning_uri=provisioning_uri,
        secret=user.totp_secret,
        user=user,
    )


@auth_bp.route("/totp/qr/<int:user_id>")
def totp_qr(user_id):
    if current_app.config.get("DISABLE_TOTP", False):
        return "TOTP disabled", 403
    if session.get("setup_user_id") != user_id:
        return "Unauthorized", 403
    user = User.query.get_or_404(user_id)
    provisioning_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
        name=user.email,
        issuer_name=current_app.config.get("QR_ISSUER", "HashWhisper"),
    )
    img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


@auth_bp.route("/logout")
def logout():
    lang = session.get("lang")
    logout_user()
    session.clear()
    if lang:
        session["lang"] = lang
    flash("Logged out", "info")
    return redirect(url_for("auth.login"))
