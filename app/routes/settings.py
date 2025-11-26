import io
import qrcode
import pyotp
from flask import Blueprint, flash, redirect, render_template, url_for, current_app, send_file
from flask_login import current_user, login_required

from ..extensions import db
from ..forms import SettingsForm
from ..models import User

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


@settings_bp.route("/", methods=["GET", "POST"])
@login_required
def settings():
    form = SettingsForm(obj=current_user)
    # If TOTP is mandatory, hide the toggle and ensure enable_totp is true
    if current_app.config.get("REQUIRE_TOTP", True):
        form.enable_totp.data = True
    else:
        # For optional TOTP, default checkbox reflects current status on GET
        if not form.is_submitted():
            form.enable_totp.data = bool(current_user.totp_confirmed)
    if form.validate_on_submit():
        current_user.preferred_theme = form.preferred_theme.data
        current_user.language = form.language.data
        current_user.notifications_enabled = form.notifications_enabled.data
        current_user.timezone = form.timezone.data
        if not current_app.config.get("REQUIRE_TOTP", True):
            want_totp = form.enable_totp.data
            if want_totp:
                current_user.totp_confirmed = True
            else:
                current_user.totp_confirmed = False
        db.session.commit()
        flash("Settings updated", "success")
        return redirect(url_for("settings.settings"))
    # Always prepare a provisioning URI for the current user
    totp_uri = pyotp.totp.TOTP(current_user.totp_secret).provisioning_uri(
        name=current_user.email,
        issuer_name=current_app.config.get("QR_ISSUER", "HashWhisper"),
    )
    return render_template(
        "settings/settings.html",
        form=form,
        require_totp=current_app.config.get("REQUIRE_TOTP", True),
        totp_uri=totp_uri,
    )


@settings_bp.route("/totp/qr")
@login_required
def settings_totp_qr():
    totp_uri = pyotp.totp.TOTP(current_user.totp_secret).provisioning_uri(
        name=current_user.email,
        issuer_name=current_app.config.get("QR_ISSUER", "HashWhisper"),
    )
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")
