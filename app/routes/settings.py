import io
import qrcode
import pyotp
from flask import Blueprint, flash, redirect, render_template, url_for, current_app, send_file, session
from flask_login import current_user, login_required
from flask_babel import _

from ..extensions import db
from ..forms import SettingsForm
from ..models import User

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


@settings_bp.route("/", methods=["GET", "POST"])
@login_required
def settings():
    form = SettingsForm(obj=current_user)
    totp_disabled = current_app.config.get("DISABLE_TOTP", False)
    base_require_totp = current_app.config.get("REQUIRE_TOTP", True)
    require_totp = (not totp_disabled) and base_require_totp
    allowed_langs = set(current_app.config.get("LANGUAGES", {}).keys())
    default_lang = current_app.config.get("BABEL_DEFAULT_LOCALE", "en")
    if current_user.language not in allowed_langs:
        current_user.language = default_lang
        form.language.data = default_lang
    # If TOTP is mandatory, hide the toggle and ensure enable_totp is true
    if require_totp:
        form.enable_totp.data = True
    else:
        # For optional TOTP, default checkbox reflects current status on GET
        if not form.is_submitted():
            form.enable_totp.data = bool(current_user.totp_confirmed)
    if totp_disabled:
        form.enable_totp.data = False
        form.enable_totp.render_kw = {**(form.enable_totp.render_kw or {}), "disabled": True}
    if form.validate_on_submit():
        current_user.preferred_theme = form.preferred_theme.data
        lang_choice = form.language.data if form.language.data in allowed_langs else default_lang
        current_user.language = lang_choice
        session["lang"] = lang_choice
        current_user.notifications_enabled = form.notifications_enabled.data
        current_user.timezone = form.timezone.data
        if not require_totp and not totp_disabled:
            want_totp = form.enable_totp.data
            if want_totp:
                current_user.totp_confirmed = True
            else:
                current_user.totp_confirmed = False
        db.session.commit()
        flash(_("Settings updated"), "success")
        return redirect(url_for("settings.settings"))
    # Always prepare a provisioning URI for the current user
    totp_uri = pyotp.totp.TOTP(current_user.totp_secret).provisioning_uri(
        name=current_user.email,
        issuer_name=current_app.config.get("QR_ISSUER", "HashWhisper"),
    )
    return render_template(
        "settings/settings.html",
        form=form,
        require_totp=require_totp,
        totp_disabled=totp_disabled,
        totp_uri=totp_uri,
    )


@settings_bp.route("/totp/qr")
@login_required
def settings_totp_qr():
    if current_app.config.get("DISABLE_TOTP", False):
        return "TOTP disabled", 403
    totp_uri = pyotp.totp.TOTP(current_user.totp_secret).provisioning_uri(
        name=current_user.email,
        issuer_name=current_app.config.get("QR_ISSUER", "HashWhisper"),
    )
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")
