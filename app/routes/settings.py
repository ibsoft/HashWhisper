from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import current_user, login_required

from ..extensions import db
from ..forms import SettingsForm

settings_bp = Blueprint("settings", __name__, url_prefix="/settings")


@settings_bp.route("/", methods=["GET", "POST"])
@login_required
def settings():
    form = SettingsForm(obj=current_user)
    if form.validate_on_submit():
        current_user.preferred_theme = form.preferred_theme.data
        current_user.language = form.language.data
        current_user.notifications_enabled = form.notifications_enabled.data
        current_user.timezone = form.timezone.data
        db.session.commit()
        flash("Settings updated", "success")
        return redirect(url_for("settings.settings"))
    return render_template("settings/settings.html", form=form)
