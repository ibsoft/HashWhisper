import secrets
from datetime import datetime, timedelta

from flask import Blueprint, current_app, jsonify, render_template, request
from flask_login import current_user, login_required

from ..extensions import db, limiter
from ..models import OneTimeSecret


vault_bp = Blueprint("vault", __name__)


def _generate_slug() -> str:
    for _ in range(5):
        candidate = secrets.token_urlsafe(10)
        if not OneTimeSecret.query.filter_by(slug=candidate).first():
            return candidate
    return secrets.token_urlsafe(8)


@vault_bp.route("/vault/create", methods=["POST"])
@login_required
@limiter.limit(lambda: current_app.config.get("VAULT_RATELIMIT", "15 per hour"))
def create_vault_entry():
    payload = request.get_json(silent=True) or {}
    ciphertext = (payload.get("ciphertext") or "").strip()
    nonce = (payload.get("nonce") or "").strip()
    auth_tag = (payload.get("auth_tag") or "").strip()
    title = (payload.get("title") or "").strip()
    burn_after_read = bool(payload.get("burn_after_read", True))
    max_views = int(payload.get("max_views") or 1)
    expires_hours = payload.get("expires_hours")

    errors = []
    if not ciphertext:
        errors.append("ciphertext")
    if not nonce:
        errors.append("nonce")
    if not auth_tag:
        errors.append("auth_tag")
    if errors:
        return jsonify({"error": "missing_fields", "fields": errors}), 400

    if burn_after_read:
        max_views = 1
    else:
        max_views = max(1, min(max_views, 10))
    if isinstance(expires_hours, (int, float)):
        hours = expires_hours
    else:
        try:
            hours = int(expires_hours)
        except Exception:
            hours = None
    if hours is not None and hours >= 0:
        if hours == 0:
            expires_at = None
        else:
            hours = min(hours, 168)
            expires_at = datetime.utcnow() + timedelta(hours=hours)
    else:
        expires_at = datetime.utcnow() + timedelta(hours=24)

    slug = _generate_slug()
    entry = OneTimeSecret(
        slug=slug,
        title=title or None,
        ciphertext=ciphertext,
        nonce=nonce,
        auth_tag=auth_tag,
        burn_after_read=burn_after_read,
        max_views=max_views,
        expires_at=expires_at,
        created_by=current_user.id,
    )
    db.session.add(entry)
    db.session.commit()
    return jsonify(
        {
            "slug": slug,
            "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
            "max_views": max_views,
            "burn_after_read": burn_after_read,
        }
    )


@vault_bp.route("/api/vault/<slug>")
def fetch_vault_entry(slug):
    entry = OneTimeSecret.query.filter_by(slug=slug).first()
    if not entry:
        return jsonify({"error": "not_found"}), 404

    now = datetime.utcnow()
    if entry.expires_at and entry.expires_at < now:
        if not entry.burned:
            entry.burned = True
            db.session.commit()
        return jsonify({"error": "expired"}), 410
    if entry.burned:
        return jsonify({"error": "burned"}), 410

    entry.view_count = (entry.view_count or 0) + 1
    if entry.view_count >= entry.max_views:
        entry.burned = True
    db.session.commit()

    remaining = max(entry.max_views - entry.view_count, 0)
    return jsonify(
        {
            "slug": entry.slug,
            "title": entry.title,
            "ciphertext": entry.ciphertext,
            "nonce": entry.nonce,
            "auth_tag": entry.auth_tag,
            "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
            "views_remaining": remaining,
            "max_views": entry.max_views,
            "burn_after_read": entry.burn_after_read,
        }
    )


@vault_bp.route("/vault/<slug>")
def view_vault(slug):
    return render_template("vault/view.html", slug=slug)
