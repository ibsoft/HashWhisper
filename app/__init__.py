import socket
import time
from flask import Flask, jsonify, request, session
import click
from sqlalchemy import text
from flask_limiter.errors import RateLimitExceeded
from flask_talisman import Talisman
from flask_login import current_user
from flask_babel import get_locale as babel_get_locale
from .config import Config
from .extensions import db, login_manager, csrf, migrate, limiter, babel
from .security import register_security_hooks
from .tasks import purge_expired_messages
from .presence import create_presence_bus
from .routes.auth import auth_bp
from .routes.chat import chat_bp
from .routes.settings import settings_bp
from .routes.vault import vault_bp


def create_app(config_class: type[Config] = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.default_limits = [app.config.get("RATELIMIT_DEFAULT", "1000 per hour")]
    limiter.init_app(app)
    app.extensions["presence_bus"] = create_presence_bus(app)
    babel.init_app(app, locale_selector=lambda: select_locale(app))
    def current_locale():
        locale = babel_get_locale()
        if locale:
            return str(locale)
        return app.config.get("BABEL_DEFAULT_LOCALE", "en")

    app.add_template_global(current_locale, name="get_locale")

    _net_cache = {"ts": 0.0, "online": True}

    def has_connectivity():
        if not app.config.get("CHECK_INTERNET", True):
            return True
        now = time.monotonic()
        cache_seconds = app.config.get("CHECK_INTERNET_CACHE_SECONDS", 30)
        if now - _net_cache["ts"] < cache_seconds:
            return _net_cache["online"]
        timeout = app.config.get("CHECK_INTERNET_TIMEOUT", 1.5)
        online = True
        try:
            socket.create_connection(("1.1.1.1", 443), timeout=timeout).close()
        except OSError:
            online = False
        _net_cache["ts"] = now
        _net_cache["online"] = online
        return online

    @app.before_request
    def apply_lang_param():
        lang = request.args.get("lang")
        if lang and lang in app.config.get("LANGUAGES", {}):
            session["lang"] = lang

    @app.before_request
    def guard_maintenance():
        if not app.config.get("MAINTENANCE_MODE"):
            return
        # allow static assets and service worker so we can show the page
        if request.endpoint == "static" or request.path.startswith("/static"):
            return
        if request.path.endswith("/sw.js"):
            return
        msg = app.config.get("MAINTENANCE_MESSAGE") or "We'll be back shortly."
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({"error": "maintenance", "message": msg}), 503
        return render_template("maintenance.html", message=msg), 503

    @app.before_request
    def guard_connectivity():
        if not app.config.get("CHECK_INTERNET", True):
            return
        # Skip static assets and service worker to allow offline shell.
        if request.endpoint == "static" or request.path.startswith("/static"):
            return
        if request.path.endswith("/sw.js"):
            return
        online = has_connectivity()
        if online:
            return
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({"error": "offline", "message": "No internet connectivity detected."}), 503
        return render_template("offline.html"), 503

    # Security headers via Talisman
    talisman = Talisman(
        app,
        content_security_policy=app.config["SECURITY_CSP"],
        permissions_policy=app.config.get("FEATURE_POLICY"),
        force_https=True,
        force_https_permanent=True,
        session_cookie_secure=True,
        content_security_policy_nonce_in=None,
    )
    register_security_hooks(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(vault_bp)

    with app.app_context():
        db.create_all()

    @app.errorhandler(RateLimitExceeded)
    def handle_ratelimit(e):  # pragma: no cover - small UX helper
        message = "You’ve hit the request limit. Please wait a moment and try again."
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({"error": "rate_limited", "message": message}), 429
        return message, 429

    @app.cli.command("purge-expired")
    def purge_expired():
        """Delete expired messages and blobs."""
        purge_expired_messages()
        print("Expired encrypted payloads purged")

    @app.cli.command("list-users")
    def list_users():
        """Print all users with id, username, email, and TOTP status."""
        users = User.query.order_by(User.id).all()
        for user in users:
            print(f"{user.id}\t{user.username}\t{user.email}\tTOTP={'yes' if user.totp_confirmed else 'no'}")

    @app.cli.command("delete-user")
    @click.argument("user_id", type=int)
    def delete_user(user_id: int):
        """Delete a user by id."""
        user = User.query.get(user_id)
        if not user:
            print(f"No user with id={user_id}")
            return
        db.session.delete(user)
        db.session.commit()
        print(f"Deleted user {user_id}")

    @app.cli.command("wipe-data")
    @click.option("--yes", is_flag=True, help="Confirm destructive wipe.")
    def wipe_data(yes: bool):
        """Danger: truncate all tables and reset ids (Postgres)."""
        if not yes:
            print("Add --yes to confirm wipe.")
            return
        tables = [
            "media_blobs",
            "message_reactions",
            "presence_events",
            "integrity_chain",
            "messages",
            "group_memberships",
            '"group"',
            '"user"',
        ]
        sql = f"TRUNCATE TABLE {', '.join(tables)} RESTART IDENTITY CASCADE;"
        with db.engine.begin() as conn:
            conn.execute(text(sql))
        print("All data wiped (database only). Delete storage folder separately if needed.")

    return app


def select_locale(app: Flask):
    """Resolve locale from user preference or Accept-Language."""
    try:
        # Honor explicit selections from form posts (e.g., Settings) immediately.
        if request.method == "POST":
            form_lang = request.form.get("language")
            if form_lang and form_lang in app.config.get("LANGUAGES", {}):
                session["lang"] = form_lang
                return form_lang

        lang_override = session.get("lang")
        if lang_override and lang_override in app.config.get("LANGUAGES", {}):
            return lang_override
    except Exception:
        pass
    try:
        if current_user and getattr(current_user, "is_authenticated", False):
            lang = (current_user.language or "").lower()
            if lang in app.config.get("LANGUAGES", {}):
                # Keep session aligned so PWA/cached pages pick up the chosen language consistently.
                if session.get("lang") != lang:
                    session["lang"] = lang
                return lang
    except Exception:
        pass
    try:
        preferred = request.accept_languages.best_match(
            list(app.config.get("LANGUAGES", {}).keys()),
            default=app.config.get("BABEL_DEFAULT_LOCALE", "en"),
        )
        return preferred or app.config.get("BABEL_DEFAULT_LOCALE", "en")
    except Exception:
        return app.config.get("BABEL_DEFAULT_LOCALE", "en")
