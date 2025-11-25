from flask import Flask
from flask_talisman import Talisman
from .config import Config
from .extensions import db, login_manager, csrf, migrate, limiter
from .security import register_security_hooks
from .tasks import purge_expired_messages
from .presence import create_presence_bus
from .routes.auth import auth_bp
from .routes.chat import chat_bp
from .routes.settings import settings_bp


def create_app(config_class: type[Config] = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    app.extensions["presence_bus"] = create_presence_bus(app)

    # Security headers via Talisman
    talisman = Talisman(
        app,
        content_security_policy=app.config["SECURITY_CSP"],
        force_https=True,
        force_https_permanent=True,
        session_cookie_secure=True,
        content_security_policy_nonce_in=None,
    )
    register_security_hooks(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(settings_bp)

    with app.app_context():
        db.create_all()

    @app.cli.command("purge-expired")
    def purge_expired():
        """Delete expired messages and blobs."""
        purge_expired_messages()
        print("Expired encrypted payloads purged")

    return app
