import secrets
from datetime import datetime
from flask import current_app, redirect, request, session, url_for, g
from flask_login import current_user
from werkzeug.middleware.proxy_fix import ProxyFix


def register_security_hooks(app):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_for=1)

    @app.before_request
    def enforce_https():
        if not request.is_secure and not app.testing:
            return redirect(request.url.replace("http://", "https://"), code=301)

    @app.before_request
    def set_security_context():
        g.request_started = datetime.utcnow()

    @app.after_request
    def set_headers(response):
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    @app.before_request
    def prevent_session_fixation():
        if current_user.is_authenticated:
            stored = session.get("_last_user")
            if stored is None:
                session["_last_user"] = current_user.get_id()
            elif stored != current_user.get_id():
                session.clear()
                return redirect(url_for("auth.logout"))
        else:
            session.pop("_last_user", None)

    @app.after_request
    def mark_user_session(response):
        if current_user.is_authenticated:
            session["_last_user"] = current_user.get_id()
        return response

    @app.after_request
    def add_cache_headers(response):
        response.cache_control.private = True
        response.cache_control.no_store = True
        return response


def regenerate_session(sess):
    data = dict(sess)
    sess.clear()
    sess.update(data)
    sess["_session_nonce"] = secrets.token_hex(16)
