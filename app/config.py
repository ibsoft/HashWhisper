import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get("HASHWHISPER_SECRET", os.urandom(32))
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "HASHWHISPER_DATABASE_URI", "sqlite:///hashwhisper.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_URL = os.environ.get("HASHWHISPER_REDIS_URL")
    _rl_storage = os.environ.get("HASHWHISPER_RATELIMIT_URI")
    if _rl_storage and _rl_storage.strip().startswith("$"):
        _rl_storage = None
    RATELIMIT_STORAGE_URI = _rl_storage or REDIS_URL or "memory://"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    WTF_CSRF_TIME_LIMIT = 3600
    MAX_CONTENT_LENGTH = int(os.environ.get("HASHWHISPER_MAX_UPLOAD", 10 * 1024 * 1024))
    UPLOAD_FOLDER = os.environ.get("HASHWHISPER_UPLOAD_FOLDER", "app/storage")
    ALLOWED_MIMETYPES = {
        "image/jpeg",
        "image/png",
        "image/webp",
        "image/gif",
        "image/heic",
        "image/heif",
        "video/webm",
        "video/quicktime",
        "audio/mpeg",
        "audio/ogg",
        "audio/webm",
        "audio/wav",
        "audio/mp4",
        "audio/aac",
        "audio/mp3",
        "application/pdf",
        "text/plain",
        "text/csv",
        "application/json",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.oasis.opendocument.text",
        "application/vnd.oasis.opendocument.spreadsheet",
        "application/vnd.oasis.opendocument.presentation",
    }
    
    SECURITY_CSP = {
        "default-src": ["'self'"],
        "img-src": ["'self'", "data:", "blob:"],
        "media-src": ["'self'", "blob:"],
        "font-src": ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
        "style-src": ["'self'", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
        "script-src": ["'self'", "https://cdn.jsdelivr.net", "'unsafe-inline'"],
        "connect-src": ["'self'"],
        "frame-src": ["'self'", "https://www.youtube.com"],
        "frame-ancestors": ["'none'"],
    }

    # Rate limiting
    RATELIMIT_DEFAULT = "1000 per hour"
    RATELIMIT_STRATEGY = "fixed-window"
    RATELIMIT_LOGIN = "30 per minute"
    RATELIMIT_REGISTER = "10 per minute"

    # AES-GCM client side requirements
    CLIENT_AAD = "HashWhisper:v1"

    MESSAGE_RETENTION_DAYS = int(os.environ.get("HASHWHISPER_RETENTION_DAYS", 365))
    PRESENCE_BROADCAST_TTL = 30

    QR_ISSUER = "HashWhisper"
    DISABLE_TOTP = os.environ.get("HASHWHISPER_DISABLE_TOTP", "false").lower() == "true"
    REQUIRE_TOTP = False if DISABLE_TOTP else os.environ.get("HASHWHISPER_REQUIRE_TOTP", "true").lower() == "true"
    APP_TITLE = os.environ.get("HASHWHISPER_APP_TITLE", "HashWhisper")
    APP_VERSION = os.environ.get("HASHWHISPER_APP_VERSION", "2.0.1")
