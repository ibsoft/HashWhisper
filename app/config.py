import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get("HASHWHISPER_SECRET", os.urandom(32))
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "HASHWHISPER_DATABASE_URI", "sqlite:///hashwhisper.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_URL = os.environ.get("HASHWHISPER_REDIS_URL")
    RATELIMIT_STORAGE_URI = os.environ.get("HASHWHISPER_RATELIMIT_URI", REDIS_URL or "memory://")
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
        "video/mp4",
        "video/webm",
        "audio/mpeg",
        "audio/ogg",
        "audio/webm",
        "audio/wav",
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
    RATELIMIT_DEFAULT = "200/hour"
    RATELIMIT_STRATEGY = "fixed-window"
    RATELIMIT_LOGIN = "5 per minute"
    RATELIMIT_REGISTER = "3 per minute"

    # AES-GCM client side requirements
    CLIENT_AAD = "HashWhisper:v1"

    MESSAGE_RETENTION_DAYS = int(os.environ.get("HASHWHISPER_RETENTION_DAYS", 7))
    PRESENCE_BROADCAST_TTL = 30

    QR_ISSUER = "HashWhisper"
