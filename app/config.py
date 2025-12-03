import ipaddress
import os
import re
from datetime import timedelta
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

def _resolve_storage_path(env_var: str, default: Path) -> str:
    raw_value = os.environ.get(env_var)
    if raw_value:
        candidate = Path(os.path.expanduser(raw_value))
        if not candidate.is_absolute():
            candidate = BASE_DIR / candidate
    else:
        candidate = default
    return str(candidate.resolve())


def _parse_networks(raw_value: str | None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    if not raw_value:
        return []
    networks = []
    for part in raw_value.split(","):
        candidate = part.strip()
        if not candidate:
            continue
        try:
            networks.append(ipaddress.ip_network(candidate, strict=False))
        except ValueError:
            continue
    return networks


def _normalize_font_size(raw: str | None, default: str) -> str:
    value = (raw or "").strip()
    if not value:
        return default
    if re.fullmatch(r"\d+(\.\d+)?", value):
        return f"{value}px"
    return value


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
    _cookie_secure = os.environ.get("HASHWHISPER_COOKIE_SECURE", "true").lower() == "true"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _cookie_secure
    REMEMBER_COOKIE_SECURE = _cookie_secure
    REMEMBER_COOKIE_HTTPONLY = True
    CHECK_INTERNET = os.environ.get("HASHWHISPER_CHECK_INTERNET", "true").lower() == "true"
    CHECK_INTERNET_TIMEOUT = float(os.environ.get("HASHWHISPER_CHECK_INTERNET_TIMEOUT", 1.5))
    CHECK_INTERNET_CACHE_SECONDS = int(os.environ.get("HASHWHISPER_CHECK_INTERNET_CACHE_SECONDS", 30))
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    WTF_CSRF_TIME_LIMIT = 3600
    MAX_CONTENT_LENGTH = int(os.environ.get("HASHWHISPER_MAX_UPLOAD", 10 * 1024 * 1024))
    _upload_default = BASE_DIR / "app" / "storage"
    UPLOAD_FOLDER = _resolve_storage_path("HASHWHISPER_UPLOAD_FOLDER", _upload_default)
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
        "script-src": ["'self'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com", "'unsafe-inline'"],
        # Allow blob: for media/object URLs generated client-side (e.g., decrypted media fetches).
        "connect-src": ["'self'", "blob:", "https://api.openai.com", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
        "frame-src": ["'self'", "https://www.youtube.com"],
        "frame-ancestors": ["'none'"],
    }
    FEATURE_POLICY = {
        # Permissions-Policy header (formerly Feature-Policy)
        "microphone": ["'self'"],
        "camera": ["'self'"],
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

    APP_TITLE = os.environ.get("HASHWHISPER_APP_TITLE", "HashWhisper")
    QR_ISSUER = os.environ.get("HASHWHISPER_QR_ISSUER") or APP_TITLE
    DISABLE_TOTP = os.environ.get("HASHWHISPER_DISABLE_TOTP", "false").lower() == "true"
    REQUIRE_TOTP = False if DISABLE_TOTP else os.environ.get("HASHWHISPER_REQUIRE_TOTP", "true").lower() == "true"
    LANGUAGES = {"en": "English", "el": "Ελληνικά"}
    BABEL_DEFAULT_LOCALE = "en"
    # Flask-Babel resolves this relative to app.root_path; keep it to the translations folder at repo root.
    BABEL_TRANSLATION_DIRECTORIES = "translations"
    MAINTENANCE_MODE = os.environ.get("HASHWHISPER_MAINTENANCE", "false").lower() == "true"
    APP_VERSION = os.environ.get("HASHWHISPER_APP_VERSION", "9.0.3")
    MAINTENANCE_MESSAGE = os.environ.get(
        "HASHWHISPER_MAINTENANCE_MESSAGE",
        "We are updating HashWhisper. Please check back in a few minutes.",
    )

    # AI Assistant (optional)
    AI_ENABLED = os.environ.get("HASHWHISPER_AI_ENABLED", "false").lower() == "true"
    AI_API_KEY = os.environ.get("HASHWHISPER_AI_API_KEY", "")
    AI_MODEL = os.environ.get("HASHWHISPER_AI_MODEL", "gpt-4o-mini")
    AI_TIMEOUT = int(os.environ.get("HASHWHISPER_AI_TIMEOUT", 20))
    AI_SYSTEM_PROMPT = (
        "You are Leonard (Λεονάρδος in Greek) a concise, friendly assistant helping inside an end-to-end encrypted chat app. "
        "Decline and warn if a request is malicious, dangerous, ofensive or violates safety. "
        "When asked to summarize a meeting or chat history, rely strictly on the supplied messages, focus on decisions, action items, and next steps, and reply with a concise, copy-friendly summary."
    )
    AI_RATELIMIT = os.environ.get("HASHWHISPER_AI_RATELIMIT", "5 per minute")

    # User controls
    ALLOW_MESSAGE_DELETE = os.environ.get("HASHWHISPER_ALLOW_MESSAGE_DELETE", "true").lower() == "true"
    _avatar_default = _upload_default / "avatars"
    AVATAR_UPLOAD_FOLDER = _resolve_storage_path("HASHWHISPER_AVATAR_UPLOAD_FOLDER", _avatar_default)
    MAX_AVATAR_SIZE = int(os.environ.get("HASHWHISPER_MAX_AVATAR_SIZE", 2 * 1024 * 1024))  # 2MB default
    ALLOW_USER_REGISTRATIONS = os.environ.get("HASHWHISPER_ALLOW_USER_REGISTRATIONS", "true").lower() == "true"
    _registration_network_env = os.environ.get("HASHWHISPER_REGISTRATION_NETWORKS")
    REGISTRATION_ALLOWED_NETWORKS = tuple(_parse_networks(_registration_network_env))

    FONT_FAMILY = os.environ.get(
        "HASHWHISPER_FONT_FAMILY",
        "'Space Grotesk', 'Segoe UI', 'Apple Color Emoji', 'Segoe UI Emoji', 'Noto Color Emoji', sans-serif"
    )
    FONT_SIZE = _normalize_font_size(os.environ.get("HASHWHISPER_FONT_SIZE"), "12px")
