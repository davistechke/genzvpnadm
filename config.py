import os
from dotenv import load_dotenv

load_dotenv()


def _db_url():
    url = os.getenv("DATABASE_URL", "sqlite:///genzvpn.db")
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-change-me")
    SQLALCHEMY_DATABASE_URI = _db_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "0") == "1"
    # Locks the config the app downloads and the share file (AES-256-GCM). Put the same text in the Android
    # app's CONFIG_KEY. Empty = configs are served as plain JSON.
    CONFIG_KEY = os.getenv("CONFIG_KEY", "")
    SEED_DEFAULT_TWEAK = os.getenv("SEED_DEFAULT_TWEAK", "1") == "1"  # add AIRTEL CAP on first start
    MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "300"))          # the Android app (APK) upload
    MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024
    SMALL_UPLOAD_LIMIT = 2 * 1024 * 1024  # every other upload (payload files, config bundles) stays at 2 MB
    TZ_OFFSET_HOURS = int(os.getenv("TZ_OFFSET_HOURS", "3"))  # for "today" and the daily chart (3 = East Africa Time)
    # Optional: first admin is created automatically on startup when both are set.
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
