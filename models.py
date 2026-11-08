import json
import re
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


def utcnow():
    return datetime.utcnow()


class Admin(db.Model):
    __tablename__ = "admins"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)


class Tweak(db.Model):
    """One ready-to-connect config. There are no separate servers: the tweak holds everything the app needs.

    `data` holds protocol-specific settings as JSON (SSH: username, password, payload, proxy; others: the outbound).
    The table has its own name so an older database that still has the previous `servers` / `tweaks` tables
    keeps working: those tables are simply left unused.
    """
    __tablename__ = "tweak_configs"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    country_code = db.Column(db.String(2), default="")
    description = db.Column(db.String(200), default="")
    protocol = db.Column(db.String(12), nullable=False)  # ssh | v2ray | wireguard | custom
    host = db.Column(db.String(255), default="")
    port = db.Column(db.Integer, default=0)
    expires_at = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    sort = db.Column(db.Integer, default=0)
    data = db.Column(db.Text, default="{}")
    created_at = db.Column(db.DateTime, default=utcnow)

    @property
    def cfg(self):
        try:
            return json.loads(self.data or "{}")
        except ValueError:
            return {}

    @cfg.setter
    def cfg(self, value):
        self.data = json.dumps(value, separators=(",", ":"))


class Notice(db.Model):
    """A message the admin posts; shows up in the app's Notifications screen."""
    __tablename__ = "notices"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80), nullable=False)
    message = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=utcnow)


class Setting(db.Model):
    __tablename__ = "settings"
    key = db.Column(db.String(40), primary_key=True)
    value = db.Column(db.Text, default="")


def get_setting(key, default=""):
    row = db.session.get(Setting, key)
    return row.value if row else default


def set_setting(key, value):
    row = db.session.get(Setting, key)
    if row:
        row.value = value
    else:
        db.session.add(Setting(key=key, value=value))


def bump_rev():
    """Every admin change calls this so apps can tell the config changed."""
    set_setting("rev", str(int(get_setting("rev", "0") or 0) + 1))


# ---------------------------------------------------------------- the Android app download
CHUNK = 2 * 1024 * 1024   # an APK is stored in the database in pieces of exactly this size (so it survives redeploys)


def slugify(text):
    return re.sub(r"[^a-z0-9.]+", "-", (text or "").lower()).strip("-") or "app"


class ApkRelease(db.Model):
    """One uploaded version of the Android app."""
    __tablename__ = "apk_releases"
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(60), nullable=False, default="GenzVPN")
    version = db.Column(db.String(30), nullable=False)
    notes = db.Column(db.Text, default="")
    size = db.Column(db.BigInteger, default=0)
    sha256 = db.Column(db.String(64), default="")
    downloads = db.Column(db.Integer, default=0, nullable=False)
    is_published = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)

    @property
    def filename(self):
        return f"{slugify(self.app_name)}-{slugify(self.version)}.apk"


class ApkChunk(db.Model):
    __tablename__ = "apk_chunks"
    release_id = db.Column(db.Integer, db.ForeignKey("apk_releases.id"), primary_key=True)
    idx = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.LargeBinary, nullable=False)


class ApkDownload(db.Model):
    """One download. The visitor is a salted hash of address and browser, never the address itself."""
    __tablename__ = "apk_downloads"
    id = db.Column(db.Integer, primary_key=True)
    release_id = db.Column(db.Integer, db.ForeignKey("apk_releases.id"), nullable=False, index=True)
    visitor = db.Column(db.String(16), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)


class Presence(db.Model):
    """Who is connected right now. The app reports every 30 seconds while the VPN is on and once when it turns off.
    Rows are removed on disconnect and anything silent for an hour is purged, so nothing builds up as history."""
    __tablename__ = "presence"
    device = db.Column(db.String(64), primary_key=True)      # random id made by the app on first run, not a hardware id
    tweak_id = db.Column(db.Integer)
    tweak_name = db.Column(db.String(80), default="")
    ip = db.Column(db.String(64), default="")                # the phone's address, as the server sees it
    exit_ip = db.Column(db.String(64), default="")           # the address websites see through the VPN, as the app reports it
    app_version = db.Column(db.String(20), default="")
    connected_at = db.Column(db.DateTime, default=utcnow)
    last_seen = db.Column(db.DateTime, default=utcnow, index=True)
