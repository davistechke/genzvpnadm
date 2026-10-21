import json
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


class Server(db.Model):
    """One connectable profile. `data` holds protocol-specific settings as JSON."""
    __tablename__ = "servers"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    country_code = db.Column(db.String(2), default="")
    protocol = db.Column(db.String(12), nullable=False)  # ssh | v2ray | wireguard | custom
    host = db.Column(db.String(255), default="")
    port = db.Column(db.Integer, default=0)
    note = db.Column(db.String(200), default="")
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


class Tweak(db.Model):
    """A reusable set of connection tricks (payload, SNI, host header, proxy, DNS)."""
    __tablename__ = "tweaks"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200), default="")
    payload = db.Column(db.Text, default="")
    sni = db.Column(db.String(255), default="")
    host_header = db.Column(db.String(255), default="")
    proxy_host = db.Column(db.String(255), default="")
    proxy_port = db.Column(db.Integer, default=0)
    dns = db.Column(db.String(120), default="")
    protocols = db.Column(db.String(60), default="")   # csv, empty = all
    server_ids = db.Column(db.String(400), default="")  # csv, empty = all
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    sort = db.Column(db.Integer, default=0)


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
