import functools
import secrets
import time

from flask import abort, redirect, request, session, url_for

from models import Admin, db


def current_admin():
    uid = session.get("admin_uid")
    return db.session.get(Admin, uid) if uid else None


def admin_required(f):
    @functools.wraps(f)
    def wrapper(*a, **k):
        if not current_admin():
            return redirect(url_for("admin.login"))
        return f(*a, **k)
    return wrapper


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Session expired. Refresh the page and try again.")


_attempts = {}


def throttled(key, limit=6, window=300):
    now = time.time()
    _attempts[key] = [t for t in _attempts.get(key, []) if now - t < window]
    return len(_attempts[key]) >= limit


def record_failure(key):
    _attempts.setdefault(key, []).append(time.time())


def clear_failures(key):
    _attempts.pop(key, None)
