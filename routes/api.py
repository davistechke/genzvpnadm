import gzip
import ipaddress
import re
from datetime import timedelta

from flask import Blueprint, Response, current_app, request

from models import Presence, Tweak, db, utcnow
from routes.common import record_failure, throttled
from services.bundle import body_and_etag, build_bundle
from services.lock import lock

bp = Blueprint("api", __name__, url_prefix="/api/v1")


@bp.get("/config")
def config():
    """Public, no login. Small on purpose: ETag + gzip so it costs users almost no data."""
    body, etag = body_and_etag(build_bundle(public=True))
    headers = {"ETag": etag, "Cache-Control": "no-cache", "Content-Type": "application/json; charset=utf-8",
               "Access-Control-Allow-Origin": "*"}
    if request.headers.get("If-None-Match") == etag:
        return Response(status=304, headers={"ETag": etag})
    key = current_app.config["CONFIG_KEY"]
    if key:  # the ETag was computed on the plain text, so caching still works with a fresh random nonce
        body = lock(body, key)
    if "gzip" in request.headers.get("Accept-Encoding", "") and len(body) > 400:
        body = gzip.compress(body, 6)
        headers["Content-Encoding"] = "gzip"
    return Response(body, headers=headers)


def _ip_or_blank(text):
    try:
        return str(ipaddress.ip_address(str(text).strip()))
    except ValueError:
        return ""


@bp.post("/presence")
def presence():
    """The app calls this every 30 seconds while the VPN is connected, and once more with state "off" when it disconnects.
    It tells the panel that this phone is online, on which tweak, and the address websites see. Nothing about
    what the user does online is sent."""
    ip = request.remote_addr or ""
    key = f"presence:{ip}"
    if throttled(key, limit=40, window=60):
        return Response(status=429)
    record_failure(key)  # counts every call from this address, not only failures
    data = request.get_json(silent=True) or {}
    device = str(data.get("device", ""))
    if not re.fullmatch(r"[0-9a-f-]{16,64}", device):
        return Response(status=400)
    now = utcnow()
    Presence.query.filter(Presence.last_seen < now - timedelta(seconds=current_app.config["PRESENCE_KEEP_SECONDS"])).delete()
    if data.get("state") == "off":
        Presence.query.filter_by(device=device).delete()
        db.session.commit()
        return Response(status=204)
    try:
        tweak_id = int(data.get("tweak"))
    except (TypeError, ValueError):
        tweak_id = None
    tweak = db.session.get(Tweak, tweak_id) if tweak_id else None
    row = db.session.get(Presence, device)
    fresh = row is None or row.tweak_id != tweak_id or \
        (now - row.last_seen).total_seconds() > current_app.config["ONLINE_SECONDS"] * 2
    if row is None:
        row = Presence(device=device)
        db.session.add(row)
    if fresh:
        row.connected_at = now
    row.tweak_id, row.tweak_name = tweak_id, (tweak.name if tweak else "")[:80]
    row.ip, row.exit_ip = ip[:64], _ip_or_blank(data.get("exit_ip", ""))
    row.app_version, row.last_seen = str(data.get("app", ""))[:20], now
    db.session.commit()
    return Response(status=204)
