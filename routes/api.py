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
    data = request.get_json(silent=True) or {}
    device = str(data.get("device", ""))
    if not re.fullmatch(r"[0-9a-f-]{16,64}", device):
        current_app.logger.warning("presence: rejected a report with a bad device id from %s", ip)
        return Response(status=400)
    # Reports arrive through the VPN, so many phones share one address (the VPN server's). Limit per phone, with a
    # generous limit per address on top to stop flooding.
    for key, limit in ((f"presence:dev:{device}", 12), (f"presence:ip:{ip}", 600)):
        if throttled(key, limit=limit, window=60):
            current_app.logger.warning("presence: too many reports from %s (%s)", device[:6], ip)
            return Response(status=429)
        record_failure(key)  # counts every call, not only failures
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
    # The phone's own address as the app reports it (its public address from before connecting, or its carrier-network
    # address). The request itself comes through the VPN, so the address the server sees is the VPN's, not the phone's.
    row.ip, row.exit_ip = (_ip_or_blank(data.get("phone_ip", "")) or ip)[:64], _ip_or_blank(data.get("exit_ip", ""))
    row.app_version, row.last_seen = str(data.get("app", ""))[:20], now
    db.session.commit()
    return Response(status=204)
