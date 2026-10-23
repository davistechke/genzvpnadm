"""The config bundle the app downloads (and admins can export/import)."""
import hashlib
import json
from datetime import datetime

from models import Notice, Tweak, bump_rev, db, get_setting, set_setting, utcnow

FORMAT = "genzvpn-config"


def _date(text):
    try:
        return datetime.strptime(text, "%Y-%m-%d") if text else None
    except ValueError:
        return None


def tweak_to_dict(t, full=False):
    d = {"id": t.id, "name": t.name, "country": t.country_code or "", "description": t.description or "",
         "protocol": t.protocol, "dns": "",
         "expires_at": t.expires_at.strftime("%Y-%m-%d") if t.expires_at else ""}
    if full:  # backups keep what the public bundle leaves out
        d.update(active=t.is_active, sort=t.sort or 0)
    cfg = t.cfg
    if t.protocol == "ssh":
        d["ssh"] = {"host": t.host or "", "port": t.port or 22,
                    **{k: cfg.get(k, "") for k in ("username", "password", "payload", "sni", "proxy_host")},
                    "proxy_port": int(cfg.get("proxy_port") or 0)}
    else:
        d.update(host=t.host or "", port=t.port or 0, outbound=cfg.get("outbound", {}))
    return d


def notice_to_dict(n):
    return {"id": n.id, "title": n.title, "message": n.message or "",
            "date": n.created_at.strftime("%Y-%m-%d") if n.created_at else ""}


def build_bundle(public=True):
    q = Tweak.query
    tweaks = q.filter_by(is_active=True).order_by(Tweak.sort, Tweak.name).all() if public else \
        q.order_by(Tweak.sort, Tweak.name).all()
    now = utcnow()
    tweaks = [t for t in tweaks if not (public and t.expires_at and t.expires_at < now)]
    return {"format": FORMAT, "version": int(get_setting("rev", "0") or 0),
            "channel_url": get_setting("channel_url", ""),
            "notifications": [notice_to_dict(n) for n in Notice.query.order_by(Notice.id.desc()).limit(20)],
            "tweaks": [tweak_to_dict(t, not public) for t in tweaks]}


def body_and_etag(bundle):
    body = json.dumps(bundle, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode()
    return body, '"' + hashlib.sha256(body).hexdigest()[:24] + '"'


def _import_one(d, i):
    protocol = d.get("protocol") or ("ssh" if d.get("ssh") else "v2ray")
    ssh = d.get("ssh") or {}
    if protocol == "ssh":  # old backups kept host/port on the server itself, not inside "ssh"
        host, port = ssh.get("host") or d.get("host", ""), int(ssh.get("port") or d.get("port") or 22)
    else:
        host, port = d.get("host", ""), int(d.get("port") or 0)
    t = Tweak(name=d.get("name", "Tweak")[:80], country_code=(d.get("country") or "")[:2].upper(),
              description=(d.get("description") or d.get("note") or "")[:200], protocol=protocol,
              host=host, port=port, sort=d.get("sort", i), is_active=bool(d.get("active", True)),
              expires_at=_date(d.get("expires_at")))
    if protocol == "ssh":
        t.cfg = {k: ssh.get(k, "") for k in ("username", "password", "payload", "sni", "proxy_host")}
        t.cfg = {**t.cfg, "proxy_port": int(ssh.get("proxy_port") or 0)}
    else:
        t.cfg = {"outbound": d.get("outbound", {})}
    db.session.add(t)


def import_bundle(data, replace=True):
    """Load a bundle exported from this panel. Returns the number of tweaks imported.

    Backups from before servers were removed still load: their servers become tweaks, and the old add-on tweaks
    (payload / SNI overlays with no protocol of their own) are skipped.
    """
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise ValueError("That file is not a GenzVPN config bundle")
    if replace:
        Tweak.query.delete()
        Notice.query.delete()
    items = [d for d in data.get("servers", [])] + [d for d in data.get("tweaks", []) if "protocol" in d]
    for i, d in enumerate(items):
        _import_one(d, i)
    if "channel_url" in data:
        set_setting("channel_url", str(data["channel_url"])[:200])
    for n in reversed(data.get("notifications", [])):  # oldest first so ids keep their order
        db.session.add(Notice(title=str(n.get("title", ""))[:80] or "Update", message=str(n.get("message", "")),
                              created_at=_date(n.get("date")) or utcnow()))
    bump_rev()
    db.session.commit()
    return len(items)
