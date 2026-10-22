"""The config bundle the app downloads (and admins can export/import)."""
import hashlib
import json
from datetime import datetime

from models import Notice, Server, Tweak, bump_rev, db, get_setting, set_setting, utcnow

FORMAT = "genzvpn-config"


def _date(text):
    try:
        return datetime.strptime(text, "%Y-%m-%d") if text else None
    except ValueError:
        return None


def _csv(value):
    return [x.strip() for x in (value or "").split(",") if x.strip()]


def server_to_dict(s, full=False):
    d = {"id": s.id, "name": s.name, "country": s.country_code or "", "protocol": s.protocol,
         "host": s.host or "", "port": s.port or 0, "note": s.note or "",
         "expires_at": s.expires_at.strftime("%Y-%m-%d") if s.expires_at else ""}
    if full:  # backups keep what the public bundle leaves out
        d.update(active=s.is_active, sort=s.sort or 0)
    cfg = s.cfg
    if s.protocol == "ssh":
        d["ssh"] = {k: cfg.get(k, "") for k in ("username", "password", "payload", "sni", "proxy_host")}
        d["ssh"]["proxy_port"] = int(cfg.get("proxy_port") or 0)
    else:
        d["outbound"] = cfg.get("outbound", {})
    return d


def tweak_to_dict(t, full=False):
    d = {"id": t.id, "name": t.name, "description": t.description or "", "payload": t.payload or "",
            "sni": t.sni or "", "host_header": t.host_header or "", "proxy_host": t.proxy_host or "",
            "proxy_port": t.proxy_port or 0, "dns": t.dns or "",
            "protocols": _csv(t.protocols), "server_ids": [int(x) for x in _csv(t.server_ids) if x.isdigit()]}
    if full:
        d.update(active=t.is_active, sort=t.sort or 0)
    return d


def notice_to_dict(n):
    return {"id": n.id, "title": n.title, "message": n.message or "",
            "date": n.created_at.strftime("%Y-%m-%d") if n.created_at else ""}


def build_bundle(public=True):
    q = Server.query
    servers = q.filter_by(is_active=True).order_by(Server.sort, Server.name).all() if public else \
        q.order_by(Server.sort, Server.name).all()
    now = utcnow()
    servers = [s for s in servers if not (public and s.expires_at and s.expires_at < now)]
    tq = Tweak.query.filter_by(is_active=True) if public else Tweak.query
    return {"format": FORMAT, "version": int(get_setting("rev", "0") or 0),
            "channel_url": get_setting("channel_url", ""),
            "notifications": [notice_to_dict(n) for n in Notice.query.order_by(Notice.id.desc()).limit(20)],
            "servers": [server_to_dict(s, not public) for s in servers],
            "tweaks": [tweak_to_dict(t, not public) for t in tq.order_by(Tweak.sort, Tweak.name).all()]}


def body_and_etag(bundle):
    body = json.dumps(bundle, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode()
    return body, '"' + hashlib.sha256(body).hexdigest()[:24] + '"'


def import_bundle(data, replace=True):
    """Load a bundle exported from this panel. Returns (servers, tweaks) counts."""
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise ValueError("That file is not a GenzVPN config bundle")
    if replace:
        Server.query.delete()
        Tweak.query.delete()
        Notice.query.delete()
    id_map = {}
    for i, d in enumerate(data.get("servers", [])):
        s = Server(name=d.get("name", "Server")[:80], country_code=(d.get("country") or "")[:2].upper(),
                   protocol=d["protocol"], host=d.get("host", ""), port=int(d.get("port") or 0),
                   note=d.get("note", "")[:200], sort=d.get("sort", i),
                   is_active=bool(d.get("active", True)), expires_at=_date(d.get("expires_at")))
        cfg = d.get("ssh") if d["protocol"] == "ssh" else {"outbound": d.get("outbound", {})}
        s.cfg = cfg or {}
        db.session.add(s)
        db.session.flush()
        id_map[d.get("id")] = s.id
    for i, d in enumerate(data.get("tweaks", [])):
        ids = ",".join(str(id_map[x]) for x in d.get("server_ids", []) if x in id_map)
        db.session.add(Tweak(name=d.get("name", "Tweak")[:80], description=d.get("description", "")[:200],
                             payload=d.get("payload", ""), sni=d.get("sni", ""),
                             host_header=d.get("host_header", ""), proxy_host=d.get("proxy_host", ""),
                             proxy_port=int(d.get("proxy_port") or 0), dns=d.get("dns", ""),
                             protocols=",".join(d.get("protocols", [])), server_ids=ids, sort=d.get("sort", i),
                             is_active=bool(d.get("active", True))))
    if "channel_url" in data:
        set_setting("channel_url", str(data["channel_url"])[:200])
    for n in reversed(data.get("notifications", [])):  # oldest first so ids keep their order
        db.session.add(Notice(title=str(n.get("title", ""))[:80] or "Update", message=str(n.get("message", "")),
                              created_at=_date(n.get("date")) or utcnow()))
    bump_rev()
    db.session.commit()
    return len(data.get("servers", [])), len(data.get("tweaks", []))
