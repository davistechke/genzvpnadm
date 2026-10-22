import json
import re
from datetime import datetime

from flask import (Blueprint, Response, current_app, flash, redirect, render_template, request, session, url_for)

from models import Admin, Notice, Server, Tweak, bump_rev, db, get_setting, set_setting
from routes.common import (admin_required, check_csrf, clear_failures, current_admin, record_failure,
                           throttled)
from services import links
from services.bundle import FORMAT, build_bundle, import_bundle
from services.lock import is_locked, lock, unlock

bp = Blueprint("admin", __name__, url_prefix="/admin")
PROTOCOLS = ("ssh", "v2ray", "wireguard", "custom")


@bp.before_request
def _csrf():
    check_csrf()


# ------------------------------------------------------------------ auth

@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_admin():
        return redirect(url_for("admin.home"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        key = f"admin:{email}:{request.remote_addr}"
        if throttled(key):
            flash("Too many attempts. Try again in a few minutes.", "error")
        else:
            a = Admin.query.filter_by(email=email).first()
            if a and a.check_password(request.form.get("password", "")):
                clear_failures(key)
                session.clear()
                session["admin_uid"] = a.id
                return redirect(url_for("admin.home"))
            record_failure(key)
            flash("Wrong email or password.", "error")
    return render_template("admin_login.html")


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("admin.login"))


@bp.post("/password")
@admin_required
def change_password():
    a = current_admin()
    if not a.check_password(request.form.get("current", "")) or len(request.form.get("new", "")) < 8:
        flash("Current password is wrong, or the new one is shorter than 8 characters.", "error")
    else:
        a.set_password(request.form["new"])
        db.session.commit()
        flash("Password changed.", "ok")
    return redirect(url_for("admin.home", tab="settings"))


# ------------------------------------------------------------------ pages

@bp.get("")
@bp.get("/")
@admin_required
def home():
    tab = request.args.get("tab", "servers")
    ctx = {"tab": tab, "servers": [], "tweaks": []}
    ctx["servers"] = Server.query.order_by(Server.sort, Server.name).all()
    ctx["tweaks"] = Tweak.query.order_by(Tweak.sort, Tweak.name).all()
    ctx["channel_url"] = get_setting("channel_url", "")
    ctx["notices"] = Notice.query.order_by(Notice.id.desc()).limit(50).all()
    ctx["rev"] = get_setting("rev", "0")
    ctx["locked"] = bool(current_app.config["CONFIG_KEY"])
    return render_template("admin.html", **ctx)


# ------------------------------------------------------------------ servers

def _server_values(s):
    cfg = s.cfg if s else {}
    return {
        "name": s.name if s else "", "country_code": s.country_code if s else "KE",
        "protocol": s.protocol if s else "ssh", "host": s.host if s else "", "port": s.port if s else 22,
        "note": s.note if s else "", "sort": s.sort if s else 0, "is_active": s.is_active if s else True,
        "expires_at": s.expires_at.strftime("%Y-%m-%d") if s and s.expires_at else "",
        "ssh_username": cfg.get("username", ""), "ssh_password": cfg.get("password", ""),
        "ssh_payload": cfg.get("payload", ""), "ssh_sni": cfg.get("sni", ""),
        "ssh_proxy": (f"{cfg['proxy_host']}:{cfg.get('proxy_port') or ''}".rstrip(":") if cfg.get("proxy_host") else ""),
        "v2ray_link": cfg.get("link", ""), "wg_conf": cfg.get("wg_conf", ""),
        "custom_outbound": json.dumps(cfg["outbound"], indent=2) if s and s.protocol == "custom" and cfg.get("outbound") else "",
    }


def _parse_proxy(text):
    """'host:port' (optionally with http://) -> (host, port). Empty means no proxy."""
    text = re.sub(r"^https?://", "", (text or "").strip()).rstrip("/")
    if not text:
        return "", 0
    host, _, port = text.rpartition(":")
    if not host:
        return text, 8080  # host only: assume the usual proxy port
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise links.LinkError("Remote proxy must look like host:port, e.g. proxy.example.com:8080")
    return host, int(port)


def _fill_server(s, f, files=None):
    """Apply the form to a Server. Raises links.LinkError with a friendly message."""
    proto = f.get("protocol", "ssh")
    if proto not in PROTOCOLS:
        raise links.LinkError("Pick a protocol")
    name = f.get("name", "").strip()
    host, port = f.get("host", "").strip(), f.get("port", type=int) or 0
    cfg = {}
    if proto == "ssh":
        if not host or not port or not f.get("ssh_username", "").strip():
            raise links.LinkError("SSH needs host, port and username")
        payload = f.get("ssh_payload", "")
        up = files.get("payload_file") if files else None
        if up and up.filename:
            try:
                payload = up.read(50_000).decode("utf-8")
            except UnicodeDecodeError:
                raise links.LinkError("The payload file is not plain text")
        proxy_host, proxy_port = _parse_proxy(f.get("ssh_proxy", ""))
        cfg = {"username": f["ssh_username"].strip(), "password": f.get("ssh_password", ""),
               "payload": payload.strip(), "sni": f.get("ssh_sni", "").strip(),
               "proxy_host": proxy_host, "proxy_port": proxy_port}
    elif proto == "v2ray":
        link = f.get("v2ray_link", "").strip()
        if not link and s.cfg.get("outbound"):
            cfg = s.cfg
        else:
            p = links.parse_link(link)
            cfg, host, port = {"link": link, "outbound": p["outbound"]}, p["host"], p["port"]
            name = name or p["name"]
    elif proto == "wireguard":
        conf = f.get("wg_conf", "").strip()
        if not conf and s.cfg.get("outbound"):
            cfg = s.cfg
        else:
            p = links.parse_wg_conf(conf)
            cfg, host, port = {"wg_conf": conf, "outbound": p["outbound"]}, p["host"], p["port"]
    else:
        out = links.parse_custom(f.get("custom_outbound", ""))
        cfg = {"outbound": out}
        host, port = host or "custom", port or 0
    if not name:
        raise links.LinkError("Give the server a name")
    expires = f.get("expires_at", "").strip()
    try:
        s.expires_at = datetime.strptime(expires, "%Y-%m-%d") if expires else None
    except ValueError:
        raise links.LinkError("Expiry must look like 2026-12-31")
    s.name, s.protocol, s.host, s.port, s.cfg = name[:80], proto, host, port, cfg
    s.country_code = f.get("country_code", "").strip().upper()[:2]
    s.note = f.get("note", "").strip()[:200]
    s.sort = f.get("sort", type=int) or 0
    s.is_active = bool(f.get("is_active"))


@bp.route("/servers/new", methods=["GET", "POST"])
@bp.route("/servers/<int:sid>", methods=["GET", "POST"])
@admin_required
def server_form(sid=None):
    s = db.session.get(Server, sid) if sid else None
    if sid and not s:
        return redirect(url_for("admin.home", tab="servers"))
    values = _server_values(s)
    if request.method == "POST":
        target = s or Server(protocol="ssh", data="{}")
        try:
            _fill_server(target, request.form, request.files)
        except links.LinkError as e:
            flash(str(e), "error")
            values = {**values, **{k: v for k, v in request.form.items()},
                      "is_active": bool(request.form.get("is_active"))}
        else:
            db.session.add(target)
            bump_rev()
            db.session.commit()
            flash(f"Saved {target.name}.", "ok")
            return redirect(url_for("admin.home", tab="servers"))
    return render_template("server_form.html", s=s, v=values)


@bp.post("/servers/<int:sid>/delete")
@admin_required
def server_delete(sid):
    s = db.session.get(Server, sid)
    if s:
        db.session.delete(s)
        bump_rev()
        db.session.commit()
    return redirect(url_for("admin.home", tab="servers"))


@bp.post("/servers/<int:sid>/toggle")
@admin_required
def server_toggle(sid):
    s = db.session.get(Server, sid)
    if s:
        s.is_active = not s.is_active
        bump_rev()
        db.session.commit()
    return redirect(url_for("admin.home", tab="servers"))


@bp.post("/servers/<int:sid>/duplicate")
@admin_required
def server_duplicate(sid):
    s = db.session.get(Server, sid)
    if s:
        c = Server(name=f"{s.name} (copy)", country_code=s.country_code, protocol=s.protocol, host=s.host,
                   port=s.port, note=s.note, expires_at=s.expires_at, is_active=False, sort=s.sort, data=s.data)
        db.session.add(c)
        bump_rev()
        db.session.commit()
        flash("Duplicated (hidden until you enable it).", "ok")
    return redirect(url_for("admin.home", tab="servers"))


# ------------------------------------------------------------------ tweaks

def _tweak_values(t):
    return {
        "name": t.name if t else "", "description": t.description if t else "", "payload": t.payload if t else "",
        "sni": t.sni if t else "", "host_header": t.host_header if t else "",
        "proxy_host": t.proxy_host if t else "", "proxy_port": t.proxy_port or "" if t else "",
        "dns": t.dns if t else "", "sort": t.sort if t else 0, "is_active": t.is_active if t else True,
        "protocols": [x for x in (t.protocols or "").split(",") if x] if t else [],
        "server_ids": [x for x in (t.server_ids or "").split(",") if x] if t else [],
    }


@bp.route("/tweaks/new", methods=["GET", "POST"])
@bp.route("/tweaks/<int:tid>", methods=["GET", "POST"])
@admin_required
def tweak_form(tid=None):
    t = db.session.get(Tweak, tid) if tid else None
    if tid and not t:
        return redirect(url_for("admin.home", tab="tweaks"))
    values = _tweak_values(t)
    if request.method == "POST":
        f = request.form
        payload = f.get("payload", "")
        up = request.files.get("payload_file")
        if up and up.filename:
            try:
                payload = up.read(50_000).decode("utf-8")
            except UnicodeDecodeError:
                flash("That file is not plain text.", "error")
                return render_template("tweak_form.html", t=t, v=values, servers=Server.query.all())
        if not f.get("name", "").strip():
            flash("Give the tweak a name.", "error")
        else:
            t = t or Tweak()
            t.name, t.description = f["name"].strip()[:80], f.get("description", "").strip()[:200]
            t.payload, t.sni = payload.strip(), f.get("sni", "").strip()
            t.host_header, t.proxy_host = f.get("host_header", "").strip(), f.get("proxy_host", "").strip()
            t.proxy_port, t.dns = f.get("proxy_port", type=int) or 0, f.get("dns", "").strip()
            t.protocols = ",".join(p for p in f.getlist("protocols") if p in PROTOCOLS)
            t.server_ids = ",".join(x for x in f.getlist("server_ids") if x.isdigit())
            t.sort, t.is_active = f.get("sort", type=int) or 0, bool(f.get("is_active"))
            db.session.add(t)
            bump_rev()
            db.session.commit()
            flash(f"Saved {t.name}.", "ok")
            return redirect(url_for("admin.home", tab="tweaks"))
        values = {**values, **{k: v for k, v in f.items()}, "payload": payload,
                  "protocols": f.getlist("protocols"), "server_ids": f.getlist("server_ids"),
                  "is_active": bool(f.get("is_active"))}
    return render_template("tweak_form.html", t=t, v=values, servers=Server.query.order_by(Server.name).all())


@bp.post("/tweaks/<int:tid>/delete")
@admin_required
def tweak_delete(tid):
    t = db.session.get(Tweak, tid)
    if t:
        db.session.delete(t)
        bump_rev()
        db.session.commit()
    return redirect(url_for("admin.home", tab="tweaks"))


@bp.post("/tweaks/<int:tid>/toggle")
@admin_required
def tweak_toggle(tid):
    t = db.session.get(Tweak, tid)
    if t:
        t.is_active = not t.is_active
        bump_rev()
        db.session.commit()
    return redirect(url_for("admin.home", tab="tweaks"))


# ------------------------------------------------------------------ import / export / settings

@bp.post("/import-links")
@admin_required
def import_links():
    added, errors = 0, []
    for i, line in enumerate(request.form.get("lines", "").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if "://" in line and line.split("://", 1)[0].lower() in ("vmess", "vless", "trojan", "ss"):
                p = links.parse_link(line)
                db.session.add(Server(name=p["name"][:80], protocol="v2ray", host=p["host"], port=p["port"],
                                      cfg={"link": line, "outbound": p["outbound"]}))
            else:
                p = links.parse_ssh_line(line)
                db.session.add(Server(name=f"SSH {p['host']}", protocol="ssh", host=p["host"], port=p["port"],
                                      cfg={"username": p["username"], "password": p["password"], "payload": "",
                                           "sni": "", "proxy_host": "", "proxy_port": 0}))
            added += 1
        except links.LinkError as e:
            errors.append(f"line {i}: {e}")
    if added:
        bump_rev()
        db.session.commit()
    flash(f"Added {added} server(s)." + (" Problems: " + "; ".join(errors[:5]) if errors else ""),
          "ok" if added and not errors else "error")
    return redirect(url_for("admin.home", tab="servers"))


@bp.post("/import-bundle")
@admin_required
def import_bundle_route():
    up = request.files.get("bundle")
    try:
        data = json.loads(up.read().decode("utf-8")) if up and up.filename else None
        if is_locked(data):
            data = json.loads(unlock(data, current_app.config["CONFIG_KEY"]).decode("utf-8"))
        n_s, n_t = import_bundle(data, replace=bool(request.form.get("replace")))
        flash(f"Imported {n_s} server(s) and {n_t} tweak(s).", "ok")
    except (ValueError, KeyError, TypeError) as e:
        db.session.rollback()
        flash(f"Import failed: {e}", "error")
    return redirect(url_for("admin.home", tab="backup"))


@bp.get("/export")
@admin_required
def export():
    """Share file for users: locked when CONFIG_KEY is set. ?plain=1 gives a readable admin backup."""
    plain = json.dumps(build_bundle(public=False), indent=2, ensure_ascii=False)
    key = current_app.config["CONFIG_KEY"]
    if request.args.get("plain") or not key:
        name = "genzvpn-backup-PLAIN.json" if key else "genzvpn-config.json"
        return Response(plain, mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename={name}"})
    return Response(lock(plain.encode(), key), mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=genzvpn-config.json"})


@bp.post("/settings")
@admin_required
def settings():
    url = request.form.get("channel_url", "").strip()
    ok = not url or re.match(r"^https://(www\.)?whatsapp\.com/channel/[A-Za-z0-9_-]+/?$", url)
    if not ok:
        flash("That does not look like a WhatsApp channel link (https://whatsapp.com/channel/...).", "error")
    else:
        set_setting("channel_url", url)
        bump_rev()
        db.session.commit()
        flash("Saved.", "ok")
    return redirect(url_for("admin.home", tab="settings"))


@bp.post("/notices")
@admin_required
def notice_add():
    title, message = request.form.get("title", "").strip()[:80], request.form.get("message", "").strip()[:1000]
    if not title:
        flash("Give the notification a title.", "error")
    else:
        db.session.add(Notice(title=title, message=message))
        bump_rev()
        db.session.commit()
        flash("Sent. Users see it after they tap Update.", "ok")
    return redirect(url_for("admin.home", tab="notices"))


@bp.post("/notices/<int:nid>/delete")
@admin_required
def notice_delete(nid):
    n = db.session.get(Notice, nid)
    if n:
        db.session.delete(n)
        bump_rev()
        db.session.commit()
    return redirect(url_for("admin.home", tab="notices"))
