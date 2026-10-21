"""Turn share links / pasted configs into Xray outbound objects (tag is always "proxy")."""
import base64
import json
import re
from urllib.parse import parse_qs, unquote, urlparse


class LinkError(ValueError):
    pass


def _b64(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8")
    except Exception as e:
        raise LinkError("That link is not valid base64") from e


def _stream(net="tcp", security="none", host="", path="", sni="", alpn="", fp="",
            pbk="", sid="", spx="", service="", mode="", header_type="none"):
    net = {"splithttp": "xhttp", "": "tcp"}.get(net, net)
    s = {"network": net, "security": security or "none"}
    if net == "ws":
        s["wsSettings"] = {"path": path or "/", "host": host, "headers": {"Host": host} if host else {}}
    elif net == "httpupgrade":
        s["httpupgradeSettings"] = {"path": path or "/", "host": host}
    elif net == "xhttp":
        s["xhttpSettings"] = {"path": path or "/", "host": host, **({"mode": mode} if mode else {})}
    elif net == "grpc":
        s["grpcSettings"] = {"serviceName": service or path, "multiMode": mode == "multi"}
    elif net == "kcp":
        s["kcpSettings"] = {"header": {"type": header_type or "none"}, **({"seed": path} if path else {})}
    elif net == "tcp" and header_type == "http":
        s["tcpSettings"] = {"header": {"type": "http", "request": {
            "path": [path or "/"], "headers": {"Host": [h for h in (host or "").split(",") if h]}}}}
    if security == "tls":
        t = {"serverName": sni or host}
        if alpn:
            t["alpn"] = [a for a in alpn.split(",") if a]
        if fp:
            t["fingerprint"] = fp
        s["tlsSettings"] = t
    elif security == "reality":
        s["realitySettings"] = {"serverName": sni, "fingerprint": fp or "chrome", "publicKey": pbk,
                                "shortId": sid, "spiderX": spx}
    return s


def _q(query, key, default=""):
    v = query.get(key)
    return v[0] if v else default


def _hostport(u):
    if not u.hostname or not u.port:
        raise LinkError("Link is missing a host or port")
    return u.hostname, u.port


def parse_link(link):
    """Returns {"name", "host", "port", "outbound"} or raises LinkError."""
    link = link.strip()
    scheme = link.split("://", 1)[0].lower() if "://" in link else ""
    if scheme == "vmess":
        try:
            j = json.loads(_b64(link[8:]))
        except ValueError as e:
            raise LinkError("Bad vmess link") from e
        host, port = j.get("add", ""), int(j.get("port") or 0)
        if not host or not port or not j.get("id"):
            raise LinkError("vmess link is missing address, port or id")
        tls = "tls" if j.get("tls") in ("tls", "1", True) else "none"
        out = {"protocol": "vmess", "tag": "proxy",
               "settings": {"vnext": [{"address": host, "port": port, "users": [
                   {"id": j["id"], "security": j.get("scy") or "auto"}]}]},
               "streamSettings": _stream(j.get("net", "tcp"), tls, host=j.get("host", ""),
                                         path=j.get("path", ""), sni=j.get("sni", ""),
                                         alpn=j.get("alpn", ""), fp=j.get("fp", ""),
                                         header_type=j.get("type", "none"))}
        return {"name": j.get("ps") or host, "host": host, "port": port, "outbound": out}

    if scheme in ("vless", "trojan"):
        u = urlparse(link)
        host, port = _hostport(u)
        q = parse_qs(u.query)
        ident = unquote(u.username or "")
        if not ident:
            raise LinkError(f"{scheme} link is missing the id/password")
        security = _q(q, "security", "tls" if scheme == "trojan" else "none")
        st = _stream(_q(q, "type", "tcp"), security, host=_q(q, "host"), path=unquote(_q(q, "path")),
                     sni=_q(q, "sni"), alpn=_q(q, "alpn"), fp=_q(q, "fp"), pbk=_q(q, "pbk"),
                     sid=_q(q, "sid"), spx=unquote(_q(q, "spx")), service=_q(q, "serviceName"),
                     mode=_q(q, "mode"), header_type=_q(q, "headerType", "none"))
        if scheme == "vless":
            user = {"id": ident, "encryption": _q(q, "encryption", "none")}
            if _q(q, "flow"):
                user["flow"] = _q(q, "flow")
            settings = {"vnext": [{"address": host, "port": port, "users": [user]}]}
        else:
            settings = {"servers": [{"address": host, "port": port, "password": ident}]}
        out = {"protocol": scheme, "tag": "proxy", "settings": settings, "streamSettings": st}
        return {"name": unquote(u.fragment) or host, "host": host, "port": port, "outbound": out}

    if scheme == "ss":
        body, _, frag = link[5:].partition("#")
        body = body.split("?", 1)[0]
        if "@" in body:
            userinfo, _, hp = body.rpartition("@")
            creds = userinfo if ":" in userinfo else _b64(userinfo)
        else:
            decoded = _b64(body)
            creds, _, hp = decoded.rpartition("@")
        method, _, password = creds.partition(":")
        host, _, port = hp.rpartition(":")
        if not (method and password and host and port.isdigit()):
            raise LinkError("Bad shadowsocks link")
        out = {"protocol": "shadowsocks", "tag": "proxy", "settings": {"servers": [
            {"address": host.strip("[]"), "port": int(port), "method": method, "password": password}]}}
        return {"name": unquote(frag) or host, "host": host, "port": int(port), "outbound": out}

    raise LinkError("Unsupported link. Use vmess://, vless://, trojan:// or ss://")


# ---------------------------------------------------------------- WireGuard

def parse_wg_conf(text):
    """Parse a wg-quick style config into an Xray wireguard outbound."""
    section, iface, peer = None, {}, {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            section = line.strip("[]").lower()
            continue
        if "=" not in line:
            continue
        k, v = (x.strip() for x in line.split("=", 1))
        (iface if section == "interface" else peer if section == "peer" else {})[k.lower()] = v
    need = (iface.get("privatekey"), iface.get("address"), peer.get("publickey"), peer.get("endpoint"))
    if not all(need):
        raise LinkError("WireGuard config needs PrivateKey, Address, PublicKey and Endpoint")
    host, _, port = peer["endpoint"].rpartition(":")
    if not port.isdigit():
        raise LinkError("Endpoint must look like host:port")
    p = {"publicKey": peer["publickey"], "endpoint": peer["endpoint"],
         "allowedIPs": [x.strip() for x in peer.get("allowedips", "0.0.0.0/0, ::/0").split(",")]}
    if peer.get("presharedkey"):
        p["preSharedKey"] = peer["presharedkey"]
    if peer.get("persistentkeepalive"):
        p["keepAlive"] = int(peer["persistentkeepalive"])
    settings = {"secretKey": iface["privatekey"],
                "address": [a.strip() for a in iface["address"].split(",")],
                "peers": [p], "mtu": int(iface.get("mtu", 1280))}
    return {"host": host.strip("[]"), "port": int(port),
            "outbound": {"protocol": "wireguard", "tag": "proxy", "settings": settings}}


def parse_custom(text):
    try:
        o = json.loads(text)
    except ValueError as e:
        raise LinkError(f"Not valid JSON: {e}") from e
    if not isinstance(o, dict) or "protocol" not in o:
        raise LinkError('Paste one Xray outbound object, e.g. {"protocol": "...", "settings": {...}}')
    o["tag"] = "proxy"
    return o


# ---------------------------------------------------------------- SSH lines

_SSH_AT = re.compile(r"^(?P<host>[^:@\s]+):(?P<port>\d+)@(?P<user>[^:\s]+):(?P<pw>.+)$")


def parse_ssh_line(line):
    """Accepts host:port@user:pass  or  ssh://user:pass@host:port"""
    line = line.strip()
    m = _SSH_AT.match(line)
    if m:
        return {"host": m["host"], "port": int(m["port"]), "username": m["user"], "password": m["pw"]}
    if line.lower().startswith("ssh://"):
        u = urlparse(line)
        if u.hostname and u.username:
            return {"host": u.hostname, "port": u.port or 22, "username": unquote(u.username),
                    "password": unquote(u.password or "")}
    raise LinkError("SSH lines look like host:port@user:pass")
