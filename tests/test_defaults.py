from app import create_app
from models import Tweak, db


def make(tmp_path):
    return create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path/'t.db'}", "TESTING": True})


def test_airtel_cap_is_seeded_once(tmp_path):
    app = make(tmp_path)
    with app.app_context():
        by = {x.name: x for x in Tweak.query}
        t = by["AIRTEL CAP"]
        assert t.protocol == "ssh" and t.host == "suzuki.turbo-ssh.uk" and t.port == 443
        assert t.cfg["proxy_port"] == 80 and "[rotate=" in t.cfg["payload"] and "[host]" in t.cfg["payload"]
        k = by["TELKOM UNLIMITED"]
        assert (k.host, k.port, k.cfg["sni"]) == ("172.235.157.43", 443, "myaccount.telkom.co.ke") and not k.cfg["proxy_host"]
        assert k.cfg["payload"] == "[method] [host_port] [protocol][crlf]Host: [host][crlf]Service: SSH[crlf]Mode: Bypass[crlf][crlf]"
        for x in list(by.values()):
            db.session.delete(x)
        db.session.commit()
    app2 = make(tmp_path)  # restart: deleted defaults stay deleted
    with app2.app_context():
        assert Tweak.query.count() == 0


def test_public_bundle_has_the_ssh_block(tmp_path):
    app = make(tmp_path)
    b = app.test_client().get("/api/v1/config").get_json()
    first = {x["name"]: x for x in b["tweaks"]}
    s = first["AIRTEL CAP"]["ssh"]
    assert s["host"] == "suzuki.turbo-ssh.uk" and s["proxy_port"] == 80
    assert first["TELKOM UNLIMITED"]["ssh"]["sni"] == "myaccount.telkom.co.ke"


def test_seeded_even_when_other_tweaks_exist(tmp_path):
    app = create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path/'t.db'}", "TESTING": True, "SEED_DEFAULT_TWEAK": False})
    with app.app_context():
        db.session.add(Tweak(name="Mine", protocol="ssh", host="h", port=22))
        db.session.commit()
    app2 = create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path/'t.db'}", "TESTING": True})
    with app2.app_context():
        assert sorted(x.name for x in Tweak.query) == ["AIRTEL CAP", "Mine", "TELKOM UNLIMITED"]


def test_admin_forms_behave_like_the_injector_apps(tmp_path):
    from routes.admin import _normalize_payload, _parse_proxy, _split_host_port
    assert _split_host_port("suzuki.turbo-ssh.uk:443", 22) == ("suzuki.turbo-ssh.uk", 443)
    assert _split_host_port("[2001:db8::1]:2222", 22) == ("2001:db8::1", 2222)
    assert _split_host_port("ssh.example.com", 22) == ("ssh.example.com", 22)
    assert _parse_proxy("apptest.example.com") == ("apptest.example.com", 80)
    raw = "GET / HTTP/1.1[crlf]Host: [rotate=a.com;\nb.com][crlf]\nConnection: Upgrade\nUpgrade: websocket\nX: y[crlf][crlf]\n"
    assert _normalize_payload(raw) == ("GET / HTTP/1.1[crlf]Host: [rotate=a.com;b.com][crlf]Connection: Upgrade"
                                       "[crlf]Upgrade: websocket[crlf]X: y[crlf][crlf]")


def post_tweak(c, data):
    import re
    page = c.get("/admin/tweaks/new").get_data(as_text=True)
    token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    return c.post("/admin/tweaks/new", data={"csrf": token, "is_active": "1", **data})


def admin_client(tmp_path):
    import re
    app = create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path/'t.db'}", "TESTING": True, "SEED_DEFAULT_TWEAK": False,
                      "ADMIN_EMAIL": "boss@x.co", "ADMIN_PASSWORD": "adminpass1"})
    c = app.test_client()
    token = re.search(r'name="csrf" value="([^"]+)"', c.get("/admin/login").get_data(as_text=True)).group(1)
    assert c.post("/admin/login", data={"csrf": token, "email": "boss@x.co", "password": "adminpass1"}).status_code == 302
    return app, c


def test_v2ray_server_account_transport(tmp_path):
    app, c = admin_client(tmp_path)
    r = post_tweak(c, {"name": "V2 WS", "protocol": "v2ray", "host": "v2.example.com", "port": "443",
                       "v2_uuid": "11111111-2222-3333-4444-555555555555", "v2_proto": "vless", "v2_network": "ws",
                       "v2_path": "/ws", "v2_hosthdr": "bug.example.com", "v2_tls": "1"})
    assert r.status_code == 302
    t = app.test_client().get("/api/v1/config").get_json()["tweaks"][0]
    o = t["outbound"]
    assert t["protocol"] == "v2ray" and o["protocol"] == "vless"
    assert o["settings"]["vnext"][0]["address"] == "v2.example.com" and o["settings"]["vnext"][0]["users"][0]["id"].startswith("1111")
    ws = o["streamSettings"]["wsSettings"]
    assert ws["path"] == "/ws" and ws["headers"]["Host"] == "bug.example.com"
    assert o["streamSettings"]["security"] == "tls" and o["streamSettings"]["tlsSettings"]["serverName"] == "bug.example.com"
    assert "UUID" in post_tweak(c, {"name": "x", "protocol": "v2ray", "host": "h", "port": "443"}).get_data(as_text=True)


def test_udp_server_account_and_port_ranges(tmp_path):
    app, c = admin_client(tmp_path)

    def make(name, server, **extra):
        return post_tweak(c, {"name": name, "protocol": "udp", "udp_server": server, "udp_username": "bob",
                              "udp_password": "pw", **extra})

    assert make("single", "udp.example.com:4443").status_code == 302
    assert make("range", "udp.example.com:20000-50000").status_code == 302
    assert make("underscore", "udp.example.com:1_65535").status_code == 302
    assert make("v6", "[2001:db8::1]:443").status_code == 302
    by = {t["name"]: t["outbound"] for t in app.test_client().get("/api/v1/config").get_json()["tweaks"]}
    one = by["single"]
    assert one["protocol"] == "hysteria" and one["settings"]["address"] == "udp.example.com" and one["settings"]["port"] == 4443
    assert one["streamSettings"]["hysteriaSettings"]["auth"] == "bob:pw"
    hop = by["range"]["streamSettings"]["finalmask"]["quicParams"]["udpHop"]    # where the current engine wants it
    assert by["range"]["settings"]["port"] == 20000 and hop["ports"] == "20000-50000" and hop["interval"] >= 5
    assert "udphop" not in by["range"]["streamSettings"]["hysteriaSettings"]
    assert by["underscore"]["streamSettings"]["finalmask"]["quicParams"]["udpHop"]["ports"] == "1-65535"
    assert "finalmask" not in one["streamSettings"]
    for o in by.values():                                                         # the engine rejects this setting outright
        assert "allowInsecure" not in o["streamSettings"]["tlsSettings"]
    assert by["v6"]["settings"]["address"] == "2001:db8::1"
    assert 'value="udp.example.com:20000-50000"' in c.get("/admin/tweaks/2").get_data(as_text=True)   # shown back as typed
    for bad, word in (("udp.example.com", "Add the port"), ("udp.example.com:99999", "1 to 65535"),
                      ("udp.example.com:500-100", "smaller number"), ("udp.example.com:abc", "not a port")):
        assert word in make("bad", bad).get_data(as_text=True)
    assert "password" in post_tweak(c, {"name": "u", "protocol": "udp", "udp_server": "h:1"}).get_data(as_text=True)


def test_udp_certificate_pinning_and_old_saved_tweaks_are_repaired(tmp_path):
    from models import Tweak
    from services import links
    app, c = admin_client(tmp_path)
    fp = ":".join(["AB"] * 32)
    r = post_tweak(c, {"name": "pinned", "protocol": "udp", "udp_server": "udp.example.com:443", "udp_password": "pw",
                       "udp_pin": fp, "udp_certname": "real.example.com"})
    assert r.status_code == 302
    tls = app.test_client().get("/api/v1/config").get_json()["tweaks"][0]["outbound"]["streamSettings"]["tlsSettings"]
    assert tls["pinnedPeerCertSha256"] == "ab" * 32 and tls["verifyPeerCertByName"] == "real.example.com"
    assert "fingerprint" in post_tweak(c, {"name": "bad", "protocol": "udp", "udp_server": "h:1", "udp_password": "p",
                                           "udp_pin": "not-a-fingerprint"}).get_data(as_text=True)
    # a UDP tweak saved by the earlier version still carries the removed setting: it is cleaned when served
    old = {"protocol": "hysteria", "tag": "proxy", "settings": {"version": 2, "address": "h", "port": 20000},
           "streamSettings": {"network": "hysteria", "security": "tls",
                              "tlsSettings": {"serverName": "h", "alpn": ["h3"], "allowInsecure": True},
                              "hysteriaSettings": {"version": 2, "auth": "u:p", "udphop": {"port": "20000-50000", "interval": 30}}}}
    with app.app_context():
        t = Tweak(name="legacy", protocol="udp", host="h", port=20000)
        t.cfg = {"outbound": old}
        db.session.add(t)
        db.session.commit()
    served = {x["name"]: x for x in app.test_client().get("/api/v1/config").get_json()["tweaks"]}["legacy"]["outbound"]
    ss = served["streamSettings"]
    assert "allowInsecure" not in ss["tlsSettings"] and "udphop" not in ss["hysteriaSettings"]
    assert ss["finalmask"]["quicParams"]["udpHop"]["ports"] == "20000-50000"
    assert links.clean_outbound(None) == {}


def test_panel_that_already_has_airtel_gets_telkom_once(tmp_path):
    from models import set_setting
    uri = f"sqlite:///{tmp_path/'t.db'}"
    app = create_app({"SQLALCHEMY_DATABASE_URI": uri, "TESTING": True})          # a panel from before Telkom existed:
    with app.app_context():
        Tweak.query.filter_by(name="TELKOM UNLIMITED").delete()
        from models import Setting
        Setting.query.filter_by(key="default_seeded_telkom").delete()
        db.session.commit()
    app2 = create_app({"SQLALCHEMY_DATABASE_URI": uri, "TESTING": True})
    with app2.app_context():
        assert sorted(x.name for x in Tweak.query) == ["AIRTEL CAP", "TELKOM UNLIMITED"]
    app3 = create_app({"SQLALCHEMY_DATABASE_URI": uri, "TESTING": True})          # and not again after that
    with app3.app_context():
        assert Tweak.query.count() == 2
