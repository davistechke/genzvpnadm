from app import create_app
from models import Tweak, db


def make(tmp_path):
    return create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path/'t.db'}", "TESTING": True})


def test_airtel_cap_is_seeded_once(tmp_path):
    app = make(tmp_path)
    with app.app_context():
        t = Tweak.query.one()
        assert t.name == "AIRTEL CAP" and t.protocol == "ssh" and t.host == "suzuki.turbo-ssh.uk" and t.port == 443
        assert t.cfg["proxy_port"] == 80 and "[rotate=" in t.cfg["payload"] and "[host]" in t.cfg["payload"]
        db.session.delete(t)
        db.session.commit()
    app2 = make(tmp_path)  # restart: a deleted default stays deleted
    with app2.app_context():
        assert Tweak.query.count() == 0


def test_public_bundle_has_the_ssh_block(tmp_path):
    app = make(tmp_path)
    b = app.test_client().get("/api/v1/config").get_json()
    s = b["tweaks"][0]["ssh"]
    assert b["tweaks"][0]["name"] == "AIRTEL CAP" and s["host"] == "suzuki.turbo-ssh.uk" and s["proxy_port"] == 80


def test_seeded_even_when_other_tweaks_exist(tmp_path):
    app = create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path/'t.db'}", "TESTING": True, "SEED_DEFAULT_TWEAK": False})
    with app.app_context():
        db.session.add(Tweak(name="Mine", protocol="ssh", host="h", port=22))
        db.session.commit()
    app2 = create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path/'t.db'}", "TESTING": True})
    with app2.app_context():
        assert sorted(x.name for x in Tweak.query) == ["AIRTEL CAP", "Mine"]


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


def test_udp_server_and_account(tmp_path):
    app, c = admin_client(tmp_path)
    r = post_tweak(c, {"name": "UDP 1", "protocol": "udp", "host": "udp.example.com:4443", "port": "443",
                       "udp_username": "bob", "udp_password": "pw", "udp_insecure": "1"})
    assert r.status_code == 302
    o = app.test_client().get("/api/v1/config").get_json()["tweaks"][0]["outbound"]
    assert o["protocol"] == "hysteria" and o["settings"]["address"] == "udp.example.com" and o["settings"]["port"] == 4443
    assert o["streamSettings"]["hysteriaSettings"]["auth"] == "bob:pw"
    assert "password" in post_tweak(c, {"name": "u", "protocol": "udp", "host": "h", "port": "1"}).get_data(as_text=True)
