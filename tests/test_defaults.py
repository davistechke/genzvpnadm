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
