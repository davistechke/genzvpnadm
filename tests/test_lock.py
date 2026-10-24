import io
import json

from app import create_app
from services import lock as lk
from tests.test_admin import csrf, post  # reuse helpers


def make(tmp_path, key):
    return create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path/'t.db'}", "TESTING": True, "SEED_DEFAULT_TWEAK": False,
                       "ADMIN_EMAIL": "boss@x.co", "ADMIN_PASSWORD": "adminpass1", "CONFIG_KEY": key})


def login(app):
    c = app.test_client()
    c.post("/admin/login", data={"email": "boss@x.co", "password": "adminpass1", "csrf": csrf(c, "/admin/login")})
    return c


def test_locked_api_export_and_import(tmp_path):
    app = make(tmp_path, "s3cret-key")
    c = login(app)
    post(c, "/admin/tweaks/new", {"name": "Secret One", "protocol": "ssh", "host": "10.1.2.3", "port": "2222",
                                   "ssh_username": "bob", "ssh_password": "hunter2", "ssh_proxy": "px.example.com:8080",
                                   "ssh_payload": "GET / HTTP/1.1[crlf][crlf]", "is_active": "1"})
    pub = app.test_client()
    r = pub.get("/api/v1/config")
    raw = r.get_data(as_text=True)
    for leak in ("10.1.2.3", "2222", "hunter2", "bob", "px.example.com", "GET /", "Secret One"):
        assert leak not in raw  # nothing readable in the public reply
    body = json.loads(raw)
    assert lk.is_locked(body)
    plain = json.loads(lk.unlock(body, "s3cret-key"))
    assert plain["tweaks"][0]["ssh"]["password"] == "hunter2"
    assert pub.get("/api/v1/config", headers={"If-None-Match": r.headers["ETag"]}).status_code == 304

    shared = c.get("/admin/export")
    assert b"hunter2" not in shared.data and lk.is_locked(json.loads(shared.data))
    backup = c.get("/admin/export?plain=1")
    assert b"hunter2" in backup.data and "PLAIN" in backup.headers["Content-Disposition"]

    # both the locked share file and the plain backup can be imported back
    for blob in (shared.data, backup.data):
        r = c.post("/admin/import-bundle", data={"csrf": csrf(c, "/admin/?tab=backup"), "replace": "1",
                   "bundle": (io.BytesIO(blob), "c.json")}, content_type="multipart/form-data")
        assert r.status_code == 302
        assert json.loads(lk.unlock(json.loads(pub.get("/api/v1/config").data), "s3cret-key"))["tweaks"][0]["name"] == "Secret One"

    other = make(tmp_path, "different-key")  # wrong key on import is refused, not half-applied
    oc = login(other)
    r = oc.post("/admin/import-bundle", data={"csrf": csrf(oc, "/admin/?tab=backup"), "replace": "1",
                "bundle": (io.BytesIO(shared.data), "c.json")}, content_type="multipart/form-data",
                follow_redirects=True)
    assert b"different key" in r.data


def test_unlock_rejects_tampering_and_wrong_key():
    blob = json.loads(lk.lock(b'{"a":1}', "k1"))
    assert lk.unlock(blob, "k1") == b'{"a":1}'
    for bad in ("k2", ""):
        try:
            lk.unlock(blob, bad)
            assert False
        except ValueError:
            pass
    blob["data"] = blob["data"][:-4] + "AAAA"
    try:
        lk.unlock(blob, "k1")
        assert False
    except ValueError:
        pass
