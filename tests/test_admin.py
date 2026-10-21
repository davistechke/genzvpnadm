import base64
import gzip
import io
import json
import re

import pytest

from app import create_app
from models import Admin, Server, db


@pytest.fixture()
def app(tmp_path):
    return create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path/'t.db'}", "TESTING": True,
                       "ADMIN_EMAIL": "boss@x.co", "ADMIN_PASSWORD": "adminpass1"})


def csrf(c, path):
    return re.search(r'name="csrf" value="([^"]+)"', c.get(path).get_data(as_text=True)).group(1)


@pytest.fixture()
def admin(app):
    c = app.test_client()
    r = c.post("/admin/login", data={"email": "boss@x.co", "password": "adminpass1", "csrf": csrf(c, "/admin/login")})
    assert r.status_code == 302
    return c


def post(c, url, data, page="/admin/", **kw):
    return c.post(url, data={"csrf": csrf(c, page), **data}, **kw)


def bundle(c):
    return c.get("/api/v1/config").get_json()


def test_login_required_and_wrong_password(app):
    c = app.test_client()
    assert c.get("/admin/").status_code == 302
    r = c.post("/admin/login", data={"email": "boss@x.co", "password": "nope", "csrf": csrf(c, "/admin/login")})
    assert r.status_code == 200 and b"Wrong email" in r.data
    assert c.post("/admin/login", data={"email": "boss@x.co", "password": "adminpass1"}).status_code == 400  # no csrf
    assert b"/admin" not in c.get("/").data  # nothing public links to the panel


def test_ssh_server_and_public_config(app, admin):
    r = post(admin, "/admin/servers/new", {
        "name": "Nairobi SSH", "protocol": "ssh", "country_code": "ke", "host": "1.2.3.4", "port": "22",
        "ssh_username": "u1", "ssh_password": "p1", "ssh_sni": "bug.example.com", "is_active": "1",
        "ssh_payload": "GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]"})
    assert r.status_code == 302
    pub = app.test_client()  # no login at all
    b = bundle(pub)
    s = b["servers"][0]
    assert s["protocol"] == "ssh" and s["country"] == "KE" and s["ssh"]["username"] == "u1"
    assert s["ssh"]["sni"] == "bug.example.com" and "outbound" not in s
    assert b["version"] >= 1


def test_etag_gzip_and_revision(app, admin):
    for i in range(6):
        post(admin, "/admin/servers/new", {"name": f"S{i}", "protocol": "ssh", "host": "h", "port": "22",
                                           "ssh_username": "u", "is_active": "1"})
    pub = app.test_client()
    r = pub.get("/api/v1/config")
    etag = r.headers["ETag"]
    assert pub.get("/api/v1/config", headers={"If-None-Match": etag}).status_code == 304
    g = pub.get("/api/v1/config", headers={"Accept-Encoding": "gzip"})
    assert g.headers["Content-Encoding"] == "gzip" and len(json.loads(gzip.decompress(g.data))["servers"]) == 6
    post(admin, "/admin/servers/1/toggle", {})
    assert pub.get("/api/v1/config", headers={"If-None-Match": etag}).status_code == 200
    assert len(bundle(pub)["servers"]) == 5  # hidden servers are not published


def test_v2ray_wireguard_custom_and_validation(app, admin):
    link = "vless://abc@h.example.com:443?type=ws&security=tls&sni=s.example.com&host=h.example.com&path=%2Fws#MyNode"
    assert post(admin, "/admin/servers/new", {"name": "", "protocol": "v2ray", "v2ray_link": link,
                                              "is_active": "1"}).status_code == 302
    r = post(admin, "/admin/servers/new", {"name": "Bad", "protocol": "v2ray", "v2ray_link": "http://nope"})
    assert r.status_code == 200 and b"Unsupported link" in r.data
    wg = "[Interface]\nPrivateKey=AAA\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=BBB\nEndpoint=9.9.9.9:51820"
    post(admin, "/admin/servers/new", {"name": "UDP", "protocol": "wireguard", "wg_conf": wg, "is_active": "1"})
    post(admin, "/admin/servers/new", {"name": "Raw", "protocol": "custom", "host": "x", "port": "1",
                                       "custom_outbound": '{"protocol":"vless","settings":{}}', "is_active": "1"})
    r = post(admin, "/admin/servers/new", {"name": "Raw2", "protocol": "custom", "custom_outbound": "[1]"})
    assert b"outbound object" in r.data
    by = {s["name"]: s for s in bundle(app.test_client())["servers"]}
    assert by["MyNode"]["outbound"]["tag"] == "proxy" and by["MyNode"]["port"] == 443
    assert by["UDP"]["outbound"]["protocol"] == "wireguard" and by["UDP"]["host"] == "9.9.9.9"
    assert by["Raw"]["outbound"]["tag"] == "proxy"


def test_edit_keeps_link_and_expiry_hides(app, admin):
    link = "trojan://pw@t.example.com:443#T1"
    post(admin, "/admin/servers/new", {"name": "T1", "protocol": "trojan_placeholder"})  # invalid type rejected
    post(admin, "/admin/servers/new", {"name": "T1", "protocol": "v2ray", "v2ray_link": link, "is_active": "1"})
    with app.app_context():
        sid = Server.query.filter_by(name="T1").first().id
    r = post(admin, f"/admin/servers/{sid}", {"name": "T1 renamed", "protocol": "v2ray", "v2ray_link": "",
                                              "is_active": "1"}, page=f"/admin/servers/{sid}")
    assert r.status_code == 302
    s = bundle(app.test_client())["servers"][0]
    assert s["name"] == "T1 renamed" and s["outbound"]["protocol"] == "trojan"
    post(admin, f"/admin/servers/{sid}", {"name": "T1", "protocol": "v2ray", "v2ray_link": "", "is_active": "1",
                                          "expires_at": "2020-01-01"}, page=f"/admin/servers/{sid}")
    assert bundle(app.test_client())["servers"] == []  # expired servers disappear on their own


def test_tweaks_payload_upload_and_scoping(app, admin):
    post(admin, "/admin/servers/new", {"name": "A", "protocol": "ssh", "host": "h", "port": "22",
                                       "ssh_username": "u", "is_active": "1"})
    r = admin.post("/admin/tweaks/new", data={
        "csrf": csrf(admin, "/admin/tweaks/new"), "name": "WS", "sni": "bug.example.com", "is_active": "1",
        "protocols": ["ssh", "v2ray"], "server_ids": ["1"],
        "payload_file": (io.BytesIO(b"GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]\n"), "p.txt")},
        content_type="multipart/form-data")
    assert r.status_code == 302
    t = bundle(app.test_client())["tweaks"][0]
    assert t["payload"].startswith("GET /") and t["protocols"] == ["ssh", "v2ray"] and t["server_ids"] == [1]
    binary = admin.post("/admin/tweaks/new", data={"csrf": csrf(admin, "/admin/tweaks/new"), "name": "Bin",
                        "payload_file": (io.BytesIO(b"\xff\xfe\x00"), "x.bin")}, content_type="multipart/form-data")
    assert b"not plain text" in binary.data


def test_quick_import_lines(app, admin):
    vm = "vmess://" + base64.b64encode(json.dumps({"ps": "V", "add": "v.example.com", "port": "443",
                                                   "id": "1-2-3", "net": "tcp"}).encode()).decode()
    r = post(admin, "/admin/import-links", {"lines": f"{vm}\n5.5.5.5:2222@bob:s3cret\nrubbish\n# comment"},
             page="/admin/?tab=import")
    assert r.status_code == 302
    names = {s["name"]: s for s in bundle(app.test_client())["servers"]}
    assert names["V"]["protocol"] == "v2ray" and names["SSH 5.5.5.5"]["ssh"]["password"] == "s3cret"
    assert len(names) == 2


def test_export_import_round_trip(app, admin):
    post(admin, "/admin/servers/new", {"name": "Hidden", "protocol": "ssh", "host": "h", "port": "22",
                                       "ssh_username": "u"})  # not visible
    post(admin, "/admin/servers/new", {"name": "Live", "protocol": "ssh", "host": "h2", "port": "22",
                                       "ssh_username": "u", "is_active": "1"})
    post(admin, "/admin/settings", {"announcement": "Hello users"}, page="/admin/?tab=settings")
    exported = admin.get("/admin/export")
    data = json.loads(exported.data)
    assert {s["name"] for s in data["servers"]} == {"Hidden", "Live"} and data["announcement"] == "Hello users"
    with app.app_context():
        Server.query.delete()
        db.session.commit()
    r = admin.post("/admin/import-bundle", data={"csrf": csrf(admin, "/admin/?tab=backup"), "replace": "1",
                   "bundle": (io.BytesIO(exported.data), "c.json")}, content_type="multipart/form-data")
    assert r.status_code == 302
    assert {s["name"] for s in bundle(app.test_client())["servers"]} == {"Live"}  # hidden stays hidden
    bad = admin.post("/admin/import-bundle", data={"csrf": csrf(admin, "/admin/?tab=backup"),
                     "bundle": (io.BytesIO(b'{"nope":1}'), "c.json")}, content_type="multipart/form-data")
    assert bad.status_code == 302


def test_change_password(app, admin):
    post(admin, "/admin/password", {"current": "adminpass1", "new": "newpassword9"}, page="/admin/?tab=settings")
    with app.app_context():
        assert Admin.query.first().check_password("newpassword9")
