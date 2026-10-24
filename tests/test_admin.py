import base64
import gzip
import io
import json
import re

import pytest

from app import create_app
from models import Admin, Tweak, db


@pytest.fixture()
def app(tmp_path):
    return create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path/'t.db'}", "TESTING": True, "SEED_DEFAULT_TWEAK": False,
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


def test_ssh_tweak_and_public_config(app, admin):
    r = post(admin, "/admin/tweaks/new", {
        "name": "Nairobi SSH", "protocol": "ssh", "country_code": "ke", "host": "1.2.3.4", "port": "22",
        "ssh_username": "u1", "ssh_password": "p1", "ssh_sni": "bug.example.com", "is_active": "1",
        "ssh_payload": "GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]"})
    assert r.status_code == 302
    pub = app.test_client()  # no login at all
    b = bundle(pub)
    s = b["tweaks"][0]
    assert s["protocol"] == "ssh" and s["country"] == "KE" and s["ssh"]["username"] == "u1"
    assert s["ssh"]["sni"] == "bug.example.com" and "outbound" not in s
    assert b["version"] >= 1


def test_etag_gzip_and_revision(app, admin):
    for i in range(6):
        post(admin, "/admin/tweaks/new", {"name": f"S{i}", "protocol": "ssh", "host": "h", "port": "22",
                                           "ssh_username": "u", "is_active": "1"})
    pub = app.test_client()
    r = pub.get("/api/v1/config")
    etag = r.headers["ETag"]
    assert pub.get("/api/v1/config", headers={"If-None-Match": etag}).status_code == 304
    g = pub.get("/api/v1/config", headers={"Accept-Encoding": "gzip"})
    assert g.headers["Content-Encoding"] == "gzip" and len(json.loads(gzip.decompress(g.data))["tweaks"]) == 6
    post(admin, "/admin/tweaks/1/toggle", {})
    assert pub.get("/api/v1/config", headers={"If-None-Match": etag}).status_code == 200
    assert len(bundle(pub)["tweaks"]) == 5  # hidden tweaks are not published


def test_v2ray_wireguard_custom_and_validation(app, admin):
    link = "vless://abc@h.example.com:443?type=ws&security=tls&sni=s.example.com&host=h.example.com&path=%2Fws#MyNode"
    assert post(admin, "/admin/tweaks/new", {"name": "", "protocol": "v2ray", "v2ray_link": link,
                                              "is_active": "1"}).status_code == 302
    r = post(admin, "/admin/tweaks/new", {"name": "Bad", "protocol": "v2ray", "v2ray_link": "http://nope"})
    assert r.status_code == 200 and b"Unsupported link" in r.data
    wg = "[Interface]\nPrivateKey=AAA\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=BBB\nEndpoint=9.9.9.9:51820"
    post(admin, "/admin/tweaks/new", {"name": "UDP", "protocol": "wireguard", "wg_conf": wg, "is_active": "1"})
    post(admin, "/admin/tweaks/new", {"name": "Raw", "protocol": "custom", "host": "x", "port": "1",
                                       "custom_outbound": '{"protocol":"vless","settings":{}}', "is_active": "1"})
    r = post(admin, "/admin/tweaks/new", {"name": "Raw2", "protocol": "custom", "custom_outbound": "[1]"})
    assert b"outbound object" in r.data
    by = {s["name"]: s for s in bundle(app.test_client())["tweaks"]}
    assert by["MyNode"]["outbound"]["tag"] == "proxy" and by["MyNode"]["port"] == 443
    assert by["UDP"]["outbound"]["protocol"] == "wireguard" and by["UDP"]["host"] == "9.9.9.9"
    assert by["Raw"]["outbound"]["tag"] == "proxy"


def test_edit_keeps_link_and_expiry_hides(app, admin):
    link = "trojan://pw@t.example.com:443#T1"
    post(admin, "/admin/tweaks/new", {"name": "T1", "protocol": "trojan_placeholder"})  # invalid type rejected
    post(admin, "/admin/tweaks/new", {"name": "T1", "protocol": "v2ray", "v2ray_link": link, "is_active": "1"})
    with app.app_context():
        sid = Tweak.query.filter_by(name="T1").first().id
    r = post(admin, f"/admin/tweaks/{sid}", {"name": "T1 renamed", "protocol": "v2ray", "v2ray_link": "",
                                              "is_active": "1"}, page=f"/admin/tweaks/{sid}")
    assert r.status_code == 302
    s = bundle(app.test_client())["tweaks"][0]
    assert s["name"] == "T1 renamed" and s["outbound"]["protocol"] == "trojan"
    post(admin, f"/admin/tweaks/{sid}", {"name": "T1", "protocol": "v2ray", "v2ray_link": "", "is_active": "1",
                                          "expires_at": "2020-01-01"}, page=f"/admin/tweaks/{sid}")
    assert bundle(app.test_client())["tweaks"] == []  # expired tweaks disappear on their own


def test_no_servers_anywhere_and_payload_upload(app, admin):
    r = admin.post("/admin/tweaks/new", data={
        "csrf": csrf(admin, "/admin/tweaks/new"), "name": "WS", "protocol": "ssh", "host": "h", "port": "22",
        "ssh_username": "u", "ssh_password": "p", "is_active": "1",
        "payload_file": (io.BytesIO(b"GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]\n"), "p.txt")},
        content_type="multipart/form-data")
    assert r.status_code == 302
    b = bundle(app.test_client())
    assert "servers" not in b and b["tweaks"][0]["ssh"]["payload"].startswith("GET /")
    assert b["tweaks"][0]["ssh"]["host"] == "h" and b["tweaks"][0]["ssh"]["port"] == 22
    binary = admin.post("/admin/tweaks/new", data={"csrf": csrf(admin, "/admin/tweaks/new"), "name": "Bin",
                        "protocol": "ssh", "host": "h", "port": "22", "ssh_username": "u",
                        "payload_file": (io.BytesIO(b"\xff\xfe\x00"), "x.bin")}, content_type="multipart/form-data")
    assert b"not plain text" in binary.data
    assert admin.get("/admin/servers/new").status_code == 404  # the old server screens are gone


def test_old_backup_still_imports(app, admin):
    old = {"format": "genzvpn-config", "servers": [
        {"id": 7, "name": "Old SSH", "country": "ke", "protocol": "ssh", "host": "9.9.9.9", "port": 2222,
         "ssh": {"username": "u", "password": "p", "payload": "", "sni": "", "proxy_host": "", "proxy_port": 0}}],
        "tweaks": [{"id": 1, "name": "overlay", "payload": "x", "server_ids": [7]}]}
    r = admin.post("/admin/import-bundle", data={"csrf": csrf(admin, "/admin/?tab=backup"), "replace": "1",
                   "bundle": (io.BytesIO(json.dumps(old).encode()), "old.json")}, content_type="multipart/form-data")
    assert r.status_code == 302
    ts = bundle(app.test_client())["tweaks"]
    assert [x["name"] for x in ts] == ["Old SSH"] and ts[0]["ssh"]["host"] == "9.9.9.9" and ts[0]["ssh"]["port"] == 2222


def test_quick_import_lines(app, admin):
    vm = "vmess://" + base64.b64encode(json.dumps({"ps": "V", "add": "v.example.com", "port": "443",
                                                   "id": "1-2-3", "net": "tcp"}).encode()).decode()
    r = post(admin, "/admin/import-links", {"lines": f"{vm}\n5.5.5.5:2222@bob:s3cret\nrubbish\n# comment"},
             page="/admin/?tab=import")
    assert r.status_code == 302
    names = {s["name"]: s for s in bundle(app.test_client())["tweaks"]}
    assert names["V"]["protocol"] == "v2ray" and names["SSH 5.5.5.5"]["ssh"]["password"] == "s3cret"
    assert len(names) == 2


def test_export_import_round_trip(app, admin):
    post(admin, "/admin/tweaks/new", {"name": "Hidden", "protocol": "ssh", "host": "h", "port": "22",
                                       "ssh_username": "u"})  # not visible
    post(admin, "/admin/tweaks/new", {"name": "Live", "protocol": "ssh", "host": "h2", "port": "22",
                                       "ssh_username": "u", "is_active": "1"})
    post(admin, "/admin/settings", {"channel_url": "https://whatsapp.com/channel/0029VaABC"}, page="/admin/?tab=settings")
    post(admin, "/admin/notices", {"title": "Welcome", "message": "Hi there"}, page="/admin/?tab=notices")
    exported = admin.get("/admin/export")
    data = json.loads(exported.data)
    assert {s["name"] for s in data["tweaks"]} == {"Hidden", "Live"} and data["channel_url"].endswith("0029VaABC")
    assert data["notifications"][0]["title"] == "Welcome"
    with app.app_context():
        Tweak.query.delete()
        db.session.commit()
    r = admin.post("/admin/import-bundle", data={"csrf": csrf(admin, "/admin/?tab=backup"), "replace": "1",
                   "bundle": (io.BytesIO(exported.data), "c.json")}, content_type="multipart/form-data")
    assert r.status_code == 302
    assert {s["name"] for s in bundle(app.test_client())["tweaks"]} == {"Live"}  # hidden stays hidden
    b = bundle(app.test_client())
    assert b["channel_url"].endswith("0029VaABC") and b["notifications"][0]["message"] == "Hi there"
    bad = admin.post("/admin/import-bundle", data={"csrf": csrf(admin, "/admin/?tab=backup"),
                     "bundle": (io.BytesIO(b'{"nope":1}'), "c.json")}, content_type="multipart/form-data")
    assert bad.status_code == 302


def test_change_password(app, admin):
    post(admin, "/admin/password", {"current": "adminpass1", "new": "newpassword9"}, page="/admin/?tab=settings")
    with app.app_context():
        assert Admin.query.first().check_password("newpassword9")


def test_notifications_and_channel_link_validation(app, admin):
    pub = app.test_client()
    assert bundle(pub)["notifications"] == [] and bundle(pub)["channel_url"] == ""
    post(admin, "/admin/notices", {"title": "One", "message": "first"}, page="/admin/?tab=notices")
    post(admin, "/admin/notices", {"title": "Two", "message": "second"}, page="/admin/?tab=notices")
    post(admin, "/admin/notices", {"title": "", "message": "no title"}, page="/admin/?tab=notices")
    titles = [n["title"] for n in bundle(pub)["notifications"]]
    assert titles == ["Two", "One"]  # newest first, blank title rejected
    r = post(admin, "/admin/settings", {"channel_url": "https://evil.example.com/channel/x"}, page="/admin/?tab=settings",
             follow_redirects=True)
    assert b"does not look like a WhatsApp channel" in r.data and bundle(pub)["channel_url"] == ""
    post(admin, "/admin/settings", {"channel_url": "https://www.whatsapp.com/channel/0029VaXYZ"}, page="/admin/?tab=settings")
    assert bundle(pub)["channel_url"].endswith("0029VaXYZ")
    nid = bundle(pub)["notifications"][0]["id"]
    post(admin, f"/admin/notices/{nid}/delete", {}, page="/admin/?tab=notices")
    assert [n["title"] for n in bundle(pub)["notifications"]] == ["One"]


def test_ssh_form_remote_proxy_and_payload_file(app, admin):
    r = admin.post("/admin/tweaks/new", data={
        "csrf": csrf(admin, "/admin/tweaks/new"), "name": "Proxied", "protocol": "ssh", "host": "9.9.9.9",
        "port": "22", "ssh_username": "u", "ssh_password": "p", "ssh_proxy": "http://proxy.example.com:8080/",
        "is_active": "1", "payload_file": (io.BytesIO(b"CONNECT [host_port] HTTP/1.1[crlf][crlf]\n"), "p.txt")},
        content_type="multipart/form-data")
    assert r.status_code == 302
    ssh = bundle(app.test_client())["tweaks"][0]["ssh"]
    assert ssh["proxy_host"] == "proxy.example.com" and ssh["proxy_port"] == 8080
    assert ssh["payload"].startswith("CONNECT [host_port]") and ssh["username"] == "u" and ssh["password"] == "p"

    page = admin.get("/admin/tweaks/1").get_data(as_text=True)  # the edit form shows it as one host:port box
    assert 'value="proxy.example.com:8080"' in page

    bad = admin.post("/admin/tweaks/new", data={
        "csrf": csrf(admin, "/admin/tweaks/new"), "name": "Bad", "protocol": "ssh", "host": "h", "port": "22",
        "ssh_username": "u", "ssh_proxy": "proxy.example.com:abc"}, content_type="multipart/form-data")
    assert bad.status_code == 200 and b"host:port" in bad.data
    nothing = post(admin, "/admin/tweaks/new", {"name": "Direct", "protocol": "ssh", "host": "h", "port": "22",
                                                 "ssh_username": "u", "is_active": "1"})
    names = {s["name"]: s["ssh"] for s in bundle(app.test_client())["tweaks"]}
    assert names["Direct"]["proxy_host"] == "" and names["Direct"]["proxy_port"] == 0
