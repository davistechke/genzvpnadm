import io
import os
import re
import zipfile

import pytest

from app import create_app
from models import FreeApp, UserRequest, db


@pytest.fixture(autouse=True)
def _fresh_limits():
    from routes import common
    common._attempts.clear()


@pytest.fixture()
def app(tmp_path):
    return create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path/'t.db'}", "TESTING": True, "SEED_DEFAULT_TWEAK": False,
                       "ADMIN_EMAIL": "boss@x.co", "ADMIN_PASSWORD": "adminpass1"})


def csrf(c, path):
    return re.search(r'name="csrf" value="([^"]+)"', c.get(path).get_data(as_text=True)).group(1)


@pytest.fixture()
def admin(app):
    c = app.test_client()
    assert c.post("/admin/login", data={"email": "boss@x.co", "password": "adminpass1", "csrf": csrf(c, "/admin/login")}).status_code == 302
    return c


def fake_apk(pad=0):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("AndroidManifest.xml", b"<manifest/>")
        z.writestr("classes.dex", b"dex" + os.urandom(pad))
    return buf.getvalue()


def upload(c, name="Tool", data=None, rights=True, follow_redirects=False, **form):
    f = {"csrf": csrf(c, "/admin/?tab=freeapps"), "name": name, "is_published": "1", **form}
    if rights:
        f["rights"] = "1"
    if data is not None:
        f["apk"] = (io.BytesIO(data), "tool.apk")
    return c.post("/admin/freeapps/upload", data=f, content_type="multipart/form-data",
                  follow_redirects=follow_redirects)


def test_upload_list_download_and_counts(app, admin):
    apk = fake_apk(pad=1000)
    assert upload(admin, data=apk, version="2.1", description="Handy tool").status_code == 302
    pub = app.test_client()
    home = pub.get("/").get_data(as_text=True)
    assert "Free apps from the admin" in home and "Handy tool" in home
    r = pub.get("/apps/1/download")
    assert r.status_code == 200 and r.data == apk and "tool-2.1.apk" in r.headers["Content-Disposition"]
    assert pub.get("/apps/1/download", headers={"Range": "bytes=10-"}).status_code == 206   # resume is not a new download
    page = admin.get("/admin/?tab=freeapps").get_data(as_text=True)
    assert "Tool" in page and "<b>1</b>" in page
    with app.app_context():
        assert db.session.get(FreeApp, 1).downloads == 1


def test_upload_rules_and_hidden(app, admin):
    assert b"allowed to share" in upload(admin, data=fake_apk(), rights=False, follow_redirects=True).data
    assert b"not an Android APK" in upload(admin, data=b"nope", follow_redirects=True).data
    assert upload(admin, data=fake_apk(), is_published="").status_code == 302
    with app.app_context():
        a = db.session.get(FreeApp, 1)
        a.is_published = False
        db.session.commit()
    pub = app.test_client()
    assert pub.get("/apps/1/download").status_code == 404
    assert "Free apps from the admin" not in pub.get("/").get_data(as_text=True)


def test_admin_only(app):
    c = app.test_client()
    assert c.post("/admin/freeapps/upload", data={}).status_code in (302, 400)
    assert c.get("/admin/?tab=requests").status_code == 302


def test_user_request_flow(app, admin):
    pub = app.test_client()
    tok = csrf(pub, "/")
    assert pub.post("/request", data={"kind": "report", "subject": "AIRTEL CAP", "message": "Stopped connecting today"}).status_code == 400
    r = pub.post("/request", data={"csrf": tok, "kind": "report", "subject": "AIRTEL CAP", "message": "Stopped connecting today",
                                   "contact": "0700000000"}, follow_redirects=True)
    assert b"Thank you" in r.data
    pub.post("/request", data={"csrf": tok, "message": "x"})                       # too short: not saved
    pub.post("/request", data={"csrf": tok, "message": "spam spam", "website": "http://bot"})  # honeypot: not saved
    with app.app_context():
        assert UserRequest.query.count() == 1
    page = admin.get("/admin/?tab=requests").get_data(as_text=True)
    assert "AIRTEL CAP" in page and "Stopped connecting today" in page and "Requests (1)" in admin.get("/admin/").get_data(as_text=True)
    t = csrf(admin, "/admin/?tab=requests")
    admin.post("/admin/requests/1/status", data={"csrf": t, "status": "done"})
    assert "Stopped connecting" not in admin.get("/admin/?tab=requests").get_data(as_text=True)
    assert "Stopped connecting" in admin.get("/admin/?tab=requests&show=done").get_data(as_text=True)
    admin.post("/admin/requests/1/delete", data={"csrf": t})
    with app.app_context():
        assert UserRequest.query.count() == 0


def test_request_rate_limit(app):
    pub = app.test_client()
    tok = csrf(pub, "/")
    for i in range(8):
        pub.post("/request", data={"csrf": tok, "message": f"message number {i}"})
    with app.app_context():
        assert UserRequest.query.count() == 5
