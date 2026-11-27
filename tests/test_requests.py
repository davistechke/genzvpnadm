import re

import pytest

from app import create_app
from models import UserRequest, db


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


def test_home_has_request_form_and_menu(app):
    home = app.test_client().get("/").get_data(as_text=True)
    assert 'href="#requests"' in home and 'id="requests"' in home
    assert "free-apps" not in home and "Free apps" not in home
    assert 'class="menu"' in home and ">Home</a>" in home


def test_admin_only(app):
    c = app.test_client()
    assert c.get("/admin/?tab=requests").status_code == 302


def test_free_apps_are_gone(app, admin):
    assert "Free apps" not in admin.get("/admin/").get_data(as_text=True)
    assert admin.get("/admin/?tab=freeapps").status_code in (200, 302)   # unknown tab: falls back to the default one
    assert app.test_client().get("/apps/1/download").status_code == 404


def test_upload_size_limits(tmp_path):
    app = create_app({"SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path/'t.db'}", "TESTING": True, "SEED_DEFAULT_TWEAK": False,
                      "ADMIN_EMAIL": "boss@x.co", "ADMIN_PASSWORD": "adminpass1"})
    assert app.config["MAX_UPLOAD_MB"] == 300
    c = app.test_client()
    c.post("/admin/login", data={"email": "boss@x.co", "password": "adminpass1", "csrf": csrf(c, "/admin/login")})
    tok = csrf(c, "/admin/?tab=app")
    h = {"CONTENT_LENGTH": str(400 * 1024 * 1024)}
    assert c.post("/admin/app/upload", data={"csrf": tok}, environ_overrides=h).status_code == 413
    assert c.post("/request", data={"csrf": tok}, environ_overrides=h).status_code == 413
