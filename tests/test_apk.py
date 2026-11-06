import io
import os
import re
import zipfile

import pytest

from app import create_app
from models import CHUNK, ApkChunk, ApkDownload, ApkRelease, db


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


def fake_apk(extra=b"", pad=0):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("AndroidManifest.xml", b"<manifest/>")
        z.writestr("classes.dex", b"dex" + extra + os.urandom(pad))
    return buf.getvalue()


def upload(c, version="1.0.0", data=None, **form):
    f = {"csrf": csrf(c, "/admin/?tab=app"), "app_name": "GenzVPN", "version": version, "is_published": "1", **form}
    if data is not None:
        f["apk"] = (io.BytesIO(data), "genzvpn.apk")
    return c.post("/admin/app/upload", data=f, content_type="multipart/form-data", follow_redirects=True)


def test_home_says_coming_soon_until_an_apk_is_published(app, admin):
    anon = app.test_client()
    page = anon.get("/").get_data(as_text=True)
    assert "Android app coming soon" in page and "Download for Android" not in page
    assert anon.get("/download").status_code == 404
    r = upload(admin, "1.0.0", fake_apk(), notes="First release")
    assert b"home page now shows the download button" in r.data
    page = anon.get("/").get_data(as_text=True)
    assert "Download for Android" in page and "Android app coming soon" not in page
    assert "First release" in page and "How to install" in page and "tweaks online" in page


def test_download_returns_exact_file_and_counts_people(app, admin):
    apk = fake_apk(pad=5 * 1024 * 1024)               # spans three database pieces
    upload(admin, "2.0.0", apk)
    with app.app_context():
        assert ApkChunk.query.count() == -(-len(apk) // CHUNK)
        rid = ApkRelease.query.one().id

    def get(path="/download", ip="10.0.0.1", **h):
        return app.test_client().get(path, environ_overrides={"REMOTE_ADDR": ip}, headers={"User-Agent": "Chrome", **h})

    d = get()
    assert d.status_code == 200 and d.data == apk and int(d.headers["Content-Length"]) == len(apk)
    assert d.headers["Content-Type"].startswith("application/vnd.android.package-archive")
    assert "genzvpn-2.0.0.apk" in d.headers["Content-Disposition"] and d.headers["Accept-Ranges"] == "bytes"
    get(); get(ip="10.0.0.2"); get(f"/download/{rid}", ip="10.0.0.3")
    # a resumed download is served from the right byte and is not counted again
    cut = CHUNK + 123
    p = get(Range=f"bytes={cut}-")
    assert p.status_code == 206 and p.data == apk[cut:] and p.headers["Content-Range"] == f"bytes {cut}-{len(apk)-1}/{len(apk)}"
    mid = get(Range=f"bytes={CHUNK - 5}-{CHUNK + 4}")
    assert mid.status_code == 206 and mid.data == apk[CHUNK - 5:CHUNK + 5]
    assert get(Range="bytes=-100").data == apk[-100:]
    assert get(Range=f"bytes={len(apk) + 10}-").status_code == 416
    assert app.test_client().head("/download").status_code == 200
    page = admin.get("/admin/?tab=app").get_data(as_text=True)
    assert re.search(r"<b>4</b><span class=\"muted\">downloads", page) and re.search(r"<b>3</b><span class=\"muted\">people", page)
    with app.app_context():
        assert ApkDownload.query.count() == 4
        assert all("10.0.0" not in x.visitor for x in ApkDownload.query)


def test_rejects_bad_uploads(app, admin):
    assert b"not an Android APK" in upload(admin, "1", b"just text").data
    r = admin.post("/admin/app/upload", data={"csrf": csrf(admin, "/admin/?tab=app"), "app_name": "A", "version": "1",
                   "apk": (io.BytesIO(fake_apk()), "app.exe")}, content_type="multipart/form-data", follow_redirects=True)
    assert b"must end in .apk" in r.data
    assert b"Choose the APK file" in upload(admin, "1").data
    with app.app_context():
        assert ApkRelease.query.count() == 0 and ApkChunk.query.count() == 0


def test_hide_latest_and_delete(app, admin):
    upload(admin, "1.0.0", fake_apk(b"a"))
    upload(admin, "2.0.0", fake_apk(b"b"))
    with app.app_context():
        new = ApkRelease.query.filter_by(version="2.0.0").one().id
        old = ApkRelease.query.filter_by(version="1.0.0").one().id
    anon = app.test_client()
    assert b"dexb" in anon.get("/latest").data
    admin.post(f"/admin/app/{new}/toggle", data={"csrf": csrf(admin, "/admin/?tab=app")})
    assert anon.get(f"/download/{new}").status_code == 404 and b"dexa" in anon.get("/download").data
    assert "Older versions" not in anon.get("/").get_data(as_text=True)
    admin.post(f"/admin/app/{old}/delete", data={"csrf": csrf(admin, "/admin/?tab=app")})
    admin.post(f"/admin/app/{new}/toggle", data={"csrf": csrf(admin, "/admin/?tab=app")})
    with app.app_context():
        assert ApkRelease.query.count() == 1 and ApkChunk.query.filter_by(release_id=old).count() == 0


def test_edit_replaces_the_file(app, admin):
    upload(admin, "1.0", fake_apk(b"one"))
    with app.app_context():
        rid = ApkRelease.query.one().id
    new = fake_apk(b"two")
    admin.post(f"/admin/app/{rid}", data={"csrf": csrf(admin, f"/admin/app/{rid}"), "app_name": "GenzVPN", "version": "1.1",
               "notes": "n", "is_published": "1", "apk": (io.BytesIO(new), "x.apk")}, content_type="multipart/form-data")
    assert app.test_client().get("/download").data == new
    with app.app_context():
        r = ApkRelease.query.one()
        assert r.version == "1.1" and r.size == len(new)


def test_apk_admin_needs_login_and_other_uploads_stay_small(app, admin):
    anon = app.test_client()
    assert anon.post("/admin/app/upload", data={}).status_code in (302, 400)
    big = admin.post("/admin/import-bundle", data={"csrf": csrf(admin, "/admin/?tab=backup"),
                     "bundle": (io.BytesIO(b"x" * (3 * 1024 * 1024)), "b.json")}, content_type="multipart/form-data")
    assert big.status_code == 413
