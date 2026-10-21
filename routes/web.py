import os

from flask import Blueprint, current_app, render_template, send_from_directory

from services.bundle import build_bundle

bp = Blueprint("web", __name__)


def _apk_path():
    return os.path.join(current_app.root_path, "static", "downloads")


@bp.get("/")
def index():
    has_apk = os.path.exists(os.path.join(_apk_path(), "genzvpn.apk"))
    b = build_bundle(public=True)
    return render_template("landing.html", has_apk=has_apk, server_count=len(b["servers"]))


@bp.get("/download")
def download():
    if not os.path.exists(os.path.join(_apk_path(), "genzvpn.apk")):
        return render_template("error.html", code=404, message="The app file is not uploaded yet."), 404
    return send_from_directory(_apk_path(), "genzvpn.apk", as_attachment=True,
                               mimetype="application/vnd.android.package-archive")
