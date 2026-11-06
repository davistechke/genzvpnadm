import os

from flask import Blueprint, abort, current_app, render_template, send_from_directory

from models import ApkRelease, db
from services import apk as apk_service
from services.bundle import build_bundle

bp = Blueprint("web", __name__)


def _legacy_file():
    """The old way: a file placed by hand at static/downloads/genzvpn.apk. Still honoured if nothing was uploaded."""
    return os.path.join(current_app.root_path, "static", "downloads")


def _has_legacy():
    return os.path.exists(os.path.join(_legacy_file(), "genzvpn.apk"))


@bp.get("/")
def index():
    live = apk_service.latest_published()
    b = build_bundle(public=True)
    return render_template("landing.html", apk=live[0] if live else None, older=live[1:],
                           has_apk=_has_legacy(), tweak_count=len(b["tweaks"]))


@bp.route("/download", methods=["GET", "HEAD"])
@bp.route("/latest", methods=["GET", "HEAD"])
def download():
    """A link that never changes: always the newest published app."""
    live = apk_service.latest_published()
    if live:
        return apk_service.serve(live[0])
    if _has_legacy():
        return send_from_directory(_legacy_file(), "genzvpn.apk", as_attachment=True,
                                   mimetype="application/vnd.android.package-archive")
    abort(404, "The app file is not uploaded yet.")


@bp.route("/download/<int:rid>", methods=["GET", "HEAD"])
def download_version(rid):
    r = db.session.get(ApkRelease, rid)
    if r is None or not r.is_published:
        abort(404, "That version is not available.")
    return apk_service.serve(r)
