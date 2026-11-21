import os

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, send_from_directory, url_for

from models import REQUEST_KINDS, ApkRelease, FreeApp, UserRequest, db
from routes.common import check_csrf, record_failure, throttled
from services import apk as apk_service
from services import freeapps as free_service
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
                           has_apk=_has_legacy(), tweak_count=len(b["tweaks"]),
                           free_apps=free_service.published(), kinds=REQUEST_KINDS)


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


# ------------------------------------------------------------------ free apps shared by the admin

@bp.route("/apps/<int:aid>/download", methods=["GET", "HEAD"])
def free_app_download(aid):
    a = db.session.get(FreeApp, aid)
    if a is None or not a.is_published:
        abort(404, "That app is not available.")
    return free_service.serve(a)


# ------------------------------------------------------------------ requests and reports from users

@bp.post("/request")
def send_request():
    """Anyone can send one: a tweak that stopped working, a feature they want, or an idea. No account needed."""
    check_csrf()
    f = request.form
    if f.get("website"):          # hidden field only a bot fills in
        return redirect(url_for("web.index") + "#requests")
    key = f"request:{request.remote_addr}"
    if throttled(key, limit=5, window=3600):
        flash("You have sent a lot of requests. Please try again later.", "error")
        return redirect(url_for("web.index") + "#requests")
    kind = f.get("kind", "suggestion")
    message = f.get("message", "").strip()[:1500]
    if kind not in dict(REQUEST_KINDS):
        kind = "suggestion"
    if len(message) < 5:
        flash("Tell us a little more so we can help.", "error")
    else:
        db.session.add(UserRequest(kind=kind, subject=f.get("subject", "").strip()[:80], message=message,
                                   contact=f.get("contact", "").strip()[:80]))
        db.session.commit()
        record_failure(key)       # counts every sent request toward the hourly limit
        flash("Thank you! Your message was sent to the admin.", "ok")
    return redirect(url_for("web.index") + "#requests")
