"""Storing, serving and counting downloads of the Android app (APK).

The file lives in the database in 2 MB pieces, so it is still there after a redeploy or restart, with no disk to pay
for. Downloads can be resumed (HTTP Range), which matters on weak mobile connections.
"""
import hashlib
import re
import zipfile
from datetime import datetime, time as dtime, timedelta

from flask import Response, abort, current_app, request, stream_with_context
from sqlalchemy import delete, func, insert, select

from models import CHUNK, ApkChunk, ApkDownload, ApkRelease, db, utcnow

APK_MIME = "application/vnd.android.package-archive"


class ApkError(ValueError):
    pass


def check_apk(stream):
    """It must be a zip with an AndroidManifest.xml, so a wrong file cannot be published by mistake."""
    stream.seek(0)
    if not zipfile.is_zipfile(stream):
        raise ApkError("That file is not an Android APK.")
    stream.seek(0)
    if "AndroidManifest.xml" not in zipfile.ZipFile(stream).namelist():
        raise ApkError("That file is not an Android APK.")
    stream.seek(0)


def store(release, stream):
    """Replace the release's file with the stream. The caller commits."""
    db.session.execute(delete(ApkChunk).where(ApkChunk.release_id == release.id))
    h, size, idx = hashlib.sha256(), 0, 0
    stream.seek(0)
    while True:
        piece = stream.read(CHUNK)
        if not piece:
            break
        h.update(piece)
        size += len(piece)
        db.session.execute(insert(ApkChunk).values(release_id=release.id, idx=idx, data=piece))
        idx += 1
    release.size, release.sha256 = size, h.hexdigest()


def remove(release):
    db.session.execute(delete(ApkChunk).where(ApkChunk.release_id == release.id))
    db.session.execute(delete(ApkDownload).where(ApkDownload.release_id == release.id))


def latest_published():
    return ApkRelease.query.filter_by(is_published=True).order_by(ApkRelease.created_at.desc(), ApkRelease.id.desc()).all()


def _visitor():
    raw = f"{current_app.config['SECRET_KEY']}|{request.remote_addr}|{request.headers.get('User-Agent', '')}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def serve(release):
    """Send the APK (all of it, or the part a resumed download asks for) and count the download once."""
    size = release.size or 0
    if not size:
        abort(404, "The app file is not uploaded yet.")
    start, end, status = 0, size - 1, 200
    rng = request.headers.get("Range", "").strip()
    m = re.fullmatch(r"bytes=(\d*)-(\d*)", rng) if rng else None
    if m and (m.group(1) or m.group(2)):
        if m.group(1):
            start = int(m.group(1))
            end = min(int(m.group(2)) if m.group(2) else size - 1, size - 1)
        else:
            start = max(size - int(m.group(2)), 0)
        if start > end or start >= size:
            return Response(status=416, headers={"Content-Range": f"bytes */{size}"})
        status = 206
    if request.method == "GET" and start == 0:  # a resumed chunk is not a new download
        release.downloads = (release.downloads or 0) + 1
        db.session.add(ApkDownload(release_id=release.id, visitor=_visitor()))
        db.session.commit()
    rid, first, last = release.id, start // CHUNK, end // CHUNK

    def body():
        for i in range(first, last + 1):
            data = db.session.execute(select(ApkChunk.data).where(ApkChunk.release_id == rid, ApkChunk.idx == i)).scalar_one()
            data = bytes(data)
            lo = start - i * CHUNK if i == first else 0
            hi = end - i * CHUNK + 1 if i == last else len(data)
            yield data[lo:hi]

    headers = {"Content-Length": str(end - start + 1), "Accept-Ranges": "bytes", "Cache-Control": "no-cache",
               "Content-Disposition": f'attachment; filename="{release.filename}"'}
    if status == 206:
        headers["Content-Range"] = f"bytes {start}-{end}/{size}"
    if request.method == "HEAD":
        return Response(status=status, headers=headers, mimetype=APK_MIME)
    return Response(stream_with_context(body()), status=status, headers=headers, mimetype=APK_MIME)


def stats():
    """Downloads, people (different phones/browsers), today, last 7 days, a 14-day chart and per-version numbers."""
    off = timedelta(hours=current_app.config["TZ_OFFSET_HOURS"])
    today = (utcnow() + off).date()
    start = datetime.combine(today - timedelta(days=13), dtime.min) - off
    per_day = {today - timedelta(days=i): 0 for i in range(14)}
    for (created,) in db.session.query(ApkDownload.created_at).filter(ApkDownload.created_at >= start):
        d = (created + off).date()
        if d in per_day:
            per_day[d] += 1
    days = sorted(per_day.items())
    peak = max([n for _, n in days] + [1])
    bars = [{"x": i * 20, "h": round(n / peak * 56), "n": n, "label": d.strftime("%d %b"), "day": d.day}
            for i, (d, n) in enumerate(days)]
    per_release = {rid: (n, u) for rid, n, u in db.session.query(
        ApkDownload.release_id, func.count(ApkDownload.id), func.count(func.distinct(ApkDownload.visitor)))
        .group_by(ApkDownload.release_id)}
    return {
        "total": db.session.query(func.count(ApkDownload.id)).scalar() or 0,
        "people": db.session.query(func.count(func.distinct(ApkDownload.visitor))).scalar() or 0,
        "today": per_day[today], "week": sum(n for d, n in days if d > today - timedelta(days=7)),
        "bars": bars, "per_release": per_release,
    }
