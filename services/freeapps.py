"""Storing, serving and counting downloads of the apps the admin shares (the Free apps section).

Same approach as the VPN app's APK: the file lives in the database in 2 MB pieces so it survives redeploys, and
downloads can be resumed (HTTP Range) for weak mobile connections.
"""
import hashlib
import re
from datetime import datetime, time as dtime, timedelta

from flask import Response, abort, current_app, request, stream_with_context
from sqlalchemy import delete, func, insert, select

from models import CHUNK, FreeApp, FreeAppChunk, FreeAppDownload, db, utcnow
from services.apk import APK_MIME, ApkError, check_apk  # noqa: F401  (re-exported for the admin routes)


def store(app_row, stream):
    """Replace the app's file with the stream. The caller commits."""
    db.session.execute(delete(FreeAppChunk).where(FreeAppChunk.app_id == app_row.id))
    h, size, idx = hashlib.sha256(), 0, 0
    stream.seek(0)
    while True:
        piece = stream.read(CHUNK)
        if not piece:
            break
        h.update(piece)
        size += len(piece)
        db.session.execute(insert(FreeAppChunk).values(app_id=app_row.id, idx=idx, data=piece))
        idx += 1
    app_row.size, app_row.sha256 = size, h.hexdigest()


def remove(app_row):
    db.session.execute(delete(FreeAppChunk).where(FreeAppChunk.app_id == app_row.id))
    db.session.execute(delete(FreeAppDownload).where(FreeAppDownload.app_id == app_row.id))


def published():
    return FreeApp.query.filter_by(is_published=True).order_by(FreeApp.created_at.desc(), FreeApp.id.desc()).all()


def _visitor():
    raw = f"{current_app.config['SECRET_KEY']}|{request.remote_addr}|{request.headers.get('User-Agent', '')}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def serve(app_row):
    """Send the file (all of it, or the part a resumed download asks for) and count the download once."""
    size = app_row.size or 0
    if not size:
        abort(404, "That app file is not uploaded yet.")
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
        app_row.downloads = (app_row.downloads or 0) + 1
        db.session.add(FreeAppDownload(app_id=app_row.id, visitor=_visitor()))
        db.session.commit()
    aid, first, last = app_row.id, start // CHUNK, end // CHUNK

    def body():
        for i in range(first, last + 1):
            data = db.session.execute(
                select(FreeAppChunk.data).where(FreeAppChunk.app_id == aid, FreeAppChunk.idx == i)).scalar_one()
            data = bytes(data)
            lo = start - i * CHUNK if i == first else 0
            hi = end - i * CHUNK + 1 if i == last else len(data)
            yield data[lo:hi]

    headers = {"Content-Length": str(end - start + 1), "Accept-Ranges": "bytes", "Cache-Control": "no-cache",
               "Content-Disposition": f'attachment; filename="{app_row.filename}"'}
    if status == 206:
        headers["Content-Range"] = f"bytes {start}-{end}/{size}"
    if request.method == "HEAD":
        return Response(status=status, headers=headers, mimetype=APK_MIME)
    return Response(stream_with_context(body()), status=status, headers=headers, mimetype=APK_MIME)


def stats():
    """Downloads, people (different phones/browsers), today, last 7 days, a 14-day chart and per-app numbers."""
    off = timedelta(hours=current_app.config["TZ_OFFSET_HOURS"])
    today = (utcnow() + off).date()
    start = datetime.combine(today - timedelta(days=13), dtime.min) - off
    per_day = {today - timedelta(days=i): 0 for i in range(14)}
    for (created,) in db.session.query(FreeAppDownload.created_at).filter(FreeAppDownload.created_at >= start):
        d = (created + off).date()
        if d in per_day:
            per_day[d] += 1
    days = sorted(per_day.items())
    peak = max([n for _, n in days] + [1])
    bars = [{"x": i * 20, "h": round(n / peak * 56), "n": n, "label": d.strftime("%d %b"), "day": d.day}
            for i, (d, n) in enumerate(days)]
    per_app = {aid: (n, u) for aid, n, u in db.session.query(
        FreeAppDownload.app_id, func.count(FreeAppDownload.id), func.count(func.distinct(FreeAppDownload.visitor)))
        .group_by(FreeAppDownload.app_id)}
    return {
        "total": db.session.query(func.count(FreeAppDownload.id)).scalar() or 0,
        "people": db.session.query(func.count(func.distinct(FreeAppDownload.visitor))).scalar() or 0,
        "today": per_day[today], "week": sum(n for d, n in days if d > today - timedelta(days=7)),
        "bars": bars, "per_app": per_app,
    }
