import gzip

from flask import Blueprint, Response, request

from services.bundle import body_and_etag, build_bundle

bp = Blueprint("api", __name__, url_prefix="/api/v1")


@bp.get("/config")
def config():
    """Public, no login. Small on purpose: ETag + gzip so it costs users almost no data."""
    body, etag = body_and_etag(build_bundle(public=True))
    headers = {"ETag": etag, "Cache-Control": "no-cache", "Content-Type": "application/json; charset=utf-8",
               "Access-Control-Allow-Origin": "*"}
    if request.headers.get("If-None-Match") == etag:
        return Response(status=304, headers={"ETag": etag})
    if "gzip" in request.headers.get("Accept-Encoding", "") and len(body) > 400:
        body = gzip.compress(body, 6)
        headers["Content-Encoding"] = "gzip"
    return Response(body, headers=headers)
