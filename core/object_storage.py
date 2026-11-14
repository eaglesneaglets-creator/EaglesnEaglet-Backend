"""S3-compatible object storage (Railway Storage Buckets; MinIO locally).

Railway buckets are PRIVATE: nothing is reachable without a signature. So:

* Objects live under one of two key prefixes:
    ``public/…``   assets anyone may view (avatars, product images, lessons)
    ``private/…``  identity documents (IDs, CVs, recommendation letters)
* The database never stores a signed URL (they expire). Public assets are
  stored as a STABLE media URL — ``{BACKEND_URL}/api/v1/media/<path>`` — and
  ``core.views.media_redirect_view`` 302-redirects it to a short-lived signed
  URL. That view only ever serves the ``public/`` prefix.
* Private documents are stored as ``s3-private:<key>`` references and are
  only readable through ``core.private_docs.signed_document_url``.

``is_configured()``: credentials present (media links and the backfill work).
``is_enabled()``: also ``MEDIA_STORAGE=bucket``, so new uploads go here;
otherwise they keep going to Cloudinary (see ``core.storage``).
"""
from __future__ import annotations

import io
import mimetypes
import os
import re
import uuid
from functools import lru_cache

from django.conf import settings

PUBLIC_PREFIX = "public/"
PRIVATE_PREFIX = "private/"
MEDIA_PATH = "/api/v1/media/"
#: Lifetime of the signed URL a media redirect points at.
PUBLIC_URL_TTL = 60 * 60
#: Lifetime of a signed browser upload URL.
UPLOAD_URL_TTL = 10 * 60
THUMB_SUFFIX = "__thumb.webp"
THUMB_MAX_PX = 400
#: Images are downscaled to this on upload (Cloudinary used to do q_auto).
IMAGE_MAX_PX = 1600

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _cfg() -> dict:
    return getattr(settings, "OBJECT_STORAGE", None) or {}


def is_configured() -> bool:
    """Bucket credentials are present (media links + backfill can work)."""
    c = _cfg()
    return bool(c.get("BUCKET") and c.get("ENDPOINT") and c.get("ACCESS_KEY_ID") and c.get("SECRET_ACCESS_KEY"))


def is_enabled() -> bool:
    """NEW uploads go to the bucket: configured AND MEDIA_STORAGE=bucket."""
    return is_configured() and getattr(settings, "MEDIA_STORAGE", "cloudinary") == "bucket"


def bucket() -> str:
    return _cfg()["BUCKET"]


@lru_cache(maxsize=4)
def _client_for(endpoint: str, access_key: str, secret_key: str, region: str, addressing: str):
    import boto3
    from botocore.config import Config

    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": addressing},
            retries={"max_attempts": 3, "mode": "standard"},
            connect_timeout=10,
            read_timeout=60,
            # Newer botocore adds CRC checksums by default; several
            # S3-compatible stores reject them.
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )


def client(public: bool = False):
    """S3 client. ``public=True`` signs URLs for the browser-facing endpoint
    (differs from the internal one only in local Docker: minio vs localhost)."""
    c = _cfg()
    endpoint = (c.get("PUBLIC_ENDPOINT") if public else None) or c["ENDPOINT"]
    return _client_for(
        endpoint, c["ACCESS_KEY_ID"], c["SECRET_ACCESS_KEY"],
        c.get("REGION") or "auto", c.get("ADDRESSING_STYLE") or "auto",
    )


# ── keys & URLs ──────────────────────────────────────────────────────────

def safe_filename(name: str) -> str:
    name = os.path.basename(str(name or "file"))
    name = _SAFE_NAME.sub("-", name).strip("-.") or "file"
    return name[-80:]


def build_key(folder: str, filename: str, *, private: bool = False) -> str:
    prefix = PRIVATE_PREFIX if private else PUBLIC_PREFIX
    return f"{prefix}{folder.strip('/')}/{uuid.uuid4().hex[:12]}-{safe_filename(filename)}"


def media_url(key: str) -> str:
    """Stable, storable URL for a PUBLIC object."""
    if not key.startswith(PUBLIC_PREFIX):
        raise ValueError("media_url() is only for public/ objects")
    base = getattr(settings, "BACKEND_URL", "").rstrip("/")
    return f"{base}{MEDIA_PATH}{key[len(PUBLIC_PREFIX):]}"


def key_from_media_url(url: str) -> str | None:
    if not url or MEDIA_PATH not in str(url):
        return None
    return PUBLIC_PREFIX + str(url).split(MEDIA_PATH, 1)[1].split("?", 1)[0]


def presigned_get(key: str, ttl: int = PUBLIC_URL_TTL, *, download_name: str | None = None) -> str:
    params = {"Bucket": bucket(), "Key": key}
    if download_name:
        params["ResponseContentDisposition"] = f'inline; filename="{safe_filename(download_name)}"'
    return client(public=True).generate_presigned_url("get_object", Params=params, ExpiresIn=int(ttl))


def presigned_put(key: str, content_type: str, content_length: int, ttl: int = UPLOAD_URL_TTL) -> str:
    """Signed browser upload URL. Content type AND exact byte length are part
    of the signature, so the client cannot upload a different/larger file."""
    return client(public=True).generate_presigned_url(
        "put_object",
        Params={
            "Bucket": bucket(), "Key": key,
            "ContentType": content_type, "ContentLength": int(content_length),
        },
        ExpiresIn=int(ttl),
    )


# ── object operations ───────────────────────────────────────────────────

def put_bytes(key: str, data: bytes, content_type: str) -> None:
    client().put_object(
        Bucket=bucket(), Key=key, Body=data, ContentType=content_type,
        CacheControl="public, max-age=31536000, immutable" if key.startswith(PUBLIC_PREFIX) else "private, no-store",
    )


def exists(key: str) -> bool:
    from botocore.exceptions import ClientError
    try:
        client().head_object(Bucket=bucket(), Key=key)
        return True
    except ClientError as exc:
        if exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") in (403, 404):
            return False
        raise


def delete(key: str) -> None:
    client().delete_object(Bucket=bucket(), Key=key)


def _downscale(data: bytes, max_px: int, fmt: str | None = None) -> tuple[bytes, str] | None:
    """Return (bytes, mime) of the image resized to fit ``max_px``; None if not an image."""
    try:
        from PIL import Image, ImageOps
        img = Image.open(io.BytesIO(data))
        img = ImageOps.exif_transpose(img)  # honour phone-camera rotation; also drops EXIF (GPS)
        out_fmt = fmt or (img.format if img.format in ("JPEG", "PNG", "WEBP") else "JPEG")
        if getattr(img, "is_animated", False) and not fmt:
            return None  # keep animated GIF/WebP untouched
        img.thumbnail((max_px, max_px))
        if out_fmt == "JPEG" and img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format=out_fmt, quality=82, optimize=True)
        return buf.getvalue(), f"image/{out_fmt.lower()}"
    except Exception:
        return None


def upload(file, folder: str, *, private: bool = False, is_image: bool = False) -> dict:
    """Upload a Django file object. Returns the same dict shape the Cloudinary
    helper returns, so callers don't care which backend is active."""
    name = getattr(file, "name", None) or str(file)
    content_type = getattr(file, "content_type", None) or mimetypes.guess_type(name)[0] or "application/octet-stream"
    if hasattr(file, "seek"):
        file.seek(0)
    data = file.read()
    key = build_key(folder, name, private=private)

    thumb_url = None
    if is_image and not private:
        resized = _downscale(data, IMAGE_MAX_PX)
        if resized:
            data, content_type = resized
        thumb = _downscale(data, THUMB_MAX_PX, fmt="WEBP")
        if thumb:
            put_bytes(key + THUMB_SUFFIX, thumb[0], thumb[1])
            thumb_url = media_url(key + THUMB_SUFFIX)

    put_bytes(key, data, content_type)
    url = None if private else media_url(key)
    ext = os.path.splitext(name)[1].lstrip(".").lower()
    return {
        "url": url,
        "secure_url": url,
        "public_id": key,
        "resource_type": "image" if content_type.startswith("image/") else "video" if content_type.startswith("video/") else "raw",
        "format": ext,
        "bytes": len(data),
        "original_filename": os.path.splitext(os.path.basename(name))[0],
        "optimized_url": url if is_image else None,
        "thumbnail_url": thumb_url or (url if is_image else None),
        "raw": {"key": key, "bucket": bucket()},
    }


def thumbnail_url_for(key: str) -> str | None:
    """Media URL of the thumbnail written alongside an uploaded image."""
    if not key or not key.startswith(PUBLIC_PREFIX):
        return None
    return media_url(key + THUMB_SUFFIX)
