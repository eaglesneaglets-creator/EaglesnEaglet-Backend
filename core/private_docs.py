"""Private (access-controlled) storage for identity documents.

Government IDs, CVs and recommendation letters are PII. They used to be
uploaded as public Cloudinary assets and stored as their ``secure_url``, so
anyone holding the link could open them indefinitely.

Now they are uploaded with ``type='authenticated'`` (Cloudinary refuses to
serve them without a signature) and the model field stores an opaque reference
instead of a URL::

    cld-private:<resource_type>/<format>/<public_id>

Readers (the owner, KYC reviewers) get a short-lived signed download URL from
:func:`signed_document_url`. Legacy rows that still hold a public URL keep
working until ``manage.py privatize_kyc_documents`` converts them.
"""
from __future__ import annotations

import re
import time

import cloudinary
import cloudinary.uploader
import cloudinary.utils

PRIVATE_PREFIX = "cld-private:"
#: Reference to a document in the S3 bucket's private/ prefix: ``s3-private:<key>``.
S3_PRIVATE_PREFIX = "s3-private:"
PRIVATE_DELIVERY_TYPE = "authenticated"
#: Signed download links expire quickly: long enough to open/download, short
#: enough that a leaked link (logs, browser history, forwarded email) dies fast.
SIGNED_URL_TTL_SECONDS = 5 * 60

# https://res.cloudinary.com/<cloud>/<resource_type>/upload/[<transforms>/][v<ver>/]<public_id>[.<ext>]
_PUBLIC_URL_RE = re.compile(
    r"^https?://res\.cloudinary\.com/[^/]+/(?P<rtype>image|video|raw)/upload/"
    r"(?:[^/]*,[^/]*/)*"        # optional transformation segments (contain commas)
    r"(?:v\d+/)?"               # optional version
    r"(?P<path>.+)$"
)


def make_reference(resource_type: str, fmt: str | None, public_id: str) -> str:
    return f"{PRIVATE_PREFIX}{resource_type}/{fmt or ''}/{public_id}"


def parse_reference(value) -> tuple[str, str, str] | None:
    """Return ``(resource_type, format, public_id)`` or None if not a private ref."""
    if not value or not isinstance(value, str) or not value.startswith(PRIVATE_PREFIX):
        return None
    body = value[len(PRIVATE_PREFIX):]
    parts = body.split("/", 2)
    if len(parts) != 3 or not parts[0] or not parts[2]:
        return None
    return parts[0], parts[1], parts[2]


def s3_key_from_reference(value) -> str | None:
    """Bucket key for an ``s3-private:`` reference (must sit under private/)."""
    from . import object_storage
    if not value or not isinstance(value, str) or not value.startswith(S3_PRIVATE_PREFIX):
        return None
    key = value[len(S3_PRIVATE_PREFIX):]
    return key if key.startswith(object_storage.PRIVATE_PREFIX) else None


def is_private_reference(value) -> bool:
    return parse_reference(value) is not None or s3_key_from_reference(value) is not None


def parse_public_url(url: str) -> tuple[str, str, str] | None:
    """Split a legacy public Cloudinary URL into ``(resource_type, format, public_id)``.

    For ``raw`` assets the extension is part of the public_id; for image/video
    it is the delivery format.
    """
    if not url or not isinstance(url, str):
        return None
    m = _PUBLIC_URL_RE.match(url.split("?", 1)[0])
    if not m:
        return None
    rtype, path = m.group("rtype"), m.group("path")
    if rtype == "raw":
        return rtype, "", path
    stem, dot, ext = path.rpartition(".")
    if not dot:
        return rtype, "", path
    return rtype, ext, stem


def upload_private_document(file, file_type: str) -> str:
    """Upload ``file`` as an authenticated asset and return the stored reference."""
    from .storage import upload_to_cloudinary  # local import: avoid cycles

    from . import object_storage

    result = upload_to_cloudinary(file, file_type, type=PRIVATE_DELIVERY_TYPE)
    public_id = result.get("public_id")
    if not public_id:
        raise ValueError("Upload returned no object id")
    if str(public_id).startswith(object_storage.PRIVATE_PREFIX):
        return f"{S3_PRIVATE_PREFIX}{public_id}"
    return make_reference(result.get("resource_type") or "raw", result.get("format"), public_id)


def signed_document_url(value, ttl: int = SIGNED_URL_TTL_SECONDS) -> str | None:
    """Short-lived download URL for a stored document value.

    * private reference → signed, expiring Cloudinary download URL
    * legacy public URL → returned unchanged (convert with privatize_kyc_documents)
    * empty → None
    """
    if not value:
        return None
    value = str(value)
    s3_key = s3_key_from_reference(value)
    if s3_key is not None:
        from . import object_storage
        return object_storage.presigned_get(s3_key, ttl)
    if value.startswith(S3_PRIVATE_PREFIX):
        return None  # malformed / non-private key: never sign it
    ref = parse_reference(value)
    if ref is None:
        return value
    resource_type, fmt, public_id = ref
    return cloudinary.utils.private_download_url(
        public_id,
        fmt,
        resource_type=resource_type,
        type=PRIVATE_DELIVERY_TYPE,
        expires_at=int(time.time()) + int(ttl),
        attachment=False,
    )


def privatize_public_asset(url: str) -> str | None:
    """Switch an existing public asset to authenticated delivery.

    Returns the new private reference, or None if ``url`` is not a Cloudinary
    upload URL we can convert. Raises on Cloudinary API errors.
    """
    parsed = parse_public_url(url)
    if parsed is None:
        return None
    resource_type, fmt, public_id = parsed
    cloudinary.uploader.rename(
        public_id,
        public_id,
        resource_type=resource_type,
        type="upload",
        to_type=PRIVATE_DELIVERY_TYPE,
        overwrite=False,
        invalidate=True,  # purge the public copy from the CDN
    )
    return make_reference(resource_type, fmt, public_id)
