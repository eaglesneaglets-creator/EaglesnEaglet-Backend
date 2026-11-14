"""S3 bucket storage: key/URL rules, the media redirect, signing, and the
Cloudinary -> bucket backfill. The bucket itself is faked in memory."""
from unittest.mock import patch

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.core.management.base import CommandError
from rest_framework.test import APIClient

from apps.nests.models import Nest, NestPost
from apps.users.models import MentorKYC, User
from core import object_storage, private_docs
from core.storage import upload_to_cloudinary

CFG = {
    "BUCKET": "test-bucket", "ENDPOINT": "http://store:9000",
    "ACCESS_KEY_ID": "k", "SECRET_ACCESS_KEY": "s", "REGION": "auto",
    "ADDRESSING_STYLE": "path", "PUBLIC_ENDPOINT": "",
}
PUBLIC_URL = "https://res.cloudinary.com/demo/image/upload/v1/eaglesneaglets/images/content/pic_a1.jpg"
ID_URL = "https://res.cloudinary.com/demo/image/upload/v1/eaglesneaglets/documents/government_ids/id_9.jpg"


@pytest.fixture
def bucket(settings, monkeypatch):
    """Enable object storage with an in-memory object map."""
    settings.OBJECT_STORAGE = dict(CFG)
    settings.MEDIA_STORAGE = "bucket"
    settings.BACKEND_URL = "https://api.example.test"
    objects = {}
    monkeypatch.setattr(object_storage, "put_bytes", lambda key, data, ctype: objects.__setitem__(key, (data, ctype)))
    monkeypatch.setattr(object_storage, "exists", lambda key: key in objects)
    monkeypatch.setattr(object_storage, "delete", lambda key: objects.pop(key, None))
    monkeypatch.setattr(object_storage, "presigned_get", lambda key, ttl=3600, **kw: f"https://signed.test/{key}?sig=1&ttl={ttl}")
    monkeypatch.setattr(object_storage, "presigned_put", lambda key, ct, n, ttl=600: f"https://signed.test/put/{key}?len={n}")
    return objects


def test_disabled_without_config(settings):
    settings.OBJECT_STORAGE = {**CFG, "SECRET_ACCESS_KEY": ""}
    assert not object_storage.is_enabled()


def test_media_url_only_for_public_objects(bucket):
    key = object_storage.build_key("eaglesneaglets/images/content", "My Photo (1).png")
    assert key.startswith("public/eaglesneaglets/images/content/") and key.endswith("-My-Photo-1-.png")
    url = object_storage.media_url(key)
    assert url.startswith("https://api.example.test/api/v1/media/eaglesneaglets/")
    assert object_storage.key_from_media_url(url) == key
    with pytest.raises(ValueError):
        object_storage.media_url("private/x/y.pdf")


def test_upload_routes_to_bucket_and_private_docs_get_a_reference(bucket):
    res = upload_to_cloudinary(SimpleUploadedFile("notes.pdf", b"%PDF-1.4", content_type="application/pdf"), "misc")
    assert res["public_id"] in bucket and res["secure_url"].startswith("https://api.example.test/api/v1/media/")

    ref = private_docs.upload_private_document(
        SimpleUploadedFile("id.pdf", b"%PDF-1.4", content_type="application/pdf"), "government_ids",
    )
    assert ref.startswith("s3-private:private/") and private_docs.is_private_reference(ref)
    assert ref[len("s3-private:"):] in bucket
    signed = private_docs.signed_document_url(ref)
    assert signed.startswith("https://signed.test/private/") and "ttl=300" in signed


def test_private_reference_pointing_at_public_prefix_is_never_signed(bucket):
    assert private_docs.signed_document_url("s3-private:public/whatever.png") is None


@pytest.mark.django_db
def test_media_redirect_serves_public_prefix_only(bucket):
    c = APIClient()
    r = c.get("/api/v1/media/eaglesneaglets/images/content/a.png")
    assert r.status_code == 302 and r["Location"].startswith("https://signed.test/public/eaglesneaglets/")
    assert "max-age" in r["Cache-Control"]
    assert c.get("/api/v1/media/../private/ids/a.png").status_code == 404
    assert c.post("/api/v1/media/eaglesneaglets/a.png").status_code == 405


@pytest.mark.django_db
def test_media_redirect_404_when_bucket_not_configured(settings):
    settings.OBJECT_STORAGE = {}
    assert APIClient().get("/api/v1/media/a.png").status_code == 404


@pytest.mark.django_db
def test_sign_endpoint_issues_bucket_upload_and_validates(bucket):
    c = APIClient()
    c.force_authenticate(User.objects.create_user(email="s3signer@test.local", password="x", role="eagle"))
    ok = c.post("/api/v1/uploads/sign/", {
        "context": "content_thumbnail", "filename": "c.png", "content_type": "image/png", "size": 1234,
    }, format="json")
    assert ok.status_code == 200
    d = ok.data["data"]
    assert d["provider"] == "s3" and d["key"].startswith("public/") and "len=1234" in d["upload_url"]
    assert d["file_url"] == object_storage.media_url(d["key"])

    def sign(**over):
        body = {"context": "content_thumbnail", "filename": "c.png", "content_type": "image/png", "size": 10, **over}
        return c.post("/api/v1/uploads/sign/", body, format="json").status_code

    assert sign(content_type="application/pdf") == 400
    assert sign(size=6 * 1024 * 1024) == 400
    assert sign(size=None) == 400
    assert sign(context="government_id") == 400


# ── backfill ────────────────────────────────────────────────────────────

class _Resp:
    headers = {"Content-Type": "image/jpeg", "Content-Length": "4"}
    content = b"\xff\xd8\xff\xd9"

    def raise_for_status(self):
        pass

    def close(self):
        pass


@pytest.fixture
def legacy_rows(db):
    eagle = User.objects.create_user(email="bf-s3@test.local", password="x", role="eagle")
    nest = Nest.objects.create(name="Backfill Nest", eagle=eagle, banner_image=PUBLIC_URL)
    post = NestPost.objects.create(nest=nest, author=eagle, content=f"see {PUBLIC_URL} here", attachment_url=PUBLIC_URL)
    kyc = MentorKYC.objects.create(user=eagle)
    MentorKYC.objects.filter(pk=kyc.pk).update(
        government_id=ID_URL, cv=private_docs.make_reference("raw", "", "eaglesneaglets/documents/cvs/cv_1.pdf"),
    )
    return nest, post, kyc


def test_backfill_requires_bucket(db, settings):
    settings.OBJECT_STORAGE = {}
    with pytest.raises(CommandError, match="not configured"):
        call_command("migrate_media_to_bucket", "--dry-run")


def test_backfill_dry_run_writes_nothing(bucket, legacy_rows):
    nest, post, kyc = legacy_rows
    with patch("requests.get", return_value=_Resp()) as get:
        call_command("migrate_media_to_bucket", "--dry-run")
        get.assert_not_called()
    assert bucket == {}
    nest.refresh_from_db()
    assert nest.banner_image == PUBLIC_URL


def test_backfill_copies_and_repoints(bucket, legacy_rows):
    nest, post, kyc = legacy_rows
    signed_cld = patch("core.private_docs.cloudinary.utils.private_download_url", return_value="https://cld/signed")
    with patch("requests.get", return_value=_Resp()) as get, signed_cld:
        call_command("migrate_media_to_bucket")
        first_calls = get.call_count
        call_command("migrate_media_to_bucket")          # idempotent: nothing left
        assert get.call_count == first_calls
    assert 3 <= first_calls <= 4                          # shared public file fetched once (+ activity-log excerpt)

    nest.refresh_from_db(); post.refresh_from_db(); kyc.refresh_from_db()
    media = "https://api.example.test/api/v1/media/eaglesneaglets/images/content/pic_a1.jpg"
    assert nest.banner_image == media and post.attachment_url == media
    assert post.content == f"see {media} here"
    assert "public/eaglesneaglets/images/content/pic_a1.jpg" in bucket

    # Identity documents land in the private prefix, even the legacy PUBLIC id.
    assert str(kyc.government_id) == "s3-private:private/eaglesneaglets/documents/government_ids/id_9.jpg"
    assert kyc.cv == "s3-private:private/eaglesneaglets/documents/cvs/cv_1.pdf"
    assert not any(k.startswith("public/") and "government_ids" in k for k in bucket)


def test_backfill_leaves_value_alone_when_download_fails(bucket, legacy_rows):
    nest, _, _ = legacy_rows
    with patch("requests.get", side_effect=OSError("boom")), \
         patch("core.private_docs.cloudinary.utils.private_download_url", return_value="https://cld/signed"):
        call_command("migrate_media_to_bucket")
    nest.refresh_from_db()
    assert nest.banner_image == PUBLIC_URL and bucket == {}


def test_credentials_alone_do_not_switch_uploads(settings):
    """Connecting the Railway bucket must not move uploads until MEDIA_STORAGE=bucket."""
    settings.OBJECT_STORAGE = dict(CFG)
    settings.MEDIA_STORAGE = "cloudinary"
    assert object_storage.is_configured()
    assert not object_storage.is_enabled()
    settings.MEDIA_STORAGE = "bucket"
    assert object_storage.is_enabled()


PROD_SETTINGS_PROBE = """
import json, django
from django.conf import settings
django.setup()
print(json.dumps({
    "static_url": settings.STATIC_URL,
    "static_backend": settings.STORAGES["staticfiles"]["BACKEND"],
    "bucket": settings.OBJECT_STORAGE["BUCKET"],
    "endpoint": settings.OBJECT_STORAGE["ENDPOINT"],
    "media_storage": settings.MEDIA_STORAGE,
}))
"""


def test_railway_bucket_variables_do_not_hijack_static_files():
    """Regression: Railway injects AWS_* when a bucket is connected. The old
    production settings then served static from https://None.s3.amazonaws.com."""
    import json
    import os
    import subprocess
    import sys
    from pathlib import Path

    from cryptography.fernet import Fernet

    env = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "S3_", "DJANGO_"))}
    env.update({
        "DJANGO_SETTINGS_MODULE": "eaglesneagletsbackend.settings.production",
        "SECRET_KEY": "probe-only", "ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "ALLOWED_HOSTS": "api.example.test", "DATABASE_URL": "postgres://u:p@localhost:5432/db",
        "CLOUDINARY_API_KEY": "k", "CLOUDINARY_API_SECRET": "s", "CLOUDINARY_CLOUD_NAME": "c",
        "AWS_ACCESS_KEY_ID": "railway-key", "AWS_SECRET_ACCESS_KEY": "railway-secret",
        "AWS_ENDPOINT_URL": "https://storage.example.test", "AWS_S3_BUCKET_NAME": "media-abc",
        "AWS_DEFAULT_REGION": "auto",
    })
    out = subprocess.run(
        [sys.executable, "-c", PROD_SETTINGS_PROBE],
        cwd=Path(__file__).resolve().parents[2], env=env, capture_output=True, text=True, timeout=120,
    )
    assert out.returncode == 0, out.stderr[-2000:]
    data = json.loads(out.stdout.strip().splitlines()[-1])
    assert "amazonaws" not in data["static_url"] and "None" not in data["static_url"]
    assert data["static_backend"].startswith("whitenoise.")
    assert data["bucket"] == "media-abc" and data["endpoint"] == "https://storage.example.test"
    assert data["media_storage"] == "cloudinary"
