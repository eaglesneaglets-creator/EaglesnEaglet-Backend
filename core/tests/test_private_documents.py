"""Identity documents must never be publicly reachable.

Covers: private reference format, signed/expiring URLs, the serializer mixin
(read → signed URL, write → refused), the legacy-URL migration command, and
the direct-upload signing endpoint refusing sensitive contexts while enforcing
allowed formats server-side.
"""
from unittest.mock import patch

import pytest
from django.core.management import call_command
from rest_framework.test import APIClient

from apps.users.models import MentorKYC, User
from apps.users.serializers import MentorKYCAdminSerializer, MentorKYCSerializer
from core import private_docs
from core.storage import UPLOAD_CONTEXTS, allowed_formats_for

PUBLIC_ID_URL = (
    "https://res.cloudinary.com/demo/image/upload/v1712345678/"
    "eaglesneaglets/documents/government_ids/abc123.jpg"
)
RAW_URL = "https://res.cloudinary.com/demo/raw/upload/v1712345678/eaglesneaglets/documents/cvs/cv_x1.pdf"


# ── reference helpers ────────────────────────────────────────────────────

def test_reference_roundtrip():
    ref = private_docs.make_reference("image", "jpg", "folder/abc")
    assert private_docs.parse_reference(ref) == ("image", "jpg", "folder/abc")
    assert private_docs.is_private_reference(ref)
    assert not private_docs.is_private_reference(PUBLIC_ID_URL)


def test_parse_public_url_image_and_raw():
    assert private_docs.parse_public_url(PUBLIC_ID_URL) == (
        "image", "jpg", "eaglesneaglets/documents/government_ids/abc123",
    )
    # raw: extension stays part of the public_id
    assert private_docs.parse_public_url(RAW_URL) == (
        "raw", "", "eaglesneaglets/documents/cvs/cv_x1.pdf",
    )
    assert private_docs.parse_public_url("https://evil.example.com/x.jpg") is None


def test_signed_url_is_expiring_and_authenticated():
    ref = private_docs.make_reference("image", "jpg", "folder/abc")
    with patch("core.private_docs.cloudinary.utils.private_download_url", return_value="SIGNED") as m:
        assert private_docs.signed_document_url(ref, ttl=60) == "SIGNED"
    args, kwargs = m.call_args
    assert args[0] == "folder/abc"
    assert kwargs["type"] == "authenticated"
    assert kwargs["expires_at"] > 0


def test_legacy_url_passes_through_and_empty_is_none():
    assert private_docs.signed_document_url(PUBLIC_ID_URL) == PUBLIC_ID_URL
    assert private_docs.signed_document_url("") is None
    assert private_docs.signed_document_url(None) is None


# ── serializer mixin ────────────────────────────────────────────────────

@pytest.fixture
def mentor_kyc(db):
    user = User.objects.create_user(email="doc-eagle@test.local", password="x", role="eagle")
    kyc = MentorKYC.objects.create(user=user)
    MentorKYC.objects.filter(pk=kyc.pk).update(
        government_id=private_docs.make_reference("image", "jpg", "ids/own"),
    )
    kyc.refresh_from_db()
    return kyc


def test_serializer_returns_signed_url_not_reference(mentor_kyc):
    with patch("core.private_docs.cloudinary.utils.private_download_url", return_value="https://signed/x"):
        data = MentorKYCAdminSerializer(mentor_kyc).data
    assert data["government_id"] == "https://signed/x"
    assert "cld-private:" not in str(data)


def test_client_cannot_write_document_fields(mentor_kyc):
    """Writing another user's private reference must be impossible."""
    stolen = private_docs.make_reference("image", "jpg", "ids/someone-else")
    s = MentorKYCSerializer(
        mentor_kyc,
        data={"government_id": stolen, "recommendation_letter": stolen, "cv": stolen},
        partial=True,
    )
    assert s.is_valid(), s.errors
    s.save()
    mentor_kyc.refresh_from_db()
    assert "someone-else" not in str(mentor_kyc.government_id)
    assert "someone-else" not in str(mentor_kyc.recommendation_letter or "")
    assert "someone-else" not in str(mentor_kyc.cv or "")


# ── migration command ───────────────────────────────────────────────────

@pytest.mark.django_db
def test_privatize_command_converts_legacy_public_urls():
    user = User.objects.create_user(email="legacy@test.local", password="x", role="eagle")
    kyc = MentorKYC.objects.create(user=user)
    MentorKYC.objects.filter(pk=kyc.pk).update(government_id=PUBLIC_ID_URL, cv=RAW_URL)

    with patch("core.private_docs.cloudinary.uploader.rename") as rename:
        call_command("privatize_kyc_documents", "--dry-run")
        rename.assert_not_called()
        call_command("privatize_kyc_documents")
        call_command("privatize_kyc_documents")  # idempotent

    assert rename.call_count == 2
    for call in rename.call_args_list:
        assert call.kwargs["to_type"] == "authenticated"
        assert call.kwargs["invalidate"] is True
    kyc.refresh_from_db()
    assert private_docs.is_private_reference(str(kyc.government_id))
    assert private_docs.is_private_reference(kyc.cv)


# ── direct-upload signing ───────────────────────────────────────────────

@pytest.fixture
def authed(db):
    client = APIClient()
    client.force_authenticate(User.objects.create_user(email="signer@test.local", password="x", role="eagle"))
    return client


@pytest.mark.parametrize("context", ["government_id", "cv", "recommendation_letter"])
def test_sign_endpoint_refuses_identity_document_contexts(authed, context):
    r = authed.post("/api/v1/uploads/sign/", {"context": context}, format="json")
    assert r.status_code == 400


def test_sign_endpoint_signs_allowed_formats(authed):
    r = authed.post("/api/v1/uploads/sign/", {"context": "content_thumbnail"}, format="json")
    assert r.status_code == 200
    signed = r.data["data"]["signed_params"]
    assert signed["allowed_formats"] == allowed_formats_for(UPLOAD_CONTEXTS["content_thumbnail"]["allowed_mime"])
    assert "pdf" not in signed["allowed_formats"]


def test_every_upload_context_has_a_format_mapping():
    for rules in UPLOAD_CONTEXTS.values():
        assert allowed_formats_for(rules["allowed_mime"])
