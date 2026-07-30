"""
Profile avatar — Phase 32-01.

Locks three things that were broken or absent:
  1. An approved-KYC user CAN change their profile picture (the old KYC endpoint
     hard-blocked them, so onboarded users were stuck with their verification photo).
  2. `User.avatar_url` is the SINGLE fallback implementation, and it falls back to the
     KYC photo so nobody loses their picture at rollout.
  3. `avatar_url` is actually present in the payloads the UI reads — chat's
     UserMinimalSerializer sent no avatar at all, which is why chat showed initials.
"""

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework_simplejwt.tokens import RefreshToken

from apps.users.models import MentorKYC

pytestmark = pytest.mark.django_db

AVATAR_URL = "/api/v1/auth/me/avatar/"
ME_URL = "/api/v1/auth/me/"
KYC_PICTURE_URL = "/api/v1/auth/upload/picture/"


def _auth(api_client, user):
    token = RefreshToken.for_user(user)
    api_client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.access_token}")
    return api_client


def _png(name="pic.png", size_kb=10):
    """Minimal valid-enough PNG payload for validator + upload paths."""
    header = b"\x89PNG\r\n\x1a\n"
    return SimpleUploadedFile(name, header + b"0" * (size_kb * 1024), content_type="image/png")


@pytest.fixture
def mentor(user_factory):
    return user_factory(email="avatar_mentor@test.com", role="eagle",
                        first_name="Ama", last_name="Mentor")


@pytest.fixture
def approved_mentor(mentor):
    """A mentor whose KYC is approved — previously LOCKED OUT of picture changes."""
    MentorKYC.objects.create(
        user=mentor, status="approved",
        display_picture="https://cdn.example.com/kyc-verification-photo.jpg",
    )
    mentor.refresh_from_db()
    return mentor


# ---------------------------------------------------------------------------
# AC-3: fallback chain (pure model logic — no HTTP)
# ---------------------------------------------------------------------------

def test_fallback_returns_none_when_nothing_set(user_factory):
    u = user_factory(email="empty@test.com", role="eaglet")
    # None, not '' — the frontend branches on falsiness to render initials.
    assert u.avatar_url is None


def test_fallback_uses_sso_picture(user_factory):
    u = user_factory(email="sso@test.com", role="eaglet",
                     profile_picture_url="https://sso.example/pic.jpg")
    assert u.avatar_url == "https://sso.example/pic.jpg"


def test_fallback_uses_kyc_photo_when_nothing_else_set(approved_mentor):
    """The rollout-critical rung: an approved user keeps their existing photo."""
    assert approved_mentor.avatar_url == "https://cdn.example.com/kyc-verification-photo.jpg"


def test_fallback_prefers_uploaded_over_kyc(approved_mentor):
    approved_mentor.profile_picture_url = "https://cdn.example.com/my-avatar.jpg"
    approved_mentor.save(update_fields=["profile_picture_url"])
    assert approved_mentor.avatar_url == "https://cdn.example.com/my-avatar.jpg"


def test_fallback_is_the_only_implementation():
    """Guard against a second copy of the chain reappearing in serializers.

    Checks executable lines only — the docstring legitimately *mentions* the old
    field names while explaining the refactor.
    """
    import inspect
    from apps.nests.serializers import UserMinimalSerializer as NestsUserSerializer

    src = inspect.getsource(NestsUserSerializer.get_avatar_url)

    # Drop the docstring block and comments, keeping executable lines only.
    code_lines, in_doc = [], False
    for line in src.splitlines():
        stripped = line.strip()
        if stripped.startswith(('"""', "'''")):
            # Handles both the opening and closing fence; a one-line docstring
            # opens and closes on the same line.
            if not (in_doc is False and stripped.count('"""') == 2):
                in_doc = not in_doc
            continue
        if in_doc or stripped.startswith('#'):
            continue
        code_lines.append(line)
    code = "\n".join(code_lines)

    assert "obj.avatar_url" in code, "nests serializer must delegate to the property"
    assert "profile_picture_url" not in code, "fallback chain re-derived — keep one impl"


# ---------------------------------------------------------------------------
# AC-1 / AC-2 / AC-4: upload, delete, validation
# ---------------------------------------------------------------------------

def test_approved_kyc_user_can_upload_avatar(api_client, approved_mentor, monkeypatch):
    """THE headline fix: approval must not block a profile-picture change."""
    monkeypatch.setattr(
        "core.storage.upload_to_cloudinary",
        lambda f, t, **k: {"secure_url": "https://cdn.example.com/new-avatar.jpg",
                           "public_id": "abc123"},
    )
    resp = _auth(api_client, approved_mentor).post(
        AVATAR_URL, {"avatar": _png()}, format="multipart"
    )
    assert resp.status_code == 200, resp.data
    assert resp.json()["data"]["avatar_url"] == "https://cdn.example.com/new-avatar.jpg"

    approved_mentor.refresh_from_db()
    assert approved_mentor.avatar_url == "https://cdn.example.com/new-avatar.jpg"


def test_upload_does_not_touch_the_kyc_record(api_client, approved_mentor, monkeypatch):
    """KYC display_picture is a verification artifact — must stay immutable."""
    monkeypatch.setattr(
        "core.storage.upload_to_cloudinary",
        lambda f, t, **k: {"secure_url": "https://cdn.example.com/new.jpg", "public_id": "x"},
    )
    _auth(api_client, approved_mentor).post(AVATAR_URL, {"avatar": _png()}, format="multipart")

    kyc = MentorKYC.objects.get(user=approved_mentor)
    assert kyc.display_picture == "https://cdn.example.com/kyc-verification-photo.jpg"
    assert kyc.status == "approved"


def test_delete_falls_back_to_kyc_photo(api_client, approved_mentor):
    """Removing your upload shouldn't erase a photo you never uploaded here."""
    approved_mentor.profile_picture_url = "https://cdn.example.com/my-avatar.jpg"
    approved_mentor.save(update_fields=["profile_picture_url"])

    resp = _auth(api_client, approved_mentor).delete(AVATAR_URL)
    assert resp.status_code == 200
    assert resp.json()["data"]["avatar_url"] == "https://cdn.example.com/kyc-verification-photo.jpg"


def test_upload_rejects_missing_file(api_client, mentor):
    resp = _auth(api_client, mentor).post(AVATAR_URL, {}, format="multipart")
    assert resp.status_code == 400
    assert "no file" in resp.json()["error"]["message"].lower()


def test_upload_rejects_non_image(api_client, mentor):
    bad = SimpleUploadedFile("resume.pdf", b"%PDF-1.4 fake", content_type="application/pdf")
    resp = _auth(api_client, mentor).post(AVATAR_URL, {"avatar": bad}, format="multipart")
    assert resp.status_code == 400
    mentor.refresh_from_db()
    assert mentor.avatar_url is None


def test_upload_rejects_oversized_image(api_client, mentor):
    # Well past the project's image size cap enforced by validate_image_file.
    resp = _auth(api_client, mentor).post(
        AVATAR_URL, {"avatar": _png(size_kb=6000)}, format="multipart"
    )
    assert resp.status_code == 400
    mentor.refresh_from_db()
    assert mentor.avatar_url is None


def test_avatar_endpoint_requires_auth(api_client):
    assert api_client.post(AVATAR_URL, {}, format="multipart").status_code == 401


# ---------------------------------------------------------------------------
# AC-5: avatar_url exposed consistently
# ---------------------------------------------------------------------------

def test_me_payload_includes_avatar_url(api_client, approved_mentor):
    resp = _auth(api_client, approved_mentor).get(ME_URL)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["avatar_url"] == "https://cdn.example.com/kyc-verification-photo.jpg"


def test_chat_user_serializer_includes_avatar_url(approved_mentor):
    """Chat previously sent NO avatar — this is why it rendered initials."""
    from apps.chat.serializers import UserMinimalSerializer
    data = UserMinimalSerializer(approved_mentor).data
    assert "avatar_url" in data
    assert data["avatar_url"] == "https://cdn.example.com/kyc-verification-photo.jpg"


def test_nests_user_serializer_still_exposes_avatar_url(approved_mentor):
    """Phase 28 mentor cards depend on this field name — must not change."""
    from apps.nests.serializers import UserMinimalSerializer
    data = UserMinimalSerializer(approved_mentor).data
    assert data["avatar_url"] == "https://cdn.example.com/kyc-verification-photo.jpg"


# ---------------------------------------------------------------------------
# AC-6: KYC immutability preserved
# ---------------------------------------------------------------------------

def test_kyc_picture_endpoint_still_blocks_approved_profiles(api_client, approved_mentor):
    """The old endpoint's approval lock is intentional and must NOT be weakened."""
    resp = _auth(api_client, approved_mentor).post(
        KYC_PICTURE_URL, {"file": _png()}, format="multipart"
    )
    assert resp.status_code == 400
    assert "approved" in resp.json()["error"]["message"].lower()
