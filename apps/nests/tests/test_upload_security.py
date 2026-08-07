from unittest.mock import patch

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.test import APIClient

from apps.users.models import User


@pytest.fixture
def authenticated_client(db):
    user = User.objects.create_user(
        email="uploader@test.local", password="password", role="eagle"
    )
    client = APIClient()
    client.force_authenticate(user=user)
    return client


@pytest.mark.django_db
@patch("core.storage.upload_to_cloudinary")
def test_nest_upload_accepts_allowlisted_content(mock_upload, authenticated_client):
    mock_upload.return_value = {
        "secure_url": "https://example.test/media.gif",
        "resource_type": "image",
    }
    upload = SimpleUploadedFile(
        "media.gif", b"GIF89a" + b"\x00" * 20, content_type="image/gif"
    )

    response = authenticated_client.post(
        "/api/v1/nests/upload/", {"file": upload}, format="multipart"
    )

    assert response.status_code == 201
    mock_upload.assert_called_once()


@pytest.mark.django_db
@patch("core.storage.upload_to_cloudinary")
def test_nest_upload_rejects_spoofed_file_content(mock_upload, authenticated_client):
    upload = SimpleUploadedFile(
        "payload.png", b"<script>alert(1)</script>", content_type="image/png"
    )

    response = authenticated_client.post(
        "/api/v1/nests/upload/", {"file": upload}, format="multipart"
    )

    assert response.status_code == 400
    mock_upload.assert_not_called()
