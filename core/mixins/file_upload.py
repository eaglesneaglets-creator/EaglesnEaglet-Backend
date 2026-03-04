"""
File Upload Mixin

Reusable validation logic for file upload views. Provides centralized
file size, extension, and content-type validation to avoid duplicate
code across upload endpoints.
"""

import logging

from rest_framework.exceptions import ValidationError

logger = logging.getLogger(__name__)


class FileUploadMixin:
    """
    Mixin for file upload views with production-grade validation.

    Subclasses should define:
        upload_field_name (str): The form field name for the file (default: 'file')
        max_file_size (int): Maximum allowed file size in bytes (default: 5MB)
        allowed_extensions (tuple): Tuple of lowercase allowed file extensions
        allowed_content_types (tuple): Optional tuple of allowed MIME types

    Usage:
        class UploadCVView(FileUploadMixin, APIView):
            upload_field_name = 'file'
            max_file_size = 5 * 1024 * 1024
            allowed_extensions = ('pdf', 'docx')
    """

    upload_field_name = 'file'
    max_file_size = 5 * 1024 * 1024  # 5MB default
    allowed_extensions = ()
    allowed_content_types = ()

    def validate_uploaded_file(self, request):
        """
        Validate and return the uploaded file from the request.

        Raises:
            ValidationError: If the file is missing, too large, or has
                a disallowed extension/content type.

        Returns:
            UploadedFile: The validated Django uploaded file object.
        """
        uploaded_file = request.FILES.get(self.upload_field_name)

        if not uploaded_file:
            raise ValidationError({
                self.upload_field_name: f'No file provided in the "{self.upload_field_name}" field.'
            })

        # Validate file size
        if uploaded_file.size > self.max_file_size:
            max_mb = self.max_file_size / (1024 * 1024)
            raise ValidationError({
                self.upload_field_name: (
                    f'File size ({uploaded_file.size / (1024 * 1024):.1f}MB) '
                    f'exceeds the maximum allowed size of {max_mb:.0f}MB.'
                )
            })

        # Validate extension
        if self.allowed_extensions:
            ext = ''
            if '.' in uploaded_file.name:
                ext = uploaded_file.name.rsplit('.', 1)[-1].lower()

            if ext not in self.allowed_extensions:
                allowed = ', '.join(f'.{e}' for e in self.allowed_extensions)
                raise ValidationError({
                    self.upload_field_name: f'File type ".{ext}" is not allowed. Accepted types: {allowed}'
                })

        # Validate content type (if configured)
        if self.allowed_content_types:
            if uploaded_file.content_type not in self.allowed_content_types:
                raise ValidationError({
                    self.upload_field_name: f'Content type "{uploaded_file.content_type}" is not allowed.'
                })

        logger.debug(
            "File upload validated: name=%s, size=%d, type=%s",
            uploaded_file.name, uploaded_file.size, uploaded_file.content_type,
        )

        return uploaded_file
