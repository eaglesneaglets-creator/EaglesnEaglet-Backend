"""
User App Validators

Custom validators for KYC file uploads and format validation.
"""

import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _
from .constants import (
    ALLOWED_CV_EXTENSIONS,
    ALLOWED_IMAGE_EXTENSIONS,
    MAX_CV_SIZE_MB,
    MAX_IMAGE_SIZE_MB,
    MIN_PROFILE_DESCRIPTION_LENGTH,
    MIN_BIO_LENGTH,
)


def validate_cv_file(file):
    """
    Validate CV upload: PDF/DOCX only, max 5MB.
    """
    if not file:
        return

    # Check file extension
    ext = file.name.split('.')[-1].lower()
    if ext not in ALLOWED_CV_EXTENSIONS:
        raise ValidationError(
            _('Only PDF and DOCX files are allowed. You uploaded a .%(ext)s file.'),
            code='invalid_cv_extension',
            params={'ext': ext},
        )

    # Check file size
    max_size_bytes = MAX_CV_SIZE_MB * 1024 * 1024
    if file.size > max_size_bytes:
        raise ValidationError(
            _('CV file size must be under %(max_size)d MB. Your file is %(file_size).2f MB.'),
            code='cv_too_large',
            params={
                'max_size': MAX_CV_SIZE_MB,
                'file_size': file.size / (1024 * 1024),
            },
        )


def validate_image_file(file):
    """
    Validate image upload: JPG/PNG/WEBP only, max 2MB.
    """
    if not file:
        return

    # Check file extension
    ext = file.name.split('.')[-1].lower()
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValidationError(
            _('Only JPG, PNG, and WEBP images are allowed. You uploaded a .%(ext)s file.'),
            code='invalid_image_extension',
            params={'ext': ext},
        )

    # Check file size
    max_size_bytes = MAX_IMAGE_SIZE_MB * 1024 * 1024
    if file.size > max_size_bytes:
        raise ValidationError(
            _('Image size must be under %(max_size)d MB. Your file is %(file_size).2f MB.'),
            code='image_too_large',
            params={
                'max_size': MAX_IMAGE_SIZE_MB,
                'file_size': file.size / (1024 * 1024),
            },
        )


def validate_linkedin_url(url):
    """
    Validate LinkedIn profile URL format.
    Accepts: https://linkedin.com/in/username or https://www.linkedin.com/in/username
    """
    if not url:
        return  # Optional field

    pattern = r'^https?://(www\.)?linkedin\.com/in/[\w-]+/?$'
    if not re.match(pattern, url, re.IGNORECASE):
        raise ValidationError(
            _('Please enter a valid LinkedIn profile URL (e.g., https://linkedin.com/in/yourname).'),
            code='invalid_linkedin_url',
        )


def validate_ghana_phone(phone):
    """
    Validate Ghana phone number format.
    Accepts: +233 XX XXX XXXX or 0XX XXX XXXX
    """
    if not phone:
        return

    # Remove spaces, dashes, and other common separators
    cleaned = re.sub(r'[\s\-\.\(\)]', '', phone)

    # Ghana phone pattern: +233XXXXXXXXX or 0XXXXXXXXX
    pattern = r'^(\+233|0)[2-9][0-9]{8}$'
    if not re.match(pattern, cleaned):
        raise ValidationError(
            _('Please enter a valid Ghana phone number (e.g., +233 XX XXX XXXX or 0XX XXX XXXX).'),
            code='invalid_ghana_phone',
        )


def validate_national_id(value):
    """
    Validate national ID number format.
    Basic validation - can be customized based on specific country requirements.
    """
    if not value:
        raise ValidationError(
            _('National ID number is required.'),
            code='national_id_required',
        )

    # Remove spaces and convert to uppercase
    cleaned = value.strip().upper()

    # Basic length check (most national IDs are 6-20 characters)
    if len(cleaned) < 6 or len(cleaned) > 20:
        raise ValidationError(
            _('National ID must be between 6 and 20 characters.'),
            code='invalid_national_id_length',
        )

    # Check for alphanumeric characters only
    if not re.match(r'^[A-Z0-9-]+$', cleaned):
        raise ValidationError(
            _('National ID can only contain letters, numbers, and hyphens.'),
            code='invalid_national_id_format',
        )


def validate_profile_description(value):
    """
    Validate mentor profile description meets minimum length.
    """
    if not value:
        raise ValidationError(
            _('Profile description is required.'),
            code='profile_description_required',
        )

    if len(value.strip()) < MIN_PROFILE_DESCRIPTION_LENGTH:
        raise ValidationError(
            _('Profile description must be at least %(min_length)d characters. You have %(current)d characters.'),
            code='profile_description_too_short',
            params={
                'min_length': MIN_PROFILE_DESCRIPTION_LENGTH,
                'current': len(value.strip()),
            },
        )


def validate_bio(value):
    """
    Validate mentee bio meets minimum length.
    """
    if not value:
        raise ValidationError(
            _('Bio is required.'),
            code='bio_required',
        )

    if len(value.strip()) < MIN_BIO_LENGTH:
        raise ValidationError(
            _('Bio must be at least %(min_length)d characters. You have %(current)d characters.'),
            code='bio_too_short',
            params={
                'min_length': MIN_BIO_LENGTH,
                'current': len(value.strip()),
            },
        )
