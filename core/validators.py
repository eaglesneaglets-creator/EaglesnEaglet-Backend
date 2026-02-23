"""
Custom Validators

Input validation utilities for security and data integrity.
"""

import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class PasswordStrengthValidator:
    """
    Validates password strength beyond Django's default validators.
    Requires:
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """

    def __init__(self, min_length=10):
        self.min_length = min_length

    def validate(self, password, user=None):
        if len(password) < self.min_length:
            raise ValidationError(
                _('Password must be at least %(min_length)d characters.'),
                code='password_too_short',
                params={'min_length': self.min_length},
            )

        if not re.search(r'[A-Z]', password):
            raise ValidationError(
                _('Password must contain at least one uppercase letter.'),
                code='password_no_upper',
            )

        if not re.search(r'[a-z]', password):
            raise ValidationError(
                _('Password must contain at least one lowercase letter.'),
                code='password_no_lower',
            )

        if not re.search(r'\d', password):
            raise ValidationError(
                _('Password must contain at least one digit.'),
                code='password_no_digit',
            )

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError(
                _('Password must contain at least one special character (!@#$%^&*(),.?":{}|<>).'),
                code='password_no_special',
            )

    def get_help_text(self):
        return _(
            'Your password must contain at least %(min_length)d characters, '
            'including uppercase, lowercase, digits, and special characters.'
        ) % {'min_length': self.min_length}


def validate_phone_number(value):
    """
    Validates Nigerian phone numbers.
    Accepts formats: +234XXXXXXXXXX, 234XXXXXXXXXX, 0XXXXXXXXXX
    """
    # Remove spaces and dashes
    cleaned = re.sub(r'[\s\-]', '', value)

    # Nigerian phone number patterns
    patterns = [
        r'^\+234[789][01]\d{8}$',  # +234 format
        r'^234[789][01]\d{8}$',    # 234 format
        r'^0[789][01]\d{8}$',       # 0 format
    ]

    if not any(re.match(pattern, cleaned) for pattern in patterns):
        raise ValidationError(
            _('Enter a valid Nigerian phone number.'),
            code='invalid_phone',
        )


def validate_no_html(value):
    """
    Validates that a string doesn't contain HTML tags.
    Prevents XSS in user input.
    """
    if re.search(r'<[^>]+>', value):
        raise ValidationError(
            _('HTML tags are not allowed.'),
            code='no_html',
        )


def validate_safe_filename(value):
    """
    Validates that a filename is safe.
    Prevents path traversal attacks.
    """
    # Check for path traversal
    if '..' in value or '/' in value or '\\' in value:
        raise ValidationError(
            _('Invalid filename.'),
            code='invalid_filename',
        )

    # Check for dangerous extensions
    dangerous_extensions = ['.exe', '.bat', '.cmd', '.sh', '.php', '.py', '.js']
    if any(value.lower().endswith(ext) for ext in dangerous_extensions):
        raise ValidationError(
            _('This file type is not allowed.'),
            code='dangerous_extension',
        )


def sanitize_input(value):
    """
    Sanitizes user input by removing potentially dangerous characters.
    Use this for display purposes, not storage.
    """
    if not isinstance(value, str):
        return value

    # Remove null bytes
    value = value.replace('\x00', '')

    # Remove control characters except newlines and tabs
    value = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)

    return value.strip()
