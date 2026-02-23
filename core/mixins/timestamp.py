"""
Timestamp Mixin
Provides created_at and updated_at fields for models
"""

from django.db import models


class TimestampMixin(models.Model):
    """
    Abstract model mixin that provides self-updating
    created_at and updated_at fields.
    """

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
