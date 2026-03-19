"""
Soft Delete Mixin

Provides soft-delete functionality so records are flagged as deleted
rather than permanently removed.  A custom manager excludes soft-deleted
rows by default while still allowing explicit access when needed.
"""

from django.db import models
from django.utils import timezone


class SoftDeleteManager(models.Manager):
    """Default manager that excludes soft-deleted records."""

    def get_queryset(self):
        return super().get_queryset().filter(deleted_at__isnull=True)


class AllObjectsManager(models.Manager):
    """Manager that includes soft-deleted records."""

    pass


class SoftDeleteMixin(models.Model):
    """
    Abstract model mixin for soft-delete support.

    Usage::

        class MyModel(SoftDeleteMixin, TimestampMixin, models.Model):
            name = models.CharField(max_length=100)

        # Soft-delete
        obj.soft_delete()

        # Restore
        obj.restore()

        # Default queries exclude deleted
        MyModel.objects.all()          # only non-deleted

        # Include deleted
        MyModel.all_objects.all()      # everything
    """

    deleted_at = models.DateTimeField(null=True, blank=True, db_index=True)

    objects = SoftDeleteManager()
    all_objects = AllObjectsManager()

    class Meta:
        abstract = True

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None

    def soft_delete(self):
        """Mark the record as deleted without removing it from the database."""
        self.deleted_at = timezone.now()
        self.save(update_fields=["deleted_at"])

    def restore(self):
        """Restore a soft-deleted record."""
        self.deleted_at = None
        self.save(update_fields=["deleted_at"])
