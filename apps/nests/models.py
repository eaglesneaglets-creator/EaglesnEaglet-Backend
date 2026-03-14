"""
Nest Models

Defines the Nest community system: Nests (mentor-led groups), memberships,
mentorship requests, posts, resources, and events.
"""

import uuid

from django.conf import settings
from django.db import models
from django.utils.text import slugify

from core.mixins import TimestampMixin, SoftDeleteMixin


# ---------------------------------------------------------------------------
# Nest — the mentor-led community
# ---------------------------------------------------------------------------

class Nest(SoftDeleteMixin, TimestampMixin, models.Model):
    """
    A mentor-led community where Eagles guide Eaglets through
    structured mentorship activities.
    """

    class Privacy(models.TextChoices):
        PUBLIC = "public", "Public"
        INVITATION_ONLY = "invitation_only", "Invitation Only"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=150)
    slug = models.SlugField(max_length=170, unique=True, db_index=True)
    description = models.TextField(blank=True)
    industry_focus = models.CharField(max_length=100, blank=True)
    banner_image = models.URLField(max_length=500, blank=True)
    eagle = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="owned_nests",
        limit_choices_to={"role": "eagle"},
    )
    privacy = models.CharField(
        max_length=20,
        choices=Privacy.choices,
        default=Privacy.PUBLIC,
    )
    allow_referrals = models.BooleanField(default=True)
    meeting_link = models.URLField(max_length=500, blank=True)
    max_members = models.PositiveIntegerField(default=50)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "nests"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["eagle"]),
            models.Index(fields=["privacy"]),
            models.Index(fields=["is_active"]),
        ]

    def __str__(self) -> str:
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            base = slugify(self.name)
            slug = base
            counter = 1
            while Nest.all_objects.filter(slug=slug).exclude(pk=self.pk).exists():
                slug = f"{base}-{counter}"
                counter += 1
            self.slug = slug
        super().save(*args, **kwargs)

    @property
    def member_count(self) -> int:
        return self.memberships.filter(status="active").count()

    @property
    def is_full(self) -> bool:
        return self.member_count >= self.max_members


# ---------------------------------------------------------------------------
# Membership — eaglet ↔ nest relationship
# ---------------------------------------------------------------------------

class NestMembership(TimestampMixin, models.Model):
    """Tracks an Eaglet's membership in a Nest."""

    class MemberRole(models.TextChoices):
        MEMBER = "member", "Member"
        EAGLE_SCOUT = "eagle_scout", "Eagle Scout"

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        INACTIVE = "inactive", "Inactive"
        REMOVED = "removed", "Removed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    nest = models.ForeignKey(
        Nest, on_delete=models.CASCADE, related_name="memberships"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="nest_memberships",
    )
    role = models.CharField(
        max_length=15,
        choices=MemberRole.choices,
        default=MemberRole.MEMBER,
    )
    status = models.CharField(
        max_length=10,
        choices=Status.choices,
        default=Status.ACTIVE,
    )
    joined_at = models.DateTimeField(auto_now_add=True)
    progress_percentage = models.FloatField(default=0.0)

    class Meta:
        db_table = "nest_memberships"
        constraints = [
            models.UniqueConstraint(
                fields=["nest", "user"],
                name="unique_nest_membership",
            ),
        ]
        indexes = [
            models.Index(fields=["nest", "status"]),
            models.Index(fields=["user", "status"]),
        ]

    def __str__(self) -> str:
        return f"{self.user} → {self.nest.name} ({self.status})"


# ---------------------------------------------------------------------------
# Mentorship Request — eaglet asks to join a nest
# ---------------------------------------------------------------------------

class MentorshipRequest(TimestampMixin, models.Model):
    """An Eaglet's request to join a Nest, pending Eagle approval."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    nest = models.ForeignKey(
        Nest, on_delete=models.CASCADE, related_name="requests"
    )
    eaglet = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="mentorship_requests",
        limit_choices_to={"role": "eaglet"},
    )
    status = models.CharField(
        max_length=10,
        choices=Status.choices,
        default=Status.PENDING,
    )
    message = models.TextField(
        blank=True, help_text="Introduction message from the Eaglet."
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_requests",
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "mentorship_requests"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["nest", "status"]),
            models.Index(fields=["eaglet", "status"]),
        ]

    def __str__(self) -> str:
        return f"{self.eaglet} → {self.nest.name} [{self.status}]"


# ---------------------------------------------------------------------------
# Nest Community — posts, resources, events
# ---------------------------------------------------------------------------

class NestPost(TimestampMixin, models.Model):
    """A post within a Nest community feed."""

    class PostType(models.TextChoices):
        POST = "post", "Post"
        ANNOUNCEMENT = "announcement", "Announcement"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    nest = models.ForeignKey(
        Nest, on_delete=models.CASCADE, related_name="posts"
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="nest_posts",
    )
    post_type = models.CharField(
        max_length=15,
        choices=PostType.choices,
        default=PostType.POST,
    )
    content = models.TextField()
    attachment_url = models.URLField(max_length=500, blank=True)
    attachment_type = models.CharField(max_length=10, blank=True)
    likes_count = models.PositiveIntegerField(default=0)
    comments_count = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = "nest_posts"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["nest", "-created_at"]),
            models.Index(fields=["author"]),
            models.Index(fields=["-created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.author} in {self.nest.name}: {self.content[:50]}"


class NestPostComment(TimestampMixin, models.Model):
    """A comment on a NestPost."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    post = models.ForeignKey(
        NestPost, on_delete=models.CASCADE, related_name="comments"
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="nest_comments",
    )
    content = models.TextField()
    parent = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="replies",
    )

    class Meta:
        db_table = "nest_post_comments"
        ordering = ["created_at"]

    def __str__(self) -> str:
        return f"Comment by {self.author} on {self.post_id}"


class NestPostLike(models.Model):
    """Tracks which users liked a NestPost."""

    post = models.ForeignKey(NestPost, on_delete=models.CASCADE, related_name="likes")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="nest_likes"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "nest_post_likes"
        unique_together = ("post", "user")
        # unique_together creates a composite index covering filter(post=post, user=user)

    def __str__(self) -> str:
        return f"{self.user} liked {self.post_id}"


class NestResource(TimestampMixin, models.Model):
    """A shared file/link in the Nest resource library."""

    class FileType(models.TextChoices):
        PDF = "pdf", "PDF"
        PPTX = "pptx", "PowerPoint"
        LINK = "link", "External Link"
        VIDEO = "video", "Video"
        DOCUMENT = "document", "Document"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    nest = models.ForeignKey(
        Nest, on_delete=models.CASCADE, related_name="resources"
    )
    title = models.CharField(max_length=200)
    file_url = models.URLField(max_length=500)
    file_type = models.CharField(
        max_length=15, choices=FileType.choices, default=FileType.DOCUMENT
    )
    file_size = models.PositiveIntegerField(default=0, help_text="Size in bytes")
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="uploaded_resources",
    )

    class Meta:
        db_table = "nest_resources"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["nest", "-created_at"]),
            models.Index(fields=["uploaded_by"]),
        ]

    def __str__(self) -> str:
        return f"{self.title} ({self.file_type})"


class NestEvent(TimestampMixin, models.Model):
    """A scheduled event within a Nest."""

    class EventType(models.TextChoices):
        WORKSHOP = "workshop", "Workshop"
        SESSION = "session", "Session"
        MEETING = "meeting", "Meeting"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    nest = models.ForeignKey(
        Nest, on_delete=models.CASCADE, related_name="events"
    )
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    event_date = models.DateTimeField()
    meeting_link = models.URLField(max_length=500, blank=True)
    event_type = models.CharField(
        max_length=15,
        choices=EventType.choices,
        default=EventType.SESSION,
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="created_events",
    )

    class Meta:
        db_table = "nest_events"
        ordering = ["event_date"]
        indexes = [
            models.Index(fields=["nest", "event_date"]),
            models.Index(fields=["event_date"]),
        ]

    def __str__(self) -> str:
        return f"{self.title} — {self.event_date:%b %d, %Y}"


# ---------------------------------------------------------------------------
# Event Attendance — tracks who attended a Nest event
# ---------------------------------------------------------------------------

class EventAttendance(TimestampMixin, models.Model):
    """Records an eaglet's attendance at a NestEvent."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event = models.ForeignKey(
        NestEvent, on_delete=models.CASCADE, related_name="attendances"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="event_attendances",
    )
    attended_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "event_attendances"
        constraints = [
            models.UniqueConstraint(
                fields=["event", "user"],
                name="unique_event_attendance",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.user} attended {self.event.title}"
