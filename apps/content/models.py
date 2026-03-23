"""
Content Models

Learning content system: modules (courses), content items (videos, docs,
readings), assignments, progress tracking, and submissions.
"""

import uuid

from django.conf import settings
from django.db import models

from core.mixins import TimestampMixin, SoftDeleteMixin


# ---------------------------------------------------------------------------
# Content Module — a course / learning path
# ---------------------------------------------------------------------------

class ContentModule(SoftDeleteMixin, TimestampMixin, models.Model):
    """
    A learning module (course) created by an Eagle within a Nest.
    Contains multiple ContentItems and Assignments.
    """

    class Difficulty(models.TextChoices):
        BEGINNER = "beginner", "Beginner"
        INTERMEDIATE = "intermediate", "Intermediate"
        ADVANCED = "advanced", "Advanced"

    class Visibility(models.TextChoices):
        ALL_MENTEES = "all_mentees", "All Mentees"
        NEST_ONLY = "nest_only", "Nest Only"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    nest = models.ForeignKey(
        "nests.Nest",
        on_delete=models.CASCADE,
        related_name="modules",
        null=True,
        blank=True,
        help_text="If null, this is a global module visible to everyone.",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="created_modules",
        limit_choices_to=models.Q(role="eagle") | models.Q(role="admin"),
    )
    thumbnail_url = models.URLField(max_length=500, blank=True, null=True)
    order = models.PositiveIntegerField(default=0)
    is_published = models.BooleanField(default=False)
    difficulty = models.CharField(
        max_length=15,
        choices=Difficulty.choices,
        default=Difficulty.BEGINNER,
    )
    points_value = models.PositiveIntegerField(
        default=0,
        help_text="Bonus points awarded on module completion.",
    )
    visibility = models.CharField(
        max_length=15,
        choices=Visibility.choices,
        default=Visibility.NEST_ONLY,
        help_text="all_mentees: appears in Resource Center. nest_only: appears in Assignments/Learning Modules.",
    )

    class Meta:
        db_table = "content_modules"
        ordering = ["order", "created_at"]
        indexes = [
            models.Index(fields=["nest", "is_published"]),
            models.Index(fields=["created_by"]),
        ]

    def __str__(self) -> str:
        return self.title

    @property
    def item_count(self) -> int:
        return self.items.count()

    @property
    def total_duration_minutes(self) -> int:
        return self.items.aggregate(
            total=models.Sum("duration_minutes")
        )["total"] or 0

    @property
    def primary_type(self) -> str:
        """Infers the content type based on the first item."""
        first_item = self.items.first()
        return first_item.content_type if first_item else "document"


# ---------------------------------------------------------------------------
# Content Item — a single piece of content
# ---------------------------------------------------------------------------

class ContentItem(TimestampMixin, models.Model):
    """Single piece of learning content within a module."""

    class ContentType(models.TextChoices):
        VIDEO = "video", "Video"
        DOCUMENT = "document", "Document"
        READING = "reading", "Reading"
        QUIZ = "quiz", "Quiz"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    module = models.ForeignKey(
        ContentModule, on_delete=models.CASCADE, related_name="items"
    )
    title = models.CharField(max_length=200)
    content_type = models.CharField(
        max_length=15,
        choices=ContentType.choices,
        default=ContentType.READING,
    )
    file_url = models.URLField(max_length=500, blank=True)
    thumbnail_url = models.URLField(max_length=500, blank=True)
    duration_minutes = models.PositiveIntegerField(
        default=0, help_text="Duration in minutes (for videos)."
    )
    file_size = models.PositiveIntegerField(
        default=0, help_text="File size in bytes."
    )
    order = models.PositiveIntegerField(default=0)
    points_value = models.PositiveIntegerField(
        default=0,
        help_text="Points earned on completing this item.",
    )
    is_required = models.BooleanField(
        default=True,
        help_text="Required for module completion.",
    )

    class Meta:
        db_table = "content_items"
        ordering = ["order", "created_at"]
        indexes = [
            models.Index(fields=["module", "order"]),
        ]

    def __str__(self) -> str:
        return f"{self.title} ({self.content_type})"


# ---------------------------------------------------------------------------
# Assignment
# ---------------------------------------------------------------------------

class Assignment(TimestampMixin, models.Model):
    """A standalone nest-wide assignment that eaglets must submit."""

    class AssignmentType(models.TextChoices):
        STANDALONE = "standalone", "Standalone"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    assignment_type = models.CharField(
        max_length=15,
        choices=AssignmentType.choices,
        default=AssignmentType.STANDALONE,
    )
    module = models.ForeignKey(
        ContentModule,
        on_delete=models.SET_NULL,
        related_name="assignments",
        null=True,
        blank=True,
    )
    nest = models.ForeignKey(
        "nests.Nest",
        on_delete=models.SET_NULL,
        related_name="standalone_assignments",
        null=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_assignments",
    )
    title = models.CharField(max_length=200)
    description = models.TextField()
    due_date = models.DateTimeField(null=True, blank=True)
    points_value = models.PositiveIntegerField(default=0)
    max_submissions = models.PositiveIntegerField(default=1)
    file_url = models.URLField(max_length=1000, blank=True, default="")
    allowed_file_types = models.JSONField(
        default=list,
        help_text='E.g. ["pdf", "docx", "pptx"]',
    )

    class Meta:
        db_table = "assignments"
        ordering = ["created_at"]

    def __str__(self) -> str:
        return self.title


# ---------------------------------------------------------------------------
# Progress Tracking
# ---------------------------------------------------------------------------

class ContentProgress(TimestampMixin, models.Model):
    """Tracks a user's progress on a single content item."""

    class Status(models.TextChoices):
        NOT_STARTED = "not_started", "Not Started"
        IN_PROGRESS = "in_progress", "In Progress"
        COMPLETED = "completed", "Completed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="content_progress",
        db_index=True,
    )
    content_item = models.ForeignKey(
        ContentItem, on_delete=models.CASCADE, related_name="progress_records"
    )
    status = models.CharField(
        max_length=15,
        choices=Status.choices,
        default=Status.NOT_STARTED,
    )
    progress_percentage = models.FloatField(default=0.0)
    watch_duration_seconds = models.PositiveIntegerField(
        default=0, help_text="Video watch time in seconds."
    )
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    last_accessed_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "content_progress"
        constraints = [
            models.UniqueConstraint(
                fields=["user", "content_item"],
                name="unique_user_content_progress",
            ),
        ]
        indexes = [
            models.Index(fields=["user", "status"]),
            models.Index(fields=["content_item"]),
        ]

    def __str__(self) -> str:
        return f"{self.user} — {self.content_item.title}: {self.progress_percentage}%"


# ---------------------------------------------------------------------------
# Assignment Submission
# ---------------------------------------------------------------------------

class AssignmentSubmission(TimestampMixin, models.Model):
    """An eaglet's submission for an assignment."""

    class Status(models.TextChoices):
        SUBMITTED = "submitted", "Submitted"
        GRADED = "graded", "Graded"
        RETURNED = "returned", "Returned for Revision"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    assignment = models.ForeignKey(
        Assignment, on_delete=models.CASCADE, related_name="submissions"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="assignment_submissions",
    )
    file_url = models.URLField(max_length=500)
    notes = models.TextField(blank=True)
    status = models.CharField(
        max_length=15,
        choices=Status.choices,
        default=Status.SUBMITTED,
    )
    grade = models.CharField(max_length=20, blank=True)
    feedback = models.TextField(blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)
    graded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="graded_submissions",
    )

    class Meta:
        db_table = "assignment_submissions"
        ordering = ["-submitted_at"]
        indexes = [
            models.Index(fields=["assignment", "user"]),
            models.Index(fields=["user", "status"]),
        ]

    def __str__(self) -> str:
        return f"{self.user} — {self.assignment.title} [{self.status}]"


# ---------------------------------------------------------------------------
# Module Quiz (MCQ + descriptive questions attached to a ContentModule)
# ---------------------------------------------------------------------------

class ModuleAssignment(TimestampMixin, models.Model):
    """A quiz attached to a ContentModule. Eagles build it; Eaglets take it."""

    module = models.OneToOneField(
        ContentModule, on_delete=models.CASCADE, related_name="quiz"
    )
    title = models.CharField(max_length=200)
    pass_score = models.IntegerField(default=60, help_text="Minimum MCQ % to pass.")
    max_attempts = models.IntegerField(default=3)
    points_value = models.IntegerField(default=50)

    class Meta:
        db_table = "module_assignments"

    def __str__(self) -> str:
        return f"Quiz: {self.title} ({self.module.title})"


class ModuleQuestion(models.Model):
    """A single question in a ModuleAssignment."""

    class QuestionType(models.TextChoices):
        MCQ = "mcq", "Multiple Choice"
        DESCRIPTIVE = "descriptive", "Descriptive"

    assignment = models.ForeignKey(
        ModuleAssignment, on_delete=models.CASCADE, related_name="questions"
    )
    question_type = models.CharField(
        max_length=15, choices=QuestionType.choices
    )
    question_text = models.TextField()
    options = models.JSONField(
        null=True, blank=True,
        help_text='["opt A", "opt B", "opt C", "opt D"] for MCQ',
    )
    correct_option = models.IntegerField(
        null=True, blank=True,
        help_text="0-3 index of the correct option (MCQ only).",
    )
    order = models.IntegerField(default=0)

    class Meta:
        db_table = "module_questions"
        ordering = ["order"]

    def __str__(self) -> str:
        return f"Q{self.order + 1}: {self.question_text[:60]}"


class ModuleAssignmentAttempt(TimestampMixin, models.Model):
    """Records an Eaglet's attempt at a ModuleAssignment."""

    assignment = models.ForeignKey(
        ModuleAssignment, on_delete=models.CASCADE, related_name="attempts"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="module_attempts",
    )
    answers = models.JSONField(
        help_text='{"<question_id>": answer_index_or_text}'
    )
    score = models.IntegerField(
        null=True, blank=True,
        help_text="MCQ percentage score (0-100). Null if no MCQ questions.",
    )
    passed = models.BooleanField(default=False)
    attempt_number = models.IntegerField()
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "module_assignment_attempts"
        unique_together = ("assignment", "user", "attempt_number")
        ordering = ["-attempt_number"]

    def __str__(self) -> str:
        return f"{self.user} — {self.assignment.title} attempt #{self.attempt_number}"
