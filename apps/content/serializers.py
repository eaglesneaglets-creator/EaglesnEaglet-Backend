"""
Content Serializers

Read and write serializers for Content modules, items, assignments,
progress, and submissions.
"""

from rest_framework import serializers

from apps.nests.serializers import UserMinimalSerializer

from .models import (
    ContentModule,
    ContentItem,
    Assignment,
    ContentProgress,
    AssignmentSubmission,
    ModuleAssignment,
    ModuleQuestion,
    ModuleAssignmentAttempt,
)


# ---------------------------------------------------------------------------
# Content Module
# ---------------------------------------------------------------------------

class ContentItemSerializer(serializers.ModelSerializer):
    """Read-only content item representation."""

    class Meta:
        model = ContentItem
        fields = [
            "id", "title", "content_type", "file_url", "thumbnail_url",
            "duration_minutes", "file_size", "order", "points_value",
            "is_required", "created_at",
        ]
        read_only_fields = fields


class ContentModuleListSerializer(serializers.ModelSerializer):
    """Compact module for lists."""

    created_by_name = serializers.CharField(
        source="created_by.full_name", read_only=True
    )
    progress = serializers.FloatField(read_only=True, default=0.0)
    status = serializers.CharField(read_only=True, default="not_started")
    has_quiz = serializers.SerializerMethodField()
    resource_gate_cleared = serializers.SerializerMethodField()

    class Meta:
        model = ContentModule
        fields = [
            "id", "title", "description", "difficulty", "is_published",
            "order", "points_value", "item_count", "total_duration_minutes",
            "created_by_name", "created_at", "progress", "status",
            "primary_type", "thumbnail_url", "has_quiz", "resource_gate_cleared",
            "visibility",
        ]
        read_only_fields = fields

    def get_has_quiz(self, obj):
        return hasattr(obj, "quiz")

    def get_resource_gate_cleared(self, obj):
        request = self.context.get("request")
        if not request or not hasattr(request, "user"):
            return False
        from .services import ProgressService
        return ProgressService.check_resource_gate(request.user, obj)


class ContentModuleDetailSerializer(serializers.ModelSerializer):
    """Full module with items."""

    created_by = UserMinimalSerializer(read_only=True)
    items = ContentItemSerializer(many=True, read_only=True)
    item_count = serializers.IntegerField(read_only=True)
    total_duration_minutes = serializers.IntegerField(read_only=True)
    has_quiz = serializers.SerializerMethodField()

    class Meta:
        model = ContentModule
        fields = [
            "id", "title", "description", "nest", "difficulty",
            "is_published", "order", "points_value", "items",
            "item_count", "total_duration_minutes",
            "created_by", "created_at", "updated_at",
            "primary_type", "thumbnail_url", "has_quiz", "visibility",
        ]
        read_only_fields = fields

    def get_has_quiz(self, obj):
        return hasattr(obj, "quiz")


class ContentModuleCreateSerializer(serializers.Serializer):
    """Write serializer for creating / updating a module."""

    title = serializers.CharField(max_length=200)
    description = serializers.CharField(required=False, allow_blank=True)
    difficulty = serializers.ChoiceField(
        choices=ContentModule.Difficulty.choices, default="beginner"
    )
    order = serializers.IntegerField(default=0, min_value=0)
    points_value = serializers.IntegerField(default=0, min_value=0)
    is_published = serializers.BooleanField(default=False, required=False)
    visibility = serializers.ChoiceField(
        choices=ContentModule.Visibility.choices, default="nest_only", required=False
    )
    thumbnail = serializers.ImageField(required=False, allow_null=True)


# ---------------------------------------------------------------------------
# Content Item
# ---------------------------------------------------------------------------

class ContentItemCreateSerializer(serializers.Serializer):
    """Write serializer for adding a content item."""

    title = serializers.CharField(max_length=200)
    content_type = serializers.ChoiceField(
        choices=ContentItem.ContentType.choices
    )
    file = serializers.FileField(required=False)
    file_url = serializers.URLField(required=False, allow_blank=True)
    thumbnail_url = serializers.URLField(required=False, allow_blank=True)
    duration_minutes = serializers.IntegerField(default=0, min_value=0)
    file_size = serializers.IntegerField(default=0, min_value=0)
    order = serializers.IntegerField(default=0, min_value=0)
    points_value = serializers.IntegerField(default=0, min_value=0)
    is_required = serializers.BooleanField(default=True)
    thumbnail = serializers.ImageField(required=False, allow_null=True)


# ---------------------------------------------------------------------------
# Assignment
# ---------------------------------------------------------------------------

class AssignmentSerializer(serializers.ModelSerializer):
    """Read-only assignment representation."""

    nest_name = serializers.CharField(source="nest.name", read_only=True, default=None)
    my_submission_status = serializers.SerializerMethodField()

    class Meta:
        model = Assignment
        fields = [
            "id", "assignment_type", "module", "nest", "nest_name",
            "title", "description", "due_date", "file_url",
            "points_value", "max_submissions", "allowed_file_types",
            "my_submission_status", "created_at",
        ]
        read_only_fields = fields

    def get_my_submission_status(self, obj):
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return None
        submission = obj.submissions.filter(user=request.user).order_by("-submitted_at").first()
        return submission.status if submission else None


class AssignmentCreateSerializer(serializers.Serializer):
    """Write serializer for creating a standalone assignment."""

    title = serializers.CharField(max_length=200)
    description = serializers.CharField()
    nest_id = serializers.UUIDField(required=False)
    due_date = serializers.DateTimeField(required=False)
    points_value = serializers.IntegerField(default=0, min_value=0)
    max_submissions = serializers.IntegerField(default=1, min_value=1)
    allowed_file_types = serializers.ListField(
        child=serializers.CharField(), default=list
    )


# ---------------------------------------------------------------------------
# Module Quiz
# ---------------------------------------------------------------------------

class ModuleQuestionSerializer(serializers.ModelSerializer):
    """Read-only question (strips correct_option for eaglets)."""

    class Meta:
        model = ModuleQuestion
        fields = [
            "id", "question_type", "question_text", "options", "order",
        ]
        read_only_fields = fields


class ModuleQuestionWithAnswerSerializer(serializers.ModelSerializer):
    """Full question including correct_option (Eagle only)."""

    class Meta:
        model = ModuleQuestion
        fields = [
            "id", "question_type", "question_text", "options",
            "correct_option", "order",
        ]
        read_only_fields = fields


class ModuleAssignmentSerializer(serializers.ModelSerializer):
    """Read-only quiz representation for Eaglets (no answers)."""

    questions = ModuleQuestionSerializer(many=True, read_only=True)

    class Meta:
        model = ModuleAssignment
        fields = [
            "id", "title", "pass_score", "max_attempts", "points_value", "questions",
        ]
        read_only_fields = fields


class ModuleAssignmentEagleSerializer(serializers.ModelSerializer):
    """Full quiz with correct answers (Eagle view)."""

    questions = ModuleQuestionWithAnswerSerializer(many=True, read_only=True)

    class Meta:
        model = ModuleAssignment
        fields = [
            "id", "title", "pass_score", "max_attempts", "points_value", "questions",
        ]
        read_only_fields = fields


class ModuleQuestionCreateSerializer(serializers.Serializer):
    question_type = serializers.ChoiceField(choices=ModuleQuestion.QuestionType.choices)
    question_text = serializers.CharField()
    options = serializers.ListField(child=serializers.CharField(), required=False, allow_null=True)
    correct_option = serializers.IntegerField(required=False, allow_null=True, min_value=0, max_value=3)


class ModuleQuizCreateSerializer(serializers.Serializer):
    """Write serializer for Eagle creating/replacing a module quiz."""

    title = serializers.CharField(max_length=200)
    pass_score = serializers.IntegerField(default=60, min_value=1, max_value=100)
    max_attempts = serializers.IntegerField(default=3, min_value=1)
    points_value = serializers.IntegerField(default=50, min_value=0)
    questions = ModuleQuestionCreateSerializer(many=True)

    def validate_questions(self, value):
        if not value:
            raise serializers.ValidationError("At least one question is required.")
        for q in value:
            if q["question_type"] == "mcq":
                if not q.get("options") or len(q["options"]) < 2:
                    raise serializers.ValidationError("MCQ questions need at least 2 options.")
                if q.get("correct_option") is None:
                    raise serializers.ValidationError("MCQ questions must have a correct_option.")
        return value


class ModuleAssignmentAttemptSerializer(serializers.ModelSerializer):
    """Read-only attempt result."""

    class Meta:
        model = ModuleAssignmentAttempt
        fields = [
            "id", "score", "passed", "attempt_number", "answers", "completed_at",
        ]
        read_only_fields = fields


class QuizSubmitSerializer(serializers.Serializer):
    """Write serializer for an Eaglet submitting a quiz attempt."""

    answers = serializers.DictField(
        help_text='{"<question_id>": answer_index_or_text_string}'
    )


# ---------------------------------------------------------------------------
# Progress
# ---------------------------------------------------------------------------

class ContentProgressSerializer(serializers.ModelSerializer):
    """Read-only progress representation."""

    content_item = ContentItemSerializer(read_only=True)

    class Meta:
        model = ContentProgress
        fields = [
            "id", "content_item", "status", "progress_percentage",
            "watch_duration_seconds", "started_at", "completed_at",
            "last_accessed_at",
        ]
        read_only_fields = fields


class ProgressUpdateSerializer(serializers.Serializer):
    """Write serializer for updating progress."""

    progress_percentage = serializers.FloatField(min_value=0, max_value=100)
    watch_duration_seconds = serializers.IntegerField(default=0, min_value=0)


class BreakdownStatsSerializer(serializers.Serializer):
    completed = serializers.IntegerField()
    total = serializers.IntegerField()

class BreakdownSerializer(serializers.Serializer):
    videos = BreakdownStatsSerializer()
    assignments = BreakdownStatsSerializer()

class ProgressSummarySerializer(serializers.Serializer):
    """Dashboard progress summary."""

    total_items = serializers.IntegerField()
    completed = serializers.IntegerField()
    in_progress = serializers.IntegerField()
    average_progress = serializers.FloatField()
    overall_progress = serializers.FloatField()
    modules_completed = serializers.IntegerField()
    total_modules = serializers.IntegerField()
    breakdown = BreakdownSerializer()


# ---------------------------------------------------------------------------
# Assignment Submission
# ---------------------------------------------------------------------------

class AssignmentMinimalSerializer(serializers.ModelSerializer):
    nest_name = serializers.SerializerMethodField()
    assignment_type = serializers.CharField(read_only=True)

    class Meta:
        model = Assignment
        fields = ["id", "title", "nest_name", "assignment_type", "points_value"]

    def get_nest_name(self, obj):
        if obj.nest:
            return obj.nest.name
        if obj.module and obj.module.nest:
            return obj.module.nest.name
        return None


class AssignmentSubmissionSerializer(serializers.ModelSerializer):
    """Read-only submission representation."""

    user = UserMinimalSerializer(read_only=True)
    assignment = AssignmentMinimalSerializer(read_only=True)
    graded_by = UserMinimalSerializer(read_only=True)

    class Meta:
        model = AssignmentSubmission
        fields = [
            "id", "assignment", "user", "file_url", "notes",
            "status", "grade", "feedback", "submitted_at", "graded_by",
        ]
        read_only_fields = fields


class AssignmentSubmitSerializer(serializers.Serializer):
    """Write serializer for submitting an assignment."""

    file_url = serializers.URLField()
    notes = serializers.CharField(required=False, allow_blank=True)


class AssignmentGradeSerializer(serializers.Serializer):
    """Write serializer for grading a submission."""

    grade = serializers.CharField(max_length=20)
    feedback = serializers.CharField(required=False, allow_blank=True)
