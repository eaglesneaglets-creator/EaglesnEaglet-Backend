"""
Tests for ModuleQuizService.
"""

import pytest
from rest_framework.exceptions import ValidationError

from apps.content.services import ModuleQuizService
from apps.content.models import ModuleAssignmentAttempt

pytestmark = pytest.mark.django_db


class TestSubmitAttemptGradesMCQ:
    def test_correct_mcq_answer_scores_100(
        self, eaglet_user, quiz_with_mcq_question, nest_membership
    ):
        quiz, question = quiz_with_mcq_question
        # Complete all required items first (mock resource gate)
        from unittest.mock import patch
        with patch("apps.content.services.ProgressService.check_resource_gate", return_value=True):
            result = ModuleQuizService.submit_attempt(
                quiz.id, eaglet_user, {str(question.id): question.correct_option}
            )
        assert result["score"] == 100
        assert result["passed"] is True
        assert result["correct_count"] == 1
        assert result["total_mcq"] == 1

    def test_wrong_mcq_answer_fails_quiz(
        self, eaglet_user, quiz_with_mcq_question, nest_membership
    ):
        quiz, question = quiz_with_mcq_question
        wrong_answer = (question.correct_option + 1) % 4
        from unittest.mock import patch
        with patch("apps.content.services.ProgressService.check_resource_gate", return_value=True):
            result = ModuleQuizService.submit_attempt(
                quiz.id, eaglet_user, {str(question.id): wrong_answer}
            )
        assert result["score"] == 0
        assert result["passed"] is False


class TestSubmitAttemptDescriptive:
    def test_descriptive_answer_recorded_without_affecting_score(
        self, eaglet_user, quiz_with_descriptive_question, nest_membership
    ):
        quiz, question = quiz_with_descriptive_question
        from unittest.mock import patch
        with patch("apps.content.services.ProgressService.check_resource_gate", return_value=True):
            result = ModuleQuizService.submit_attempt(
                quiz.id, eaglet_user, {str(question.id): "My reflection answer"}
            )
        # No MCQ questions → score defaults to 100
        assert result["score"] == 100
        assert result["total_mcq"] == 0
        attempt = ModuleAssignmentAttempt.objects.get(
            assignment=quiz, user=eaglet_user, attempt_number=1
        )
        assert attempt.answers[str(question.id)] == "My reflection answer"


class TestMaxAttemptsEnforcement:
    def test_exceeding_max_attempts_raises_error(
        self, eaglet_user, quiz_with_mcq_question, nest_membership
    ):
        quiz, question = quiz_with_mcq_question
        quiz.max_attempts = 1
        quiz.save()
        from unittest.mock import patch
        with patch("apps.content.services.ProgressService.check_resource_gate", return_value=True):
            ModuleQuizService.submit_attempt(quiz.id, eaglet_user, {})
            with pytest.raises(ValidationError, match="Maximum 1 attempts reached"):
                ModuleQuizService.submit_attempt(quiz.id, eaglet_user, {})


class TestResourceGateBlocking:
    def test_resource_gate_blocks_attempt_when_incomplete(
        self, eaglet_user, quiz_with_mcq_question
    ):
        quiz, _ = quiz_with_mcq_question
        from unittest.mock import patch
        with patch("apps.content.services.ProgressService.check_resource_gate", return_value=False):
            with pytest.raises(ValidationError, match="50%"):
                ModuleQuizService.submit_attempt(quiz.id, eaglet_user, {})


class TestPassingAttemptTriggersModuleCompletion:
    def test_passing_triggers_check_module_completion(
        self, eaglet_user, quiz_with_mcq_question, nest_membership
    ):
        quiz, question = quiz_with_mcq_question
        from unittest.mock import patch, MagicMock
        with patch("apps.content.services.ProgressService.check_resource_gate", return_value=True), \
             patch("apps.content.services.ProgressService.check_module_completion") as mock_completion:
            ModuleQuizService.submit_attempt(
                quiz.id, eaglet_user, {str(question.id): question.correct_option}
            )
            mock_completion.assert_called_once()
