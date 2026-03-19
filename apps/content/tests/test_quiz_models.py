"""
Tests for ModuleAssignment, ModuleQuestion, ModuleAssignmentAttempt models.
"""

import pytest
from django.db import IntegrityError

pytestmark = pytest.mark.django_db


class TestModuleAssignmentOneToOne:
    def test_cannot_attach_two_quizzes_to_same_module(self, eagle_user, nest, content_module_factory, module_assignment_factory):
        module = content_module_factory(nest=nest, created_by=eagle_user)
        module_assignment_factory(module=module)
        with pytest.raises(IntegrityError):
            module_assignment_factory(module=module)


class TestModuleAssignmentAttemptUnique:
    def test_same_user_cannot_have_duplicate_attempt_number(
        self, eaglet_user, module_assignment_factory, content_module_factory, nest, eagle_user
    ):
        module = content_module_factory(nest=nest, created_by=eagle_user)
        quiz = module_assignment_factory(module=module)
        from apps.content.models import ModuleAssignmentAttempt
        ModuleAssignmentAttempt.objects.create(
            assignment=quiz, user=eaglet_user,
            answers={}, score=80, passed=True, attempt_number=1,
        )
        with pytest.raises(IntegrityError):
            ModuleAssignmentAttempt.objects.create(
                assignment=quiz, user=eaglet_user,
                answers={}, score=60, passed=True, attempt_number=1,
            )


class TestModuleQuestionJSONField:
    def test_mcq_options_round_trip(self, module_question_factory, module_assignment_factory, content_module_factory, nest, eagle_user):
        module = content_module_factory(nest=nest, created_by=eagle_user)
        quiz = module_assignment_factory(module=module)
        options = ["Option A", "Option B", "Option C", "Option D"]
        q = module_question_factory(assignment=quiz, question_type="mcq", options=options, correct_option=2)
        q.refresh_from_db()
        assert q.options == options
        assert q.correct_option == 2
