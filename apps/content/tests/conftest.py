"""
Pytest fixtures for content app tests.
"""

import pytest
from apps.content.models import (
    ContentModule,
    ContentItem,
    ModuleAssignment,
    ModuleQuestion,
)


@pytest.fixture
def eagle_user(db):
    from django.contrib.auth import get_user_model
    User = get_user_model()
    return User.objects.create_user(
        email="eagle@test.com", password="testpass", role="eagle",
        first_name="Eagle", last_name="User",
    )


@pytest.fixture
def eaglet_user(db):
    from django.contrib.auth import get_user_model
    User = get_user_model()
    return User.objects.create_user(
        email="eaglet@test.com", password="testpass", role="eaglet",
        first_name="Eaglet", last_name="User",
    )


@pytest.fixture
def nest(db, eagle_user):
    from apps.nests.models import Nest
    return Nest.objects.create(
        name="Test Nest", eagle=eagle_user, description="A test nest"
    )


@pytest.fixture
def nest_membership(db, eaglet_user, nest):
    from apps.nests.models import NestMembership
    return NestMembership.objects.create(
        nest=nest, user=eaglet_user, status="active"
    )


@pytest.fixture
def content_module_factory(db):
    def _factory(nest, created_by, **kwargs):
        return ContentModule.objects.create(
            title=kwargs.get("title", "Test Module"),
            nest=nest,
            created_by=created_by,
            points_value=kwargs.get("points_value", 100),
        )
    return _factory


@pytest.fixture
def content_item_factory(db):
    def _factory(module, **kwargs):
        return ContentItem.objects.create(
            module=module,
            title=kwargs.get("title", "Test Item"),
            content_type=kwargs.get("content_type", "document"),
            duration_minutes=kwargs.get("duration_minutes", 0),
            is_required=kwargs.get("is_required", True),
        )
    return _factory


@pytest.fixture
def module_assignment_factory(db):
    def _factory(module, **kwargs):
        return ModuleAssignment.objects.create(
            module=module,
            title=kwargs.get("title", "Test Quiz"),
            pass_score=kwargs.get("pass_score", 60),
            max_attempts=kwargs.get("max_attempts", 3),
            points_value=kwargs.get("points_value", 50),
        )
    return _factory


@pytest.fixture
def module_question_factory(db):
    def _factory(assignment, **kwargs):
        return ModuleQuestion.objects.create(
            assignment=assignment,
            question_type=kwargs.get("question_type", "mcq"),
            question_text=kwargs.get("question_text", "What is 2 + 2?"),
            options=kwargs.get("options", ["1", "2", "4", "8"]),
            correct_option=kwargs.get("correct_option", 2),
            order=kwargs.get("order", 0),
        )
    return _factory


@pytest.fixture
def quiz_with_mcq_question(db, nest, eagle_user, content_module_factory, module_assignment_factory, module_question_factory):
    module = content_module_factory(nest=nest, created_by=eagle_user)
    quiz = module_assignment_factory(module=module, pass_score=60)
    question = module_question_factory(
        assignment=quiz,
        question_type="mcq",
        options=["A", "B", "C", "D"],
        correct_option=1,
    )
    return quiz, question


@pytest.fixture
def quiz_with_descriptive_question(db, nest, eagle_user, content_module_factory, module_assignment_factory, module_question_factory):
    module = content_module_factory(nest=nest, created_by=eagle_user)
    quiz = module_assignment_factory(module=module)
    question = module_question_factory(
        assignment=quiz,
        question_type="descriptive",
        question_text="Describe your learning experience.",
        options=None,
        correct_option=None,
    )
    return quiz, question
