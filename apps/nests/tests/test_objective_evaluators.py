"""
Tests for the 5 objective rule evaluators (plan 14-03).

Each evaluator reads from the locked rules_snapshot — never the live
ProgramObjectiveRule — so mentor edits cannot move the finish line.
"""

from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from apps.content.models import (
    Assignment,
    AssignmentSubmission,
    ContentItem,
    ContentModule,
    ContentProgress,
)
from apps.nests.evaluators import (
    EVALUATOR_REGISTRY,
    UnknownRuleType,
    evaluate_enrollment,
    get_evaluator,
)
from apps.nests.models import Nest, NestPost
from apps.nests.models_program import Program, ProgramEnrollment
from apps.points.models import PointTransaction

User = get_user_model()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="eagle_eval@test.com", password="pass", role=User.Role.EAGLE,
        first_name="E", last_name="One",
    )


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="eaglet_eval@test.com", password="pass", role=User.Role.EAGLET,
        first_name="E", last_name="Two",
    )


@pytest.fixture
def nest(db, eagle):
    return Nest.objects.create(name="Eval Nest", eagle=eagle)


@pytest.fixture
def program(db, nest):
    return Program.objects.create(
        nest=nest, name="Eval Program", status=Program.Status.ACTIVE,
    )


@pytest.fixture
def enrollment(db, program, eaglet):
    return ProgramEnrollment.objects.create(
        program=program,
        mentee=eaglet,
        status=ProgramEnrollment.Status.ACTIVE,
        started_at=timezone.now() - timedelta(days=30),
        rules_snapshot={"program_id": str(program.id), "objectives": []},
    )


# ---------------------------------------------------------------------------
# modules_completed
# ---------------------------------------------------------------------------


class TestModulesCompletedEvaluator:
    def test_counts_modules_with_all_items_completed(self, db, enrollment, nest, eagle, eaglet):
        m1 = ContentModule.objects.create(title="M1", nest=nest, created_by=eagle)
        i1 = ContentItem.objects.create(module=m1, title="I1")
        i2 = ContentItem.objects.create(module=m1, title="I2")
        ContentProgress.objects.create(
            user=eaglet, content_item=i1, status=ContentProgress.Status.COMPLETED,
        )
        ContentProgress.objects.create(
            user=eaglet, content_item=i2, status=ContentProgress.Status.COMPLETED,
        )

        ev = get_evaluator("modules_completed")
        res = ev.progress(enrollment, {"target": 1, "config": {}})
        assert res["current"] == 1 and res["is_met"] is True

    def test_in_progress_modules_excluded(self, db, enrollment, nest, eagle, eaglet):
        m1 = ContentModule.objects.create(title="M1", nest=nest, created_by=eagle)
        i1 = ContentItem.objects.create(module=m1, title="I1")
        i2 = ContentItem.objects.create(module=m1, title="I2")
        ContentProgress.objects.create(
            user=eaglet, content_item=i1, status=ContentProgress.Status.COMPLETED,
        )
        ContentProgress.objects.create(
            user=eaglet, content_item=i2, status=ContentProgress.Status.IN_PROGRESS,
        )

        res = get_evaluator("modules_completed").progress(enrollment, {"target": 1, "config": {}})
        assert res["current"] == 0 and res["is_met"] is False


# ---------------------------------------------------------------------------
# assignments_passed
# ---------------------------------------------------------------------------


class TestAssignmentsPassedEvaluator:
    def test_counts_graded_submissions(self, db, enrollment, nest, eaglet):
        a = Assignment.objects.create(title="A1", description="x", nest=nest)
        AssignmentSubmission.objects.create(
            assignment=a, user=eaglet, file_url="http://x/y.pdf",
            status=AssignmentSubmission.Status.GRADED, grade="A",
        )
        AssignmentSubmission.objects.create(
            assignment=a, user=eaglet, file_url="http://x/y2.pdf",
            status=AssignmentSubmission.Status.SUBMITTED,
        )
        res = get_evaluator("assignments_passed").progress(enrollment, {"target": 1, "config": {}})
        assert res["current"] == 1 and res["is_met"] is True

    def test_returned_submissions_excluded(self, db, enrollment, nest, eaglet):
        a = Assignment.objects.create(title="A1", description="x", nest=nest)
        AssignmentSubmission.objects.create(
            assignment=a, user=eaglet, file_url="http://x/y.pdf",
            status=AssignmentSubmission.Status.RETURNED, grade="F",
        )
        res = get_evaluator("assignments_passed").progress(enrollment, {"target": 1, "config": {}})
        assert res["current"] == 0


# ---------------------------------------------------------------------------
# points_earned
# ---------------------------------------------------------------------------


class TestPointsEarnedEvaluator:
    def test_sums_positive_transactions_since_start(self, db, enrollment, eaglet):
        PointTransaction.objects.create(
            user=eaglet, points=50, activity_type="check_in",
        )
        PointTransaction.objects.create(
            user=eaglet, points=30, activity_type="post_created",
        )
        res = get_evaluator("points_earned").progress(enrollment, {"target": 80, "config": {}})
        assert res["current"] == 80 and res["is_met"] is True

    def test_pre_enrollment_points_excluded(self, db, enrollment, eaglet):
        # PointTransaction.created_at is auto_now_add — simulate older row by direct update.
        tx = PointTransaction.objects.create(
            user=eaglet, points=999, activity_type="check_in",
        )
        PointTransaction.objects.filter(pk=tx.pk).update(
            created_at=enrollment.started_at - timedelta(days=10),
        )
        PointTransaction.objects.create(
            user=eaglet, points=10, activity_type="check_in",
        )
        res = get_evaluator("points_earned").progress(enrollment, {"target": 100, "config": {}})
        assert res["current"] == 10


# ---------------------------------------------------------------------------
# posts_count
# ---------------------------------------------------------------------------


class TestPostsCountEvaluator:
    def test_counts_only_posts_in_enrollment_nest(self, db, enrollment, nest, eagle, eaglet):
        other_eagle = User.objects.create_user(
            email="o@x.com", password="p", role=User.Role.EAGLE,
        )
        other_nest = Nest.objects.create(name="Other", eagle=other_eagle)

        NestPost.objects.create(nest=nest, author=eaglet, content="p1")
        NestPost.objects.create(nest=nest, author=eaglet, content="p2")
        NestPost.objects.create(nest=other_nest, author=eaglet, content="p3")
        res = get_evaluator("posts_count").progress(enrollment, {"target": 2, "config": {}})
        assert res["current"] == 2 and res["is_met"] is True


# ---------------------------------------------------------------------------
# streak_days
# ---------------------------------------------------------------------------


class TestStreakDaysEvaluator:
    def test_consecutive_days_counted(self, db, enrollment, nest, eaglet):
        base = timezone.now() - timedelta(days=5)
        for i in range(3):
            p = NestPost.objects.create(nest=nest, author=eaglet, content=f"d{i}")
            NestPost.objects.filter(pk=p.pk).update(created_at=base + timedelta(days=i))
        res = get_evaluator("streak_days").progress(enrollment, {"target": 3, "config": {}})
        assert res["current"] == 3 and res["is_met"] is True

    def test_gap_breaks_streak(self, db, enrollment, nest, eaglet):
        base = timezone.now() - timedelta(days=10)
        for i in [0, 1, 5, 6]:
            p = NestPost.objects.create(nest=nest, author=eaglet, content=f"d{i}")
            NestPost.objects.filter(pk=p.pk).update(created_at=base + timedelta(days=i))
        res = get_evaluator("streak_days").progress(enrollment, {"target": 3, "config": {}})
        assert res["current"] == 2 and res["is_met"] is False


# ---------------------------------------------------------------------------
# Registry + evaluate_enrollment
# ---------------------------------------------------------------------------


class TestRegistryAndAggregate:
    def test_unknown_rule_type_raises(self):
        with pytest.raises(UnknownRuleType):
            get_evaluator("not_a_real_rule")

    def test_registry_contains_all_5_evaluators(self):
        assert set(EVALUATOR_REGISTRY.keys()) == {
            "modules_completed", "assignments_passed",
            "points_earned", "posts_count", "streak_days",
        }

    def test_evaluate_enrollment_aggregates_objectives(self, db, enrollment, nest, eaglet):
        PointTransaction.objects.create(
            user=eaglet, points=100, activity_type="check_in",
        )
        enrollment.rules_snapshot = {
            "program_id": str(enrollment.program_id),
            "objectives": [
                {
                    "id": "o1", "title": "Earn 50",
                    "rules": [{"id": "r1", "rule_type": "points_earned", "target": 50, "config": {}}],
                },
                {
                    "id": "o2", "title": "Post 1",
                    "rules": [{"id": "r2", "rule_type": "posts_count", "target": 1, "config": {}}],
                },
            ],
        }
        enrollment.save(update_fields=["rules_snapshot"])

        result = evaluate_enrollment(enrollment)
        assert result["all_met"] is False  # posts_count not met
        assert result["objectives"][0]["is_met"] is True
        assert result["objectives"][1]["is_met"] is False

    def test_evaluate_enrollment_uses_snapshot_not_live_rules(self, db, enrollment, eaglet):
        PointTransaction.objects.create(
            user=eaglet, points=10, activity_type="check_in",
        )
        # Snapshot says target=10; live rules absent — evaluator must still run on snapshot.
        enrollment.rules_snapshot = {
            "program_id": str(enrollment.program_id),
            "objectives": [{
                "id": "o1", "title": "T",
                "rules": [{"id": "r1", "rule_type": "points_earned", "target": 10, "config": {}}],
            }],
        }
        enrollment.save(update_fields=["rules_snapshot"])
        result = evaluate_enrollment(enrollment)
        assert result["all_met"] is True

    def test_empty_snapshot_means_not_met(self, db, enrollment):
        result = evaluate_enrollment(enrollment)
        assert result["all_met"] is False
