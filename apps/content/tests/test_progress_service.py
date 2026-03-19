"""
Tests for ProgressService — 50% gate, resource gate, and module completion.
"""

import pytest
from rest_framework.exceptions import ValidationError

from apps.content.services import ProgressService
from apps.content.models import ContentProgress

pytestmark = pytest.mark.django_db


class TestVideo50PercentGate:
    def test_video_blocked_completion_below_50_percent_watch_time(
        self, eaglet_user, content_item_factory, nest, content_module_factory, eagle_user, nest_membership
    ):
        module = content_module_factory(nest=nest, created_by=eagle_user)
        # 10 minute video; 50% = 300 seconds minimum watch required
        item = content_item_factory(module=module, content_type="video", duration_minutes=10)

        # Watch only 100 seconds (< 50% of 600s = 300s)
        progress = ProgressService.update_progress(
            eaglet_user, str(item.id), 100.0, watch_duration_seconds=100
        )
        # Should be capped at 99% — not completed
        assert progress.progress_percentage < 100.0
        assert progress.status != "completed"

    def test_video_completes_at_50_percent_watch_time(
        self, eaglet_user, content_item_factory, nest, content_module_factory, eagle_user, nest_membership
    ):
        module = content_module_factory(nest=nest, created_by=eagle_user)
        item = content_item_factory(module=module, content_type="video", duration_minutes=10)

        # Watch 300 seconds (50% of 600s)
        progress = ProgressService.update_progress(
            eaglet_user, str(item.id), 100.0, watch_duration_seconds=300
        )
        assert progress.status == "completed"


class TestCheckResourceGate:
    def test_returns_false_when_required_item_below_50_percent(
        self, eaglet_user, content_item_factory, content_module_factory, nest, eagle_user, nest_membership
    ):
        module = content_module_factory(nest=nest, created_by=eagle_user)
        item = content_item_factory(module=module, is_required=True, content_type="document")
        # Create progress at 30% — below gate
        ContentProgress.objects.create(
            user=eaglet_user, content_item=item, progress_percentage=30.0, status="in_progress"
        )
        assert ProgressService.check_resource_gate(eaglet_user, module) is False

    def test_returns_true_when_all_required_items_at_50_percent(
        self, eaglet_user, content_item_factory, content_module_factory, nest, eagle_user, nest_membership
    ):
        module = content_module_factory(nest=nest, created_by=eagle_user)
        item = content_item_factory(module=module, is_required=True, content_type="document")
        ContentProgress.objects.create(
            user=eaglet_user, content_item=item, progress_percentage=50.0, status="in_progress"
        )
        assert ProgressService.check_resource_gate(eaglet_user, module) is True

    def test_returns_true_when_no_required_items_exist(
        self, eaglet_user, content_module_factory, nest, eagle_user
    ):
        module = content_module_factory(nest=nest, created_by=eagle_user)
        assert ProgressService.check_resource_gate(eaglet_user, module) is True


class TestCheckModuleCompletion:
    def test_does_not_award_points_if_resource_gate_not_cleared(
        self, eaglet_user, content_module_factory, nest, eagle_user
    ):
        module = content_module_factory(nest=nest, created_by=eagle_user)
        from unittest.mock import patch
        with patch("apps.content.services.ProgressService.check_resource_gate", return_value=False), \
             patch("apps.points.services.PointService.award_points") as mock_award:
            result = ProgressService.check_module_completion(eaglet_user, module)
        assert result is False
        mock_award.assert_not_called()

    def test_does_not_award_if_quiz_not_passed(
        self, eaglet_user, content_module_factory, module_assignment_factory, nest, eagle_user
    ):
        module = content_module_factory(nest=nest, created_by=eagle_user)
        module_assignment_factory(module=module)
        from unittest.mock import patch
        with patch("apps.content.services.ProgressService.check_resource_gate", return_value=True), \
             patch("apps.points.services.PointService.award_points") as mock_award:
            result = ProgressService.check_module_completion(eaglet_user, module)
        assert result is False
        mock_award.assert_not_called()

    def test_awards_points_idempotently_when_conditions_met(
        self, eaglet_user, content_module_factory, nest, eagle_user
    ):
        module = content_module_factory(nest=nest, created_by=eagle_user)
        from unittest.mock import patch
        with patch("apps.content.services.ProgressService.check_resource_gate", return_value=True), \
             patch("apps.points.services.PointService.award_points") as mock_award:
            ProgressService.check_module_completion(eaglet_user, module)
            ProgressService.check_module_completion(eaglet_user, module)
        # award_points is called both times — idempotency enforced by PointService.source_id
        assert mock_award.call_count == 2
