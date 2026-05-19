"""Evaluator: sum positive PointTransaction.points since enrollment.started_at."""

from django.db.models import Sum

from .base import BaseEvaluator


class PointsEarnedEvaluator(BaseEvaluator):
    rule_type = "points_earned"

    def progress(self, enrollment, snapshot_rule):
        from apps.points.models import PointTransaction

        target = snapshot_rule.get("target", 0)
        config = snapshot_rule.get("config") or {}

        qs = PointTransaction.objects.filter(
            user=enrollment.mentee,
            points__gt=0,
        )
        if enrollment.started_at:
            qs = qs.filter(created_at__gte=enrollment.started_at)

        nest_scoped = config.get("nest_scoped", False)
        if nest_scoped:
            qs = qs.filter(nest=enrollment.program.nest)

        total = qs.aggregate(total=Sum("points"))["total"] or 0
        return self._result(total, target)
