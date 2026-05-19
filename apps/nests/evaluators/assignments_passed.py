"""Evaluator: count assignment submissions in 'graded' status with a passing grade."""

from .base import BaseEvaluator

PASSING_GRADES = {"pass", "passed", "a", "b", "c", "a+", "a-", "b+", "b-", "c+"}


class AssignmentsPassedEvaluator(BaseEvaluator):
    rule_type = "assignments_passed"

    def progress(self, enrollment, snapshot_rule):
        from apps.content.models import AssignmentSubmission

        target = snapshot_rule.get("target", 0)
        config = snapshot_rule.get("config") or {}
        scoped_assignment_ids = config.get("assignment_ids")

        qs = AssignmentSubmission.objects.filter(
            user=enrollment.mentee,
            status=AssignmentSubmission.Status.GRADED,
        )
        if scoped_assignment_ids:
            qs = qs.filter(assignment_id__in=scoped_assignment_ids)

        # Count submissions whose normalized grade is in passing set OR has no
        # explicit grade (treat 'graded' as passed when grade text is empty).
        count = 0
        for grade in qs.values_list("grade", flat=True):
            normalized = (grade or "").strip().lower()
            if not normalized or normalized in PASSING_GRADES or normalized.startswith(("a", "b", "c")):
                count += 1

        return self._result(count, target)
