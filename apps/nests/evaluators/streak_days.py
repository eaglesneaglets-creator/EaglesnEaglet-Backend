"""
Evaluator: longest run of consecutive calendar days (UTC) on which the mentee
recorded any activity (NestPost, ContentProgress update, AssignmentSubmission).
"""

from datetime import timedelta

from .base import BaseEvaluator


class StreakDaysEvaluator(BaseEvaluator):
    rule_type = "streak_days"

    def progress(self, enrollment, snapshot_rule):
        from apps.content.models import AssignmentSubmission, ContentProgress
        from apps.nests.models import NestPost

        target = snapshot_rule.get("target", 0)
        since = enrollment.started_at

        post_dates = NestPost.objects.filter(author=enrollment.mentee)
        progress_dates = ContentProgress.objects.filter(user=enrollment.mentee)
        submit_dates = AssignmentSubmission.objects.filter(user=enrollment.mentee)
        if since:
            post_dates = post_dates.filter(created_at__gte=since)
            progress_dates = progress_dates.filter(last_accessed_at__gte=since)
            submit_dates = submit_dates.filter(submitted_at__gte=since)

        days = set()
        for d in post_dates.values_list("created_at", flat=True):
            days.add(d.date())
        for d in progress_dates.values_list("last_accessed_at", flat=True):
            days.add(d.date())
        for d in submit_dates.values_list("submitted_at", flat=True):
            days.add(d.date())

        if not days:
            return self._result(0, target)

        sorted_days = sorted(days)
        longest = 1
        current = 1
        for i in range(1, len(sorted_days)):
            if sorted_days[i] - sorted_days[i - 1] == timedelta(days=1):
                current += 1
                longest = max(longest, current)
            else:
                current = 1
        return self._result(longest, target)
