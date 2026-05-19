"""Evaluator: count NestPosts authored by the mentee in the enrollment's Nest."""

from .base import BaseEvaluator


class PostsCountEvaluator(BaseEvaluator):
    rule_type = "posts_count"

    def progress(self, enrollment, snapshot_rule):
        from apps.nests.models import NestPost

        target = snapshot_rule.get("target", 0)
        qs = NestPost.objects.filter(
            author=enrollment.mentee,
            nest=enrollment.program.nest,
        )
        if enrollment.started_at:
            qs = qs.filter(created_at__gte=enrollment.started_at)

        return self._result(qs.count(), target)
