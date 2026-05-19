"""Evaluator: count distinct ContentModules whose every item is completed."""

from .base import BaseEvaluator


class ModulesCompletedEvaluator(BaseEvaluator):
    rule_type = "modules_completed"

    def progress(self, enrollment, snapshot_rule):
        from apps.content.models import ContentItem, ContentProgress

        target = snapshot_rule.get("target", 0)
        config = snapshot_rule.get("config") or {}
        scoped_module_ids = config.get("module_ids")

        completed_progress = ContentProgress.objects.filter(
            user=enrollment.mentee,
            status=ContentProgress.Status.COMPLETED,
        )
        if scoped_module_ids:
            completed_progress = completed_progress.filter(
                content_item__module_id__in=scoped_module_ids,
            )

        completed_item_ids = set(
            completed_progress.values_list("content_item_id", flat=True)
        )

        items_by_module: dict = {}
        for item in ContentItem.objects.filter(
            id__in=completed_item_ids,
        ).values("id", "module_id"):
            items_by_module.setdefault(item["module_id"], set()).add(item["id"])

        modules_qs = ContentItem.objects.order_by().values("module_id").distinct()
        if scoped_module_ids:
            modules_qs = modules_qs.filter(module_id__in=scoped_module_ids)

        completed_modules = 0
        for module_row in modules_qs:
            module_id = module_row["module_id"]
            all_item_ids = set(
                ContentItem.objects.filter(module_id=module_id).values_list("id", flat=True)
            )
            if all_item_ids and all_item_ids.issubset(items_by_module.get(module_id, set())):
                completed_modules += 1

        return self._result(completed_modules, target)
