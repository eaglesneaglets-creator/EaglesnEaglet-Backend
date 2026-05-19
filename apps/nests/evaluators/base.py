"""
Base interface for objective rule evaluators (plan 14-03).

Each evaluator implementation reads from the locked `rules_snapshot` on the
enrollment, NOT from the live ProgramObjectiveRule, so mentor edits cannot
move the finish line for active enrollees.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apps.nests.models_program import ProgramEnrollment


class BaseEvaluator:
    """Computes mentee progress against one snapshotted rule."""

    rule_type: str = ""

    def progress(
        self,
        enrollment: "ProgramEnrollment",
        snapshot_rule: dict,
    ) -> dict:
        """Return {'current': int, 'target': int, 'is_met': bool}."""
        raise NotImplementedError

    @staticmethod
    def _result(current: int, target: int) -> dict:
        return {
            "current": int(current),
            "target": int(target),
            "is_met": int(current) >= int(target),
        }
