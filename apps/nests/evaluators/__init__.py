"""
Objective rule evaluators (plan 14-03).

Registry maps `rule_type` (matches ProgramObjectiveRule.RuleType) to a singleton
evaluator instance. `evaluate_enrollment` walks the locked rules_snapshot on an
enrollment and returns a structured progress map used by EnrollmentService.complete().
"""

from .assignments_passed import AssignmentsPassedEvaluator
from .base import BaseEvaluator
from .modules_completed import ModulesCompletedEvaluator
from .points_earned import PointsEarnedEvaluator
from .posts_count import PostsCountEvaluator
from .streak_days import StreakDaysEvaluator

EVALUATOR_REGISTRY: dict[str, BaseEvaluator] = {
    "modules_completed": ModulesCompletedEvaluator(),
    "assignments_passed": AssignmentsPassedEvaluator(),
    "points_earned": PointsEarnedEvaluator(),
    "posts_count": PostsCountEvaluator(),
    "streak_days": StreakDaysEvaluator(),
}


class UnknownRuleType(ValueError):
    """Raised when a snapshot contains a rule_type with no registered evaluator."""


def get_evaluator(rule_type: str) -> BaseEvaluator:
    try:
        return EVALUATOR_REGISTRY[rule_type]
    except KeyError as exc:
        raise UnknownRuleType(f"No evaluator registered for rule_type={rule_type!r}") from exc


def evaluate_enrollment(enrollment) -> dict:
    """Walk the enrollment's snapshot and compute progress for every rule.

    Returns:
        {
          "program_id": "...",
          "all_met": bool,
          "objectives": [
            {
              "id": "...",
              "title": "...",
              "rules": [{rule_type, current, target, is_met}, ...],
              "is_met": bool,
            },
            ...
          ],
        }
    """
    snapshot = enrollment.rules_snapshot or {}
    objective_results = []
    overall_met = True

    for objective in snapshot.get("objectives", []):
        rule_results = []
        objective_met = True
        for rule in objective.get("rules", []):
            evaluator = get_evaluator(rule["rule_type"])
            res = evaluator.progress(enrollment, rule)
            rule_results.append({
                "rule_id": rule.get("id"),
                "rule_type": rule["rule_type"],
                "current": res["current"],
                "target": res["target"],
                "is_met": res["is_met"],
            })
            objective_met = objective_met and res["is_met"]

        objective_results.append({
            "id": objective.get("id"),
            "title": objective.get("title"),
            "rules": rule_results,
            "is_met": objective_met if objective.get("rules") else False,
        })
        if objective.get("rules"):
            overall_met = overall_met and objective_met

    if not snapshot.get("objectives"):
        overall_met = False

    return {
        "program_id": snapshot.get("program_id"),
        "all_met": overall_met,
        "objectives": objective_results,
    }


__all__ = [
    "BaseEvaluator",
    "EVALUATOR_REGISTRY",
    "UnknownRuleType",
    "evaluate_enrollment",
    "get_evaluator",
]
