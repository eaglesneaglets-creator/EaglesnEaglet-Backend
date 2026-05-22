"""Mentee level computation (plan 14-04).

Pure functional layer — no DB writes, no User mutation. Lifetime carry-forward
across qualifying ProgramEnrollment windows (ACTIVE, COMPLETED, RELEASED,
OPTED_OUT). PENDING + REJECTED enrollments do NOT qualify.

Reaching the level whose `unlocks_mentor_application` flag is True sets
`mentor_eligible=True` in the returned dict. Promotion to mentor still requires
the user to apply + KYC + admin approval (out of scope for v1).
"""

from django.db.models import Q
from django.utils import timezone


_ZERO_BLOCK = {
    "current_level": 0,
    "current_level_name": None,
    "points_total": 0,
    "next_level": 1,
    "points_to_next": None,
    "mentor_eligible": False,
    # FE-shape aliases (MenteeLevelCard reads these).
    "points": 0,
    "next_threshold": None,
    "progress_pct": 0,
    # Distinguishes "no qualifying enrollment yet" from "enrolled but no points".
    # FE uses this to surface an educational empty state instead of "0 pts / 0%".
    "requires_enrollment": True,
}


_QUALIFYING_STATUSES = ("active", "completed", "released", "opted_out")


def compute_level(user) -> dict:
    """Compute the mentee level for `user` from lifetime program activity.

    Returns a dict with keys:
        current_level, current_level_name, points_total,
        next_level, points_to_next, mentor_eligible
    """
    if getattr(user, "role", None) != "eaglet":
        return dict(_ZERO_BLOCK)

    from apps.nests.models_program import (
        MenteeLevelConfig,
        ProgramEnrollment,
    )
    from apps.points.models import PointTransaction

    enrollments = list(
        ProgramEnrollment.objects.filter(
            mentee=user, status__in=_QUALIFYING_STATUSES,
        ).values("started_at", "ended_at")
    )
    if not enrollments:
        return dict(_ZERO_BLOCK)

    now = timezone.now()
    window_q = Q()
    for e in enrollments:
        start = e["started_at"]
        end = e["ended_at"] or now
        if start is None:
            continue
        window_q |= Q(created_at__gte=start, created_at__lte=end)

    if not window_q:
        return dict(_ZERO_BLOCK)

    # distinct() guards against double-counting when windows overlap.
    points_total = _sum_points(PointTransaction, window_q, user)

    configs = list(MenteeLevelConfig.objects.order_by("level"))
    current_config = None
    for cfg in configs:
        if points_total >= cfg.points_required:
            current_config = cfg
        else:
            break

    if current_config is None:
        first = configs[0] if configs else None
        first_threshold = first.points_required if first else None
        progress_pct = (
            int((points_total / first_threshold) * 100)
            if first_threshold else 0
        )
        return {
            "current_level": 0,
            "current_level_name": None,
            "points_total": points_total,
            "next_level": first.level if first else None,
            "points_to_next": (first_threshold - points_total) if first else None,
            "mentor_eligible": False,
            # FE-shape aliases.
            "points": points_total,
            "next_threshold": first_threshold,
            "progress_pct": min(100, max(0, progress_pct)),
            "requires_enrollment": False,
        }

    next_cfg = next(
        (c for c in configs if c.level > current_config.level), None,
    )
    next_threshold = next_cfg.points_required if next_cfg else None
    # Progress within current level band: 0% at current threshold, 100% at next.
    if next_cfg is not None:
        band = next_cfg.points_required - current_config.points_required
        progress_pct = int(
            ((points_total - current_config.points_required) / band) * 100
        ) if band > 0 else 100
    else:
        progress_pct = 100
    return {
        "current_level": current_config.level,
        "current_level_name": current_config.name,
        "points_total": points_total,
        "next_level": next_cfg.level if next_cfg else None,
        "points_to_next": (
            next_threshold - points_total if next_threshold is not None else None
        ),
        "mentor_eligible": bool(current_config.unlocks_mentor_application),
        # FE-shape aliases.
        "points": points_total,
        "next_threshold": next_threshold,
        "progress_pct": min(100, max(0, progress_pct)),
        "requires_enrollment": False,
    }


def _sum_points(PointTransaction, window_q, user) -> int:
    from django.db.models import Sum
    total = (
        PointTransaction.objects.filter(window_q, user=user)
        .distinct()
        .aggregate(s=Sum("points"))["s"]
    )
    return int(total or 0)
