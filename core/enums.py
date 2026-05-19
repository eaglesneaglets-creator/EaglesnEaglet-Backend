"""
Central enum registry — single source of truth exposed to FE via /api/v1/enums/.

Adds new status enums here when FE needs them. UI-facing semantic groups
(e.g. "which enrollment statuses count as approved?") live alongside raw
value→label maps.
"""

from apps.nests.models import MentorshipRequest, NestMembership
from apps.nests.models_program import (
    Program,
    ProgramEnrollment,
    ProgramExitRequest,
)
from apps.users.models import MentorKYC, MenteeKYC


def _choices_dict(choices_cls):
    """TextChoices → { value: label } dict (Django stores tuples, FE wants object)."""
    return dict(choices_cls.choices)


# -- Raw value→label registries -----------------------------------------------

ENUMS = {
    'enrollment_status': _choices_dict(ProgramEnrollment.Status),
    'program_status': _choices_dict(Program.Status),
    'exit_request_status': _choices_dict(ProgramExitRequest.Status),
    'membership_status': _choices_dict(NestMembership.Status),
    'mentorship_request_status': _choices_dict(MentorshipRequest.Status),
    'kyc_status': _choices_dict(MentorKYC.VerificationStatus),
    'mentee_kyc_status': _choices_dict(MenteeKYC.VerificationStatus),
}


# -- Semantic groupings (UI-facing buckets) -----------------------------------
#
# A status may belong to exactly one group. The "approved" bucket is what
# the mentee sees as success state; "declined" is any terminal-negative.

ENUM_GROUPS = {
    'enrollment_status_groups': {
        'pending': ['pending'],
        'approved': ['active', 'completed'],
        'declined': ['rejected', 'released', 'opted_out'],
    },
    'kyc_status_groups': {
        'pending': ['submitted', 'under_review'],
        'approved': ['approved'],
        'declined': ['rejected', 'requires_changes'],
    },
    'mentee_kyc_status_groups': {
        'pending': ['submitted', 'under_review'],
        'approved': ['approved'],
        'declined': ['rejected', 'requires_changes'],
    },
}


def get_all_enums() -> dict:
    """Combined payload returned by /enums/ endpoint."""
    return {**ENUMS, **ENUM_GROUPS}
