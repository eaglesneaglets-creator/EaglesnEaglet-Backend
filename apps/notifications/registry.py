"""
Notification Event Registry

Single source of truth for user-configurable notification events.
Maps Notification.NotificationType enum values into 5 user-facing domains.

Adding a new event:
1. Add to Notification.NotificationType
2. Add to one DOMAINS group + EVENT_LABELS
3. (Optional) Override DEFAULTS if it should be off by default

No migration required for the preferences table — missing rows fall back
to DEFAULTS at read time.
"""

from .models import Notification

NT = Notification.NotificationType

DOMAINS = {
    "mentorship": {
        "label": "Mentorship",
        "events": [
            NT.MENTORSHIP_REQUEST,
            NT.MENTORSHIP_APPROVED,
            NT.MENTORSHIP_REJECTED,
        ],
    },
    "content": {
        "label": "Content",
        "events": [
            NT.CONTENT_PUBLISHED,
            NT.ASSIGNMENT_GRADED,
        ],
    },
    "social": {
        "label": "Community",
        "events": [
            NT.NEST_POST,
            NT.POST_LIKE,
            NT.POST_COMMENT,
            NT.CHAT_MESSAGE,
        ],
    },
    "gamification": {
        "label": "Points & Badges",
        "events": [
            NT.POINTS_AWARDED,
            NT.BADGE_EARNED,
        ],
    },
    "commerce": {
        "label": "Store & Donations",
        "events": [
            NT.ORDER_CONFIRMED,
            NT.PAYMENT_RECEIVED,
        ],
    },
}

EVENT_LABELS = {
    NT.MENTORSHIP_REQUEST: "New mentorship request",
    NT.MENTORSHIP_APPROVED: "Mentorship request approved",
    NT.MENTORSHIP_REJECTED: "Mentorship request rejected",
    NT.CONTENT_PUBLISHED: "New content published",
    NT.ASSIGNMENT_GRADED: "Assignment graded",
    NT.NEST_POST: "New post in your nest",
    NT.POST_LIKE: "Someone liked your post",
    NT.POST_COMMENT: "Someone commented on your post",
    NT.CHAT_MESSAGE: "New chat message",
    NT.POINTS_AWARDED: "Points awarded",
    NT.BADGE_EARNED: "Badge earned",
    NT.ORDER_CONFIRMED: "Order confirmed",
    NT.PAYMENT_RECEIVED: "Payment received",
}

ALWAYS_ON = {NT.GENERAL.value}

DEFAULTS = {
    e.value: (True, True)
    for d in DOMAINS.values()
    for e in d["events"]
}


def all_configurable_events() -> list[str]:
    return list(DEFAULTS.keys())


def event_to_domain(event_type: str) -> str | None:
    for key, d in DOMAINS.items():
        if event_type in [e.value for e in d["events"]]:
            return key
    return None


def is_known_event(event_type: str) -> bool:
    return event_type in DEFAULTS or event_type in ALWAYS_ON
