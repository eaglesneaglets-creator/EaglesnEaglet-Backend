"""
Data migration: seed all 47 badge records.
Runs automatically as part of `python manage.py migrate`.
Safe to re-run — uses update_or_create on slug.
"""

from django.db import migrations

BADGES = [
    # ── Learning Journey (COURSES_COMPLETED) ──────────────────────────────
    ("cracked_shell",    "Cracked Shell",    "courses_completed", 1,  "You've broken out of the shell — your first module complete.",    "learning", 1),
    ("fledgling",        "Fledgling",        "courses_completed", 3,  "Learning to use your wings — 3 modules down.",                    "learning", 2),
    ("first_flight",     "First Flight",     "courses_completed", 7,  "You've left the nest — 7 modules complete.",                      "learning", 3),
    ("gliding",          "Gliding",          "courses_completed", 15, "Effortless momentum — 15 modules behind you.",                    "learning", 4),
    ("full_wingspan",    "Full Wingspan",    "courses_completed", 25, "Fully developed, maximum spread — 25 modules complete.",          "learning", 5),

    # ── Assignment Mastery (ASSIGNMENTS_SUBMITTED) ────────────────────────
    ("eager_talons",     "Eager Talons",     "assignments_submitted", 1,  "Ready to grab knowledge — first assignment submitted.",      "assignment", 1),
    ("sharp_claws",      "Sharp Claws",      "assignments_submitted", 5,  "Precision is developing — 5 assignments submitted.",         "assignment", 2),
    ("the_hunter",       "The Hunter",       "assignments_submitted", 10, "Consistent and focused — 10 assignments submitted.",         "assignment", 3),
    ("precision_strike", "Precision Strike", "assignments_submitted", 20, "Disciplined execution — 20 assignments submitted.",          "assignment", 4),
    ("eagle_eyed",       "Eagle-Eyed",       "assignments_submitted", 35, "Nothing escapes you — 35 assignments submitted.",            "assignment", 5),

    # ── Consistency (STREAK_DAYS) ─────────────────────────────────────────
    ("morning_wing",     "Morning Wing",     "streak_days", 3,  "Early signs of habit — 3 day streak.",     "streak", 1),
    ("thermal_rider",    "Thermal Rider",    "streak_days", 7,  "Riding the updraft — 7 day streak.",       "streak", 2),
    ("wind_walker",      "Wind Walker",      "streak_days", 14, "Moving with purpose — 14 day streak.",     "streak", 3),
    ("sky_drifter",      "Sky Drifter",      "streak_days", 30, "Sustained flight — 30 day streak.",        "streak", 4),
    ("eternal_soarer",   "Eternal Soarer",   "streak_days", 60, "Unstoppable rhythm — 60 day streak.",      "streak", 5),

    # ── Points Milestones (POINTS_THRESHOLD) ─────────────────────────────
    ("hatchling",        "Hatchling",        "points_threshold", 100,   "Life begins — 100 points earned.",        "points", 1),
    ("nestling",         "Nestling",         "points_threshold", 500,   "Growing stronger — 500 points earned.",   "points", 2),
    ("fledge",           "Fledge",           "points_threshold", 1500,  "Ready to take off — 1,500 points earned.","points", 3),
    ("talon_bearer",     "Talon Bearer",     "points_threshold", 5000,  "Power earned — 5,000 points.",            "points", 4),
    ("sky_sovereign",    "Sky Sovereign",    "points_threshold", 15000, "Commanding presence — 15,000 points.",    "points", 5),

    # ── Community Voice (COMMUNITY_CONTRIBUTIONS) ─────────────────────────
    ("first_chirp",      "First Chirp",      "community_contributions", 1,   "Breaking silence — first post or comment.", "community", 1),
    ("nest_voice",       "Nest Voice",       "community_contributions", 10,  "Being noticed — 10 contributions.",         "community", 2),
    ("flock_caller",     "Flock Caller",     "community_contributions", 25,  "Others listen — 25 contributions.",         "community", 3),
    ("eagle_call",       "Eagle Call",       "community_contributions", 50,  "A rallying presence — 50 contributions.",   "community", 4),
    ("echo_of_sky",      "Echo of the Sky",  "community_contributions", 100, "Your voice carries far — 100 contributions.","community", 5),

    # ── Quiz Sharpness (QUIZZES_PASSED) ───────────────────────────────────
    ("keen_eye",         "Keen Eye",         "quizzes_passed", 1,  "Awareness awakens — first quiz passed.",           "quiz", 1),
    ("focused_gaze",     "Focused Gaze",     "quizzes_passed", 3,  "Locking onto targets — 3 quizzes passed.",         "quiz", 2),
    ("sharp_sight",      "Sharp Sight",      "quizzes_passed", 7,  "Nothing blurry — 7 quizzes passed.",               "quiz", 3),
    ("predators_vision", "Predator's Vision","quizzes_passed", 15, "Crystal clear judgement — 15 quizzes passed.",     "quiz", 4),
    ("raptor_mind",      "Raptor Mind",      "quizzes_passed", 25, "Razor-sharp intellect — 25 quizzes passed.",       "quiz", 5),

    # ── Nest Presence (EVENTS_ATTENDED) ───────────────────────────────────
    ("flock_joiner",     "Flock Joiner",     "events_attended", 1,  "You showed up — first event attended.",            "nest", 1),
    ("nest_regular",     "Nest Regular",     "events_attended", 5,  "A familiar face — 5 events attended.",             "nest", 2),
    ("circle_rider",     "Circle Rider",     "events_attended", 10, "Part of the rhythm — 10 events attended.",         "nest", 3),
    ("flock_elder",      "Flock Elder",      "events_attended", 20, "A pillar of the nest — 20 events attended.",       "nest", 4),
    ("sentinel",         "Sentinel",         "events_attended", 40, "Guardian of the community — 40 events attended.",  "nest", 5),

    # ── Special One-Time (ONE_TIME_EVENT) ─────────────────────────────────
    ("egg_cracker",          "Egg Cracker",      "one_time_event", 1, "The journey begins — profile complete.",                  "special", 0),
    ("first_nest_join",      "Found My Nest",    "one_time_event", 1, "Belonging starts here — joined your first Nest.",         "special", 0),
    ("first_resource_share", "Resource Eagle",   "one_time_event", 1, "Contributing to the flock — first resource shared.",      "special", 0),
    ("mentors_mark",         "Mentor's Mark",    "one_time_event", 1, "Noticed by your mentor — received a manual point award.", "special", 0),
    ("perfect_feathers",     "Perfect Feathers", "one_time_event", 1, "Flawless execution — scored 100% on a quiz.",             "special", 0),
    ("early_bird",           "Early Bird",       "one_time_event", 1, "Ahead of the flock — submitted an assignment early.",     "special", 0),

    # ── Nests Joined Count-Gate (NESTS_JOINED) ────────────────────────────
    ("scout",                "Scout",            "nests_joined",   3, "Curious explorer — joined 3 different Nests.",            "special", 0),

    # ── Elite / Competitive (COMPETITIVE) ────────────────────────────────
    ("thunder_wing",        "Thunder Wing",        "competitive", 1, "#1 on the leaderboard for a full month.",                       "elite", 0),
    ("legend_of_the_nest",  "Legend of the Nest",  "competitive", 1, "Highest all-time points in a specific Nest.",                   "elite", 0),
    ("iron_wing",           "Iron Wing",           "competitive", 1, "90-day unbroken streak — very rare.",                           "elite", 0),
    ("chosen_eaglet",       "The Chosen Eaglet",   "competitive", 1, "Nominated directly by your Eagle mentor.",                      "elite", 0),
    ("sky_sovereign_elite", "Sky King / Sky Queen","competitive", 1, "Top 1% of all Eaglets on the platform, recalculated quarterly.","elite", 0),
]


def seed_badges(apps, schema_editor):
    Badge = apps.get_model("points", "Badge")
    for row in BADGES:
        slug, name, criteria_type, criteria_value, description, category, tier = row
        Badge.objects.update_or_create(
            slug=slug,
            defaults={
                "name": name,
                "criteria_type": criteria_type,
                "criteria_value": criteria_value,
                "description": description,
            },
        )


def unseed_badges(apps, schema_editor):
    Badge = apps.get_model("points", "Badge")
    slugs = [row[0] for row in BADGES]
    Badge.objects.filter(slug__in=slugs).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("points", "0006_add_performance_indexes"),
    ]

    operations = [
        migrations.RunPython(seed_badges, reverse_code=unseed_badges),
    ]
