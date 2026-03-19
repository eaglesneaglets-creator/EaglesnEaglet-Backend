"""
Management command: seed_badges
Creates or updates all 47 badge records.
Safe to run multiple times (uses update_or_create on slug).

Usage:
    python manage.py seed_badges
"""
from django.core.management.base import BaseCommand
from apps.points.models import Badge
from .badge_icons import make_svg

# ---------------------------------------------------------------------------
# Badge definitions
# Format: (slug, name, criteria_type, criteria_value, description, category, tier, icon_key)
# tier=0 for non-tiered badges (special/elite)
# ---------------------------------------------------------------------------

BADGES = [
    # ── Learning Journey (COURSES_COMPLETED) ──────────────────────────────
    ("cracked_shell",    "Cracked Shell",    "courses_completed", 1,  "You've broken out of the shell — your first module complete.",    "learning", 1, "cracked_shell"),
    ("fledgling",        "Fledgling",        "courses_completed", 3,  "Learning to use your wings — 3 modules down.",                    "learning", 2, "fledgling"),
    ("first_flight",     "First Flight",     "courses_completed", 7,  "You've left the nest — 7 modules complete.",                      "learning", 3, "first_flight"),
    ("gliding",          "Gliding",          "courses_completed", 15, "Effortless momentum — 15 modules behind you.",                    "learning", 4, "gliding"),
    ("full_wingspan",    "Full Wingspan",    "courses_completed", 25, "Fully developed, maximum spread — 25 modules complete.",          "learning", 5, "full_wingspan"),

    # ── Assignment Mastery (ASSIGNMENTS_SUBMITTED) ────────────────────────
    ("eager_talons",     "Eager Talons",     "assignments_submitted", 1,  "Ready to grab knowledge — first assignment submitted.",           "assignment", 1, "eager_talons"),
    ("sharp_claws",      "Sharp Claws",      "assignments_submitted", 5,  "Precision is developing — 5 assignments submitted.",             "assignment", 2, "sharp_claws"),
    ("the_hunter",       "The Hunter",       "assignments_submitted", 10, "Consistent and focused — 10 assignments submitted.",             "assignment", 3, "the_hunter"),
    ("precision_strike", "Precision Strike", "assignments_submitted", 20, "Disciplined execution — 20 assignments submitted.",              "assignment", 4, "precision_strike"),
    ("eagle_eyed",       "Eagle-Eyed",       "assignments_submitted", 35, "Nothing escapes you — 35 assignments submitted.",               "assignment", 5, "eagle_eyed_assign"),

    # ── Consistency (STREAK_DAYS) ─────────────────────────────────────────
    ("morning_wing",     "Morning Wing",     "streak_days", 3,  "Early signs of habit — 3 day streak.",          "streak", 1, "morning_wing"),
    ("thermal_rider",    "Thermal Rider",    "streak_days", 7,  "Riding the updraft — 7 day streak.",            "streak", 2, "thermal_rider"),
    ("wind_walker",      "Wind Walker",      "streak_days", 14, "Moving with purpose — 14 day streak.",          "streak", 3, "wind_walker"),
    ("sky_drifter",      "Sky Drifter",      "streak_days", 30, "Sustained flight — 30 day streak.",             "streak", 4, "sky_drifter"),
    ("eternal_soarer",   "Eternal Soarer",   "streak_days", 60, "Unstoppable rhythm — 60 day streak.",           "streak", 5, "eternal_soarer"),

    # ── Points Milestones (POINTS_THRESHOLD) ─────────────────────────────
    ("hatchling",        "Hatchling",        "points_threshold", 100,   "Life begins — 100 points earned.",               "points", 1, "hatchling"),
    ("nestling",         "Nestling",         "points_threshold", 500,   "Growing stronger — 500 points earned.",          "points", 2, "nestling"),
    ("fledge",           "Fledge",           "points_threshold", 1500,  "Ready to take off — 1,500 points earned.",       "points", 3, "fledge"),
    ("talon_bearer",     "Talon Bearer",     "points_threshold", 5000,  "Power earned — 5,000 points.",                   "points", 4, "talon_bearer"),
    ("sky_sovereign",    "Sky Sovereign",    "points_threshold", 15000, "Commanding presence — 15,000 points.",           "points", 5, "sky_sovereign"),

    # ── Community Voice (COMMUNITY_CONTRIBUTIONS) ─────────────────────────
    ("first_chirp",      "First Chirp",      "community_contributions", 1,   "Breaking silence — first post or comment.",       "community", 1, "first_chirp"),
    ("nest_voice",       "Nest Voice",       "community_contributions", 10,  "Being noticed — 10 contributions.",               "community", 2, "nest_voice"),
    ("flock_caller",     "Flock Caller",     "community_contributions", 25,  "Others listen — 25 contributions.",               "community", 3, "flock_caller"),
    ("eagle_call",       "Eagle Call",       "community_contributions", 50,  "A rallying presence — 50 contributions.",         "community", 4, "eagle_call"),
    ("echo_of_sky",      "Echo of the Sky",  "community_contributions", 100, "Your voice carries far — 100 contributions.",     "community", 5, "echo_of_sky"),

    # ── Quiz Sharpness (QUIZZES_PASSED) ───────────────────────────────────
    ("keen_eye",         "Keen Eye",         "quizzes_passed", 1,  "Awareness awakens — first quiz passed.",               "quiz", 1, "keen_eye"),
    ("focused_gaze",     "Focused Gaze",     "quizzes_passed", 3,  "Locking onto targets — 3 quizzes passed.",             "quiz", 2, "focused_gaze"),
    ("sharp_sight",      "Sharp Sight",      "quizzes_passed", 7,  "Nothing blurry — 7 quizzes passed.",                   "quiz", 3, "sharp_sight"),
    ("predators_vision", "Predator's Vision","quizzes_passed", 15, "Crystal clear judgement — 15 quizzes passed.",         "quiz", 4, "predators_vision"),
    ("raptor_mind",      "Raptor Mind",      "quizzes_passed", 25, "Razor-sharp intellect — 25 quizzes passed.",           "quiz", 5, "raptor_mind"),

    # ── Nest Presence (EVENTS_ATTENDED) ───────────────────────────────────
    ("flock_joiner",     "Flock Joiner",     "events_attended", 1,  "You showed up — first event attended.",                "nest", 1, "flock_joiner"),
    ("nest_regular",     "Nest Regular",     "events_attended", 5,  "A familiar face — 5 events attended.",                 "nest", 2, "nest_regular"),
    ("circle_rider",     "Circle Rider",     "events_attended", 10, "Part of the rhythm — 10 events attended.",             "nest", 3, "circle_rider"),
    ("flock_elder",      "Flock Elder",      "events_attended", 20, "A pillar of the nest — 20 events attended.",           "nest", 4, "flock_elder"),
    ("sentinel",         "Sentinel",         "events_attended", 40, "Guardian of the community — 40 events attended.",      "nest", 5, "sentinel"),

    # ── Special One-Time (ONE_TIME_EVENT) ─────────────────────────────────
    ("egg_cracker",           "Egg Cracker",       "one_time_event", 1, "The journey begins — profile complete.",                  "special", 0, "egg_cracker"),
    ("first_nest_join",       "Found My Nest",     "one_time_event", 1, "Belonging starts here — joined your first Nest.",         "special", 0, "found_my_nest"),
    ("first_resource_share",  "Resource Eagle",    "one_time_event", 1, "Contributing to the flock — first resource shared.",      "special", 0, "resource_eagle"),
    ("mentors_mark",          "Mentor's Mark",     "one_time_event", 1, "Noticed by your mentor — received a manual point award.", "special", 0, "mentors_mark"),
    ("perfect_feathers",      "Perfect Feathers",  "one_time_event", 1, "Flawless execution — scored 100% on a quiz.",             "special", 0, "perfect_feathers"),
    ("early_bird",            "Early Bird",        "one_time_event", 1, "Ahead of the flock — submitted an assignment early.",     "special", 0, "early_bird"),

    # ── Nests Joined Count-Gate (NESTS_JOINED) ────────────────────────────
    ("scout",                 "Scout",             "nests_joined",   3, "Curious explorer — joined 3 different Nests.",            "special", 0, "scout"),

    # ── Elite / Competitive (COMPETITIVE) ────────────────────────────────
    ("thunder_wing",       "Thunder Wing",       "competitive", 1, "#1 on the leaderboard for a full month.",                    "elite", 0, "thunder_wing"),
    ("legend_of_the_nest", "Legend of the Nest", "competitive", 1, "Highest all-time points in a specific Nest.",                "elite", 0, "legend_nest"),
    ("iron_wing",          "Iron Wing",          "competitive", 1, "90-day unbroken streak — very rare.",                        "elite", 0, "iron_wing"),
    ("chosen_eaglet",      "The Chosen Eaglet",  "competitive", 1, "Nominated directly by your Eagle mentor.",                   "elite", 0, "chosen_eaglet"),
    ("sky_sovereign_elite","Sky King / Sky Queen","competitive", 1, "Top 1% of all Eaglets on the platform, recalculated quarterly.", "elite", 0, "sky_sovereign_el"),
]


class Command(BaseCommand):
    help = "Seed all 47 badge records. Safe to run multiple times."

    def handle(self, *args, **options):
        created_count = 0
        updated_count = 0

        for row in BADGES:
            slug, name, criteria_type, criteria_value, description, category, tier, icon_key = row
            icon = make_svg(icon_key, category, tier)

            _, created = Badge.objects.update_or_create(
                slug=slug,
                defaults={
                    "name": name,
                    "criteria_type": criteria_type,
                    "criteria_value": criteria_value,
                    "description": description,
                    "icon": icon,
                },
            )
            if created:
                created_count += 1
            else:
                updated_count += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Done — {created_count} created, {updated_count} updated. "
                f"Total: {Badge.objects.count()} badges."
            )
        )
