import pytest
from django.core.management import call_command
from apps.points.models import Badge, UserBadge
from apps.points.services import PointService


@pytest.fixture(autouse=True)
def seed(db):
    call_command("seed_badges", verbosity=0)


@pytest.fixture
def eaglet(db):
    from apps.users.models import User
    return User.objects.create_user(
        email="eaglet@test.com", password="pass", role="eaglet"
    )


@pytest.mark.django_db
def test_points_threshold_badge_awarded(eaglet):
    """Hatchling badge (100 pts) awarded when total hits threshold."""
    from apps.points.models import PointTransaction
    PointTransaction.objects.create(
        user=eaglet, points=100, activity_type="check_in"
    )
    PointService.check_and_award_badges(eaglet)
    assert UserBadge.objects.filter(user=eaglet, badge__slug="hatchling").exists()


@pytest.mark.django_db
def test_duplicate_badge_not_awarded_twice(eaglet):
    """Awarding twice does not create duplicate UserBadge rows."""
    from apps.points.models import PointTransaction
    PointTransaction.objects.create(user=eaglet, points=100, activity_type="check_in")
    PointService.check_and_award_badges(eaglet)
    PointService.check_and_award_badges(eaglet)
    assert UserBadge.objects.filter(user=eaglet, badge__slug="hatchling").count() == 1


@pytest.mark.django_db
def test_get_badge_progress_points(eaglet):
    from apps.points.models import PointTransaction
    PointTransaction.objects.create(user=eaglet, points=50, activity_type="check_in")
    badge = Badge.objects.get(slug="hatchling")
    progress = PointService.get_badge_progress(eaglet, badge)
    assert progress == 50


@pytest.mark.django_db
def test_badge_serializer_progress_field(eaglet, rf):
    """BadgeSerializer returns correct progress for current user."""
    from apps.points.serializers import BadgeSerializer
    from apps.points.models import PointTransaction
    PointTransaction.objects.create(user=eaglet, points=50, activity_type="check_in")
    badge = Badge.objects.get(slug="hatchling")
    request = rf.get("/")
    request.user = eaglet
    data = BadgeSerializer(badge, context={"request": request}).data
    assert data["progress"] == 50
    assert data["earned"] is False
    assert "slug" in data
