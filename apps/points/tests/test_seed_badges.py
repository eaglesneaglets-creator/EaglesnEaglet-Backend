import pytest
from django.core.management import call_command
from apps.points.models import Badge


@pytest.mark.django_db
def test_seed_badges_creates_all_46():
    call_command("seed_badges", verbosity=0)
    assert Badge.objects.count() == 46


@pytest.mark.django_db
def test_seed_badges_is_idempotent():
    call_command("seed_badges", verbosity=0)
    call_command("seed_badges", verbosity=0)
    assert Badge.objects.count() == 46


@pytest.mark.django_db
def test_all_badges_have_slugs():
    call_command("seed_badges", verbosity=0)
    assert not Badge.objects.filter(slug="").exists()


@pytest.mark.django_db
def test_all_badges_have_icons():
    call_command("seed_badges", verbosity=0)
    assert not Badge.objects.filter(icon="").exists()


@pytest.mark.django_db
def test_resource_eagle_badge_removed():
    """Deprecated Eagle-only badge must not exist after seed/migrate."""
    call_command("seed_badges", verbosity=0)
    assert not Badge.objects.filter(slug="first_resource_share").exists()
