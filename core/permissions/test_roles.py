"""Unit tests for the admin authorization tier permission classes.

Covers the stacked-admin bug (is_platform_staff without is_staff must pass
IsAdmin) and the scoped-admin vs superadmin tier split.
"""

from types import SimpleNamespace

from core.permissions.roles import IsAdmin, IsPlatformAdmin, IsSuperAdmin


def _req(user):
    return SimpleNamespace(user=user)


def _user(**kw):
    """Build a stand-in user exposing the same attrs the permissions read."""
    defaults = dict(
        is_authenticated=True,
        is_staff=False,
        is_superuser=False,
        is_platform_staff=False,
        role="eaglet",
    )
    defaults.update(kw)
    u = SimpleNamespace(**defaults)
    # is_admin mirrors apps/users/models.py: role==admin OR superuser OR platform_staff
    u.is_admin = (u.role == "admin" or u.is_superuser or u.is_platform_staff)
    return u


def test_scoped_admin_passes_is_admin():
    # Stacked admin: platform_staff, NOT staff, NOT superuser — the bug case.
    u = _user(is_platform_staff=True, role="eagle")
    assert IsAdmin().has_permission(_req(u), None) is True
    assert IsPlatformAdmin().has_permission(_req(u), None) is True


def test_scoped_admin_denied_superadmin():
    u = _user(is_platform_staff=True, role="eagle")
    assert IsSuperAdmin().has_permission(_req(u), None) is False


def test_stacked_mentee_admin_passes_is_admin():
    # Eaglet + platform_staff (plan 22) — same bug shape, mentee base role.
    u = _user(is_platform_staff=True, role="eaglet")
    assert IsAdmin().has_permission(_req(u), None) is True
    assert IsPlatformAdmin().has_permission(_req(u), None) is True
    assert IsSuperAdmin().has_permission(_req(u), None) is False


def test_superuser_passes_all():
    u = _user(is_superuser=True, is_staff=True, role="admin")
    assert IsAdmin().has_permission(_req(u), None) is True
    assert IsPlatformAdmin().has_permission(_req(u), None) is True
    assert IsSuperAdmin().has_permission(_req(u), None) is True


def test_legacy_role_admin_passes_is_admin():
    # role='admin' without staff/superuser flags still counts as admin.
    u = _user(role="admin")
    assert IsAdmin().has_permission(_req(u), None) is True
    assert IsPlatformAdmin().has_permission(_req(u), None) is True


def test_plain_mentee_denied_all():
    u = _user()
    assert IsAdmin().has_permission(_req(u), None) is False
    assert IsPlatformAdmin().has_permission(_req(u), None) is False
    assert IsSuperAdmin().has_permission(_req(u), None) is False


def test_unauthenticated_denied_all():
    u = _user(is_authenticated=False, is_platform_staff=True, is_superuser=True)
    assert IsAdmin().has_permission(_req(u), None) is False
    assert IsPlatformAdmin().has_permission(_req(u), None) is False
    assert IsSuperAdmin().has_permission(_req(u), None) is False
