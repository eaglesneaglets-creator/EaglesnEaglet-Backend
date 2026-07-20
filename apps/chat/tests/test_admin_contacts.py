"""
Admin cross-role messaging (Phase 27-03).

Confirms an admin can see all roles as contacts and start a DM with any of
them. The BE already grants this (ChatService.get_chattable_contacts returns
all active users for role='admin'); these tests lock that contract so a future
refactor can't silently break admin messaging.
"""

import pytest
from rest_framework.test import APIClient

from apps.users.models import User
from apps.chat.services import ChatService


@pytest.fixture
def admin(db):
    return User.objects.create_user(
        email="admin@test.com", password="p", role="admin",
        first_name="Ada", last_name="Admin", is_staff=True, is_email_verified=True,
    )


@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="e1@test.com", password="p", role="eagle",
        first_name="Eve", last_name="Eagle", is_email_verified=True,
    )


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="t1@test.com", password="p", role="eaglet",
        first_name="Tom", last_name="Eaglet", is_email_verified=True,
    )


@pytest.fixture
def other_admin(db):
    return User.objects.create_user(
        email="a2@test.com", password="p", role="admin",
        first_name="Ben", last_name="Boss", is_staff=True, is_email_verified=True,
    )


@pytest.mark.django_db
def test_admin_contacts_include_all_roles(admin, eagle, eaglet, other_admin):
    contacts = ChatService.get_chattable_contacts(admin)
    ids = set(contacts.values_list("id", flat=True))
    assert eagle.id in ids
    assert eaglet.id in ids
    assert other_admin.id in ids
    assert admin.id not in ids  # not self


@pytest.mark.django_db
def test_admin_contacts_endpoint(admin, eagle, eaglet):
    c = APIClient()
    c.force_authenticate(admin)
    resp = c.get("/api/v1/chat/contacts/")
    assert resp.status_code == 200
    payload = resp.json()
    rows = payload.get("data", payload)
    roles = {u["role"] for u in rows}
    assert "eagle" in roles and "eaglet" in roles


@pytest.mark.django_db
def test_admin_can_dm_any_role(admin, eagle, eaglet):
    for target in (eagle, eaglet):
        conv = ChatService.get_or_create_dm(admin, target)
        assert conv is not None
        assert conv.participants.filter(id=admin.id).exists()
        assert conv.participants.filter(id=target.id).exists()
