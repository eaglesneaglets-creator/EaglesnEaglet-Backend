"""REST API integration tests for chat."""
import pytest
from rest_framework.test import APIClient

from apps.users.models import User
from apps.nests.models import Nest, NestMembership
from apps.chat.models import Conversation, Message
from apps.chat.services import ChatService


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="eagle@test.com", password="pass123",
        first_name="Eagle", last_name="One",
        role="eagle", is_email_verified=True,
    )


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="eaglet@test.com", password="pass123",
        first_name="Eaglet", last_name="One",
        role="eaglet", is_email_verified=True,
    )


@pytest.fixture
def nest(db, eagle, eaglet):
    n = Nest.objects.create(name="Test Nest", description="desc", eagle=eagle)
    NestMembership.objects.create(nest=n, user=eagle, status="active")
    NestMembership.objects.create(nest=n, user=eaglet, status="active")
    return n


@pytest.fixture(autouse=True)
def _enroll_eaglet_for_gating(db, request):
    """Eaglets need an ACTIVE ProgramEnrollment for chat REST endpoints (plan 14-03).
    These legacy tests predate that gate; auto-create a minimal enrollment."""
    if "eaglet" not in request.fixturenames:
        return
    from apps.nests.models import Nest as _Nest
    from apps.nests.models_program import Program, ProgramEnrollment
    eaglet = request.getfixturevalue("eaglet")
    if ProgramEnrollment.objects.filter(
        mentee=eaglet, status=ProgramEnrollment.Status.ACTIVE,
    ).exists():
        return
    gate_eagle = User.objects.create_user(
        email=f"gate_eagle_{eaglet.id}@t.com", password="p", role="eagle",
    )
    gate_nest = _Nest.objects.create(name="Gate", eagle=gate_eagle)
    prog = Program.objects.create(nest=gate_nest, name="P", status=Program.Status.ACTIVE)
    ProgramEnrollment.objects.create(
        program=prog, mentee=eaglet, status=ProgramEnrollment.Status.ACTIVE,
    )


class TestConversationList:
    def test_unauthenticated_returns_401(self, api_client):
        resp = api_client.get("/api/v1/chat/conversations/")
        assert resp.status_code == 401

    def test_returns_user_conversations(self, api_client, eagle, eaglet):
        ChatService.get_or_create_dm(eagle, eaglet)
        api_client.force_authenticate(user=eagle)
        resp = api_client.get("/api/v1/chat/conversations/")
        assert resp.status_code == 200
        assert len(resp.data["data"]) == 1

    def test_only_own_conversations_returned(self, api_client, eagle, eaglet):
        eagle2 = User.objects.create_user(
            email="eagle2@test.com", password="pass123",
            first_name="Eagle", last_name="Two",
            role="eagle", is_email_verified=True,
        )
        ChatService.get_or_create_dm(eagle, eaglet)
        ChatService.get_or_create_dm(eagle2, eaglet)
        api_client.force_authenticate(user=eagle)
        resp = api_client.get("/api/v1/chat/conversations/")
        assert len(resp.data["data"]) == 1  # only eagle's DM


class TestCreateDM:
    def test_create_dm(self, api_client, eagle, eaglet, nest):
        api_client.force_authenticate(user=eagle)
        resp = api_client.post("/api/v1/chat/conversations/dm/", {
            "user_id": str(eaglet.id)
        })
        assert resp.status_code == 201
        assert resp.data["data"]["conversation_type"] == "direct"

    def test_create_dm_idempotent(self, api_client, eagle, eaglet, nest):
        api_client.force_authenticate(user=eagle)
        resp1 = api_client.post("/api/v1/chat/conversations/dm/", {"user_id": str(eaglet.id)})
        resp2 = api_client.post("/api/v1/chat/conversations/dm/", {"user_id": str(eaglet.id)})
        assert resp1.data["data"]["id"] == resp2.data["data"]["id"]

    def test_cannot_dm_user_outside_allowed_contacts(self, api_client, eagle):
        outsider = User.objects.create_user(
            email="unrelated@test.com", password="pass123", role="eaglet",
        )
        api_client.force_authenticate(user=eagle)

        resp = api_client.post(
            "/api/v1/chat/conversations/dm/", {"user_id": str(outsider.id)}
        )

        assert resp.status_code == 404
        assert not Conversation.objects.filter(participants=eagle).exists()


class TestMessageList:
    def test_get_messages(self, api_client, eagle, eaglet):
        conv = ChatService.get_or_create_dm(eagle, eaglet)
        ChatService.create_message(conv, eagle, "Hello!")
        api_client.force_authenticate(user=eaglet)
        resp = api_client.get(f"/api/v1/chat/conversations/{conv.id}/messages/")
        assert resp.status_code == 200
        assert len(resp.data["data"]) == 1

    def test_non_participant_cannot_get_messages(self, api_client, eagle, eaglet):
        conv = ChatService.get_or_create_dm(eagle, eaglet)
        outsider = User.objects.create_user(
            email="outsider@test.com", password="pass123",
            role="eaglet", is_email_verified=True,
        )
        api_client.force_authenticate(user=outsider)
        resp = api_client.get(f"/api/v1/chat/conversations/{conv.id}/messages/")
        assert resp.status_code == 403


class TestMarkRead:
    def test_mark_conversation_read(self, api_client, eagle, eaglet):
        conv = ChatService.get_or_create_dm(eagle, eaglet)
        ChatService.create_message(conv, eagle, "hi")
        api_client.force_authenticate(user=eaglet)
        resp = api_client.post(f"/api/v1/chat/conversations/{conv.id}/read/")
        assert resp.status_code == 200

    def test_non_participant_cannot_mark_conversation_read(self, api_client, eagle, eaglet):
        conv = ChatService.get_or_create_dm(eagle, eaglet)
        ChatService.create_message(conv, eagle, "private")
        outsider = User.objects.create_user(
            email="read-outsider@test.com", password="pass123", role="eagle",
        )
        api_client.force_authenticate(user=outsider)

        resp = api_client.post(f"/api/v1/chat/conversations/{conv.id}/read/")

        assert resp.status_code == 403


class TestNestConversation:
    def test_get_or_create_nest_conversation(self, api_client, eagle, nest):
        api_client.force_authenticate(user=eagle)
        resp = api_client.get(f"/api/v1/chat/nest/{nest.id}/conversation/")
        assert resp.status_code == 200
        assert resp.data["data"]["conversation_type"] == "nest_group"

    def test_outsider_cannot_view_nest_conversation(self, api_client, nest):
        outsider = User.objects.create_user(
            email="nest-outsider@test.com", password="pass123", role="eagle",
        )
        conversation = ChatService.get_or_create_nest_conversation(nest)
        ChatService.create_message(conversation, nest.eagle, "private nest message")
        api_client.force_authenticate(user=outsider)

        resp = api_client.get(f"/api/v1/chat/nest/{nest.id}/conversation/")

        assert resp.status_code == 404


class TestChattableContacts:
    def test_unauthenticated_returns_401(self, api_client):
        resp = api_client.get("/api/v1/chat/contacts/")
        assert resp.status_code == 401

    def test_eagle_sees_own_eaglets(self, api_client, eagle, eaglet, nest):
        api_client.force_authenticate(user=eagle)
        resp = api_client.get("/api/v1/chat/contacts/")
        assert resp.status_code == 200
        ids = [c["id"] for c in resp.data["data"]]
        assert str(eaglet.id) in ids
        assert str(eagle.id) not in ids  # should not include self

    def test_eaglet_sees_mentors_and_peers(self, api_client, eagle, eaglet, nest):
        # Create a second eaglet in the same nest
        eaglet2 = User.objects.create_user(
            email="eaglet2@test.com", password="pass123",
            first_name="Eaglet", last_name="Two",
            role="eaglet", is_email_verified=True,
        )
        NestMembership.objects.create(nest=nest, user=eaglet2, status="active")

        api_client.force_authenticate(user=eaglet)
        resp = api_client.get("/api/v1/chat/contacts/")
        assert resp.status_code == 200
        ids = [c["id"] for c in resp.data["data"]]
        assert str(eagle.id) in ids      # mentor
        assert str(eaglet2.id) in ids     # peer
        assert str(eaglet.id) not in ids  # should not include self
