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
    def test_create_dm(self, api_client, eagle, eaglet):
        api_client.force_authenticate(user=eagle)
        resp = api_client.post("/api/v1/chat/conversations/dm/", {
            "user_id": str(eaglet.id)
        })
        assert resp.status_code == 201
        assert resp.data["data"]["conversation_type"] == "direct"

    def test_create_dm_idempotent(self, api_client, eagle, eaglet):
        api_client.force_authenticate(user=eagle)
        resp1 = api_client.post("/api/v1/chat/conversations/dm/", {"user_id": str(eaglet.id)})
        resp2 = api_client.post("/api/v1/chat/conversations/dm/", {"user_id": str(eaglet.id)})
        assert resp1.data["data"]["id"] == resp2.data["data"]["id"]


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


class TestNestConversation:
    def test_get_or_create_nest_conversation(self, api_client, eagle, nest):
        api_client.force_authenticate(user=eagle)
        resp = api_client.get(f"/api/v1/chat/nest/{nest.id}/conversation/")
        assert resp.status_code == 200
        assert resp.data["data"]["conversation_type"] == "nest_group"
