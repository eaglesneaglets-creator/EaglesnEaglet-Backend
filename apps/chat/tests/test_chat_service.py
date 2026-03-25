"""Tests for ChatService business logic."""
import pytest
from rest_framework.exceptions import PermissionDenied, ValidationError

from apps.users.models import User
from apps.nests.models import Nest, NestMembership
from apps.chat.models import Conversation, Message, MessageRead
from apps.chat.services import ChatService


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
def eaglet2(db):
    return User.objects.create_user(
        email="eaglet2@test.com", password="pass123",
        first_name="Eaglet", last_name="Two",
        role="eaglet", is_email_verified=True,
    )


@pytest.fixture
def nest(db, eagle, eaglet):
    n = Nest.objects.create(name="Test Nest", description="desc", eagle=eagle)
    NestMembership.objects.create(nest=n, user=eaglet, status="active")
    return n


class TestGetOrCreateDM:
    def test_creates_dm_conversation(self, eagle, eaglet):
        conv = ChatService.get_or_create_dm(eagle, eaglet)
        assert conv.conversation_type == "direct"
        assert conv.participants.filter(id=eagle.id).exists()
        assert conv.participants.filter(id=eaglet.id).exists()

    def test_idempotent_same_users(self, eagle, eaglet):
        conv1 = ChatService.get_or_create_dm(eagle, eaglet)
        conv2 = ChatService.get_or_create_dm(eaglet, eagle)
        assert conv1.id == conv2.id

    def test_cannot_dm_self(self, eagle):
        with pytest.raises(ValidationError):
            ChatService.get_or_create_dm(eagle, eagle)


class TestGetOrCreateNestConversation:
    def test_creates_nest_group(self, eagle, eaglet, nest):
        conv = ChatService.get_or_create_nest_conversation(nest)
        assert conv.conversation_type == "nest_group"
        assert conv.nest == nest

    def test_idempotent(self, eagle, eaglet, nest):
        conv1 = ChatService.get_or_create_nest_conversation(nest)
        conv2 = ChatService.get_or_create_nest_conversation(nest)
        assert conv1.id == conv2.id


class TestCreateMessage:
    def test_create_message_as_participant(self, eagle, eaglet):
        conv = ChatService.get_or_create_dm(eagle, eaglet)
        msg = ChatService.create_message(conv, eagle, "Hello!")
        assert msg.content == "Hello!"
        assert msg.sender == eagle

    def test_non_participant_cannot_send(self, eagle, eaglet, eaglet2):
        conv = ChatService.get_or_create_dm(eagle, eaglet)
        with pytest.raises(PermissionDenied):
            ChatService.create_message(conv, eaglet2, "Hi!")

    def test_empty_content_rejected(self, eagle, eaglet):
        conv = ChatService.get_or_create_dm(eagle, eaglet)
        with pytest.raises(ValidationError):
            ChatService.create_message(conv, eagle, "   ")

    def test_content_too_long_rejected(self, eagle, eaglet):
        conv = ChatService.get_or_create_dm(eagle, eaglet)
        with pytest.raises(ValidationError):
            ChatService.create_message(conv, eagle, "x" * 4001)


class TestGetMessages:
    def test_returns_messages_in_order(self, eagle, eaglet):
        conv = ChatService.get_or_create_dm(eagle, eaglet)
        ChatService.create_message(conv, eagle, "First")
        ChatService.create_message(conv, eaglet, "Second")
        messages = ChatService.get_messages(conv, eagle)
        assert list(messages.values_list("content", flat=True)) == ["First", "Second"]

    def test_soft_deleted_messages_excluded(self, eagle, eaglet):
        conv = ChatService.get_or_create_dm(eagle, eaglet)
        msg = ChatService.create_message(conv, eagle, "To delete")
        msg.soft_delete()
        messages = ChatService.get_messages(conv, eagle)
        assert messages.count() == 0

    def test_cursor_pagination(self, eagle, eaglet):
        conv = ChatService.get_or_create_dm(eagle, eaglet)
        msgs = [ChatService.create_message(conv, eagle, f"msg {i}") for i in range(5)]
        # Get messages before the 4th message
        result = ChatService.get_messages(conv, eagle, before_id=msgs[3].id, limit=10)
        assert result.count() == 3  # msgs 0, 1, 2


class TestMarkRead:
    def test_marks_all_unread_as_read(self, eagle, eaglet):
        conv = ChatService.get_or_create_dm(eagle, eaglet)
        ChatService.create_message(conv, eagle, "hi")
        ChatService.create_message(conv, eagle, "there")
        ChatService.mark_conversation_read(conv, eaglet)
        assert MessageRead.objects.filter(user=eaglet).count() == 2

    def test_idempotent_mark_read(self, eagle, eaglet):
        conv = ChatService.get_or_create_dm(eagle, eaglet)
        ChatService.create_message(conv, eagle, "hi")
        ChatService.mark_conversation_read(conv, eaglet)
        ChatService.mark_conversation_read(conv, eaglet)  # should not raise
        assert MessageRead.objects.filter(user=eaglet).count() == 1
