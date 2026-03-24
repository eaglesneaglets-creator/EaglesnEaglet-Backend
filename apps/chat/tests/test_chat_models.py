"""Tests for chat models."""
import pytest
from django.db.utils import IntegrityError

from apps.users.models import User
from apps.nests.models import Nest
from apps.chat.models import Conversation, Message, MessageRead


@pytest.fixture
def eagle(db):
    return User.objects.create_user(
        email="eagle@test.com", password="pass123",
        first_name="Test", last_name="Eagle",
        role="eagle", is_email_verified=True,
    )


@pytest.fixture
def eaglet(db):
    return User.objects.create_user(
        email="eaglet@test.com", password="pass123",
        first_name="Test", last_name="Eaglet",
        role="eaglet", is_email_verified=True,
    )


@pytest.fixture
def nest(db, eagle):
    return Nest.objects.create(name="Test Nest", description="desc", eagle=eagle)


class TestConversation:
    def test_dm_conversation_creates_with_two_participants(self, eagle, eaglet):
        conv = Conversation.objects.create(conversation_type="direct")
        conv.participants.set([eagle, eaglet])
        assert conv.participants.count() == 2
        assert conv.conversation_type == "direct"

    def test_nest_conversation_links_to_nest(self, eagle, eaglet, nest):
        conv = Conversation.objects.create(
            conversation_type="nest_group", nest=nest
        )
        conv.participants.set([eagle, eaglet])
        assert conv.nest == nest

    def test_conversation_has_uuid_pk(self, eagle, eaglet):
        conv = Conversation.objects.create(conversation_type="direct")
        conv.participants.set([eagle, eaglet])
        assert str(conv.id)  # UUID stringifies


class TestMessage:
    def test_message_create(self, eagle, eaglet):
        conv = Conversation.objects.create(conversation_type="direct")
        conv.participants.set([eagle, eaglet])
        msg = Message.objects.create(conversation=conv, sender=eagle, content="Hello!")
        assert msg.content == "Hello!"
        assert not msg.is_deleted

    def test_soft_delete_message(self, eagle, eaglet):
        conv = Conversation.objects.create(conversation_type="direct")
        conv.participants.set([eagle, eaglet])
        msg = Message.objects.create(conversation=conv, sender=eagle, content="Hi")
        msg.soft_delete()
        # Default manager excludes soft-deleted
        assert Message.objects.filter(id=msg.id).count() == 0
        # all_objects includes it
        assert Message.all_objects.filter(id=msg.id).count() == 1

    def test_message_sender_null_on_user_delete(self, db, eagle, eaglet):
        conv = Conversation.objects.create(conversation_type="direct")
        conv.participants.set([eagle, eaglet])
        msg = Message.objects.create(conversation=conv, sender=eagle, content="Hi")
        eagle.delete()
        msg.refresh_from_db()
        assert msg.sender is None


class TestMessageRead:
    def test_message_read_unique_per_user(self, eagle, eaglet):
        conv = Conversation.objects.create(conversation_type="direct")
        conv.participants.set([eagle, eaglet])
        msg = Message.objects.create(conversation=conv, sender=eagle, content="Hi")
        MessageRead.objects.create(message=msg, user=eaglet)
        with pytest.raises(IntegrityError):
            MessageRead.objects.create(message=msg, user=eaglet)
