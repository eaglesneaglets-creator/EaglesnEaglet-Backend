"""WebSocket connect authorization.

Phase 26-01 stopped suspended accounts at the HTTP auth layer
(`CookieJWTAuthentication.get_user` → 403 AccountSuspended) precisely because
per-view permissions could be bypassed. **WebSockets never went through that
layer**, so a suspended or deactivated user holding a still-valid access token
could keep reading and sending live chat, and keep receiving notifications,
until the token expired.

Confirmed by probe before this test existed:

    HTTP  /api/v1/chat/conversations/  as suspended → 403 AccountSuspended
    WS    /ws/chat/<conv>/             as suspended → ACCEPTED

These tests pin both consumers. The IDOR cases are included because they are the
other half of the contract and were verified sound — keeping them here means a
future refactor of the auth path can't silently drop them either.
"""
import pytest
from asgiref.sync import sync_to_async
from channels.routing import URLRouter
from channels.testing import WebsocketCommunicator
from rest_framework_simplejwt.tokens import AccessToken

from apps.chat.routing import websocket_urlpatterns
from apps.chat.models import Conversation
from apps.users.models import User

APP = URLRouter(websocket_urlpatterns)

# Consumer close codes.
UNAUTHENTICATED = 4001
NOT_A_PARTICIPANT = 4003


def _user(email, **kw):
    return User.objects.create_user(
        email=email, password="x", first_name="T", last_name="U", **kw
    )


async def _connect(path):
    comm = WebsocketCommunicator(APP, path)
    connected, detail = await comm.connect()
    await comm.disconnect()
    return connected, detail


@sync_to_async
def _set_fields(user, **fields):
    """ORM writes must leave the async context (SynchronousOnlyOperation)."""
    for k, v in fields.items():
        setattr(user, k, v)
    user.save(update_fields=list(fields))


@sync_to_async
def _make_user(email, **kw):
    return _user(email, **kw)


@pytest.fixture
def conversation(db):
    a = _user("ws-a@test.local", role="eagle")
    b = _user("ws-b@test.local", role="eagle")
    conv = Conversation.objects.create(conversation_type="direct")
    conv.participants.add(a, b)
    return conv, a, b


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_participant_can_connect(conversation):
    conv, a, _ = conversation
    connected, _ = await _connect(f"/ws/chat/{conv.id}/?token={AccessToken.for_user(a)}")
    assert connected, "a legitimate participant must be able to connect"


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_anonymous_and_forged_tokens_rejected(conversation):
    conv, _, _ = conversation
    assert (await _connect(f"/ws/chat/{conv.id}/"))[0] is False
    assert (await _connect(f"/ws/chat/{conv.id}/?token=not.a.jwt"))[0] is False


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_non_participant_cannot_subscribe(conversation):
    """IDOR guard: a valid user must not read a conversation they're not in."""
    conv, _, _ = conversation
    outsider = await _make_user("ws-outsider@test.local", role="eagle")
    connected, code = await _connect(
        f"/ws/chat/{conv.id}/?token={AccessToken.for_user(outsider)}"
    )
    assert connected is False
    assert code == NOT_A_PARTICIPANT


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_suspended_user_cannot_connect_to_chat(conversation):
    """The bug: HTTP returns 403 for this user, WS used to accept them."""
    conv, a, _ = conversation
    token = str(AccessToken.for_user(a))  # issued BEFORE suspension, still valid
    await _set_fields(a, status="suspended")

    connected, code = await _connect(f"/ws/chat/{conv.id}/?token={token}")
    assert connected is False, "suspended account must not hold a live chat socket"
    assert code == UNAUTHENTICATED


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_deactivated_user_cannot_connect_to_chat(conversation):
    conv, a, _ = conversation
    token = str(AccessToken.for_user(a))
    await _set_fields(a, is_active=False)

    connected, _ = await _connect(f"/ws/chat/{conv.id}/?token={token}")
    assert connected is False, "deactivated account must not hold a live chat socket"


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_suspended_user_cannot_connect_to_notifications(conversation):
    """Same flaw, second consumer — fixing only chat would leave this open."""
    _, a, _ = conversation
    token = str(AccessToken.for_user(a))
    await _set_fields(a, status="suspended")

    connected, _ = await _connect(f"/ws/notifications/?token={token}")
    assert connected is False


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_deactivated_user_cannot_connect_to_notifications(conversation):
    _, a, _ = conversation
    token = str(AccessToken.for_user(a))
    await _set_fields(a, is_active=False)

    connected, _ = await _connect(f"/ws/notifications/?token={token}")
    assert connected is False
