"""WebSocket message rate limiting.

Measured before this existed: a single authenticated socket sent **50 chat
messages in 0.44s and all 50 persisted**. WebSocket frames never pass through
DRF's throttling, so the HTTP rate limits did not apply. One client could fill
the messages table as fast as the network allowed and fan every write out to the
whole conversation group.
"""
import time

import pytest
from asgiref.sync import sync_to_async
from channels.routing import URLRouter
from channels.testing import WebsocketCommunicator
from rest_framework_simplejwt.tokens import AccessToken

from apps.chat.models import Conversation, Message
from apps.chat.routing import websocket_urlpatterns
from apps.users.models import User
from core.ws_throttle import RateLimitExceeded, TokenBucket

APP = URLRouter(websocket_urlpatterns)


# ── Unit: the bucket itself ────────────────────────────────────────────────

def test_bucket_allows_a_burst_up_to_capacity():
    b = TokenBucket(capacity=5, rate=1)
    for _ in range(5):
        b.consume()          # must not raise
    with pytest.raises(RateLimitExceeded):
        b.consume()


def test_bucket_refills_over_time():
    b = TokenBucket(capacity=2, rate=100)  # 100/s → refills fast enough to test
    b.consume()
    b.consume()
    with pytest.raises(RateLimitExceeded):
        b.consume()
    time.sleep(0.05)                        # ~5 tokens' worth
    b.consume()                             # must not raise


def test_bucket_never_exceeds_capacity_when_idle():
    b = TokenBucket(capacity=3, rate=1000)
    time.sleep(0.02)                        # would over-refill if uncapped
    for _ in range(3):
        b.consume()
    with pytest.raises(RateLimitExceeded):
        b.consume()


def test_retry_after_is_reported():
    b = TokenBucket(capacity=1, rate=2)     # 0.5s per token
    b.consume()
    with pytest.raises(RateLimitExceeded) as exc:
        b.consume()
    assert 0 < exc.value.retry_after <= 0.5


def test_allows_is_a_non_raising_variant():
    b = TokenBucket(capacity=1, rate=1)
    assert b.allows() is True
    assert b.allows() is False


# ── Integration: the consumer enforces it ──────────────────────────────────

@sync_to_async
def _make_conversation():
    a = User.objects.create_user(email="thr-a@test.local", password="x",
                                 first_name="T", last_name="A", role="eagle")
    b = User.objects.create_user(email="thr-b@test.local", password="x",
                                 first_name="T", last_name="B", role="eagle")
    conv = Conversation.objects.create(conversation_type="direct")
    conv.participants.add(a, b)
    return conv, a


@sync_to_async
def _count(conv):
    return Message.objects.filter(conversation=conv).count()


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_flood_is_throttled_and_reported():
    """THE REGRESSION: 50 rapid messages used to persist all 50."""
    conv, sender = await _make_conversation()
    comm = WebsocketCommunicator(
        APP, f"/ws/chat/{conv.id}/?token={AccessToken.for_user(sender)}"
    )
    connected, _ = await comm.connect()
    assert connected

    for i in range(50):
        await comm.send_json_to({"type": "chat.message", "content": f"flood-{i}"})

    # Drain whatever the server sent back.
    rate_limited = 0
    for _ in range(60):
        try:
            frame = await comm.receive_json_from(timeout=0.4)
        except Exception:
            break
        if frame.get("code") == "rate_limited":
            rate_limited += 1

    stored = await _count(conv)
    # Tearing down a socket that is mid-throttle can surface a CancelledError
    # from the test harness itself; it says nothing about the behaviour asserted
    # below. Note CancelledError derives from BaseException, so `except
    # Exception` does NOT catch it.
    try:
        await comm.disconnect()
    except BaseException:
        pass

    assert stored < 50, f"throttle did not engage — {stored}/50 messages persisted"
    assert rate_limited > 0, "client was never told it was rate limited"


@pytest.mark.django_db(transaction=True)
@pytest.mark.asyncio
async def test_normal_conversation_is_unaffected():
    """The limit must not punish ordinary use — a few messages must all land."""
    conv, sender = await _make_conversation()
    comm = WebsocketCommunicator(
        APP, f"/ws/chat/{conv.id}/?token={AccessToken.for_user(sender)}"
    )
    await comm.connect()

    for i in range(5):
        await comm.send_json_to({"type": "chat.message", "content": f"hello {i}"})
    for _ in range(5):
        try:
            await comm.receive_json_from(timeout=1)
        except Exception:
            break

    assert await _count(conv) == 5
    await comm.disconnect()
