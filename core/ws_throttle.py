"""Per-connection rate limiting for WebSocket consumers.

HTTP endpoints are throttled by DRF (`DEFAULT_THROTTLE_RATES`), but WebSocket
frames never touch that machinery. Measured before this existed: **50 chat
messages accepted and persisted in 0.44s** from a single socket, with no limit —
one client could fill the messages table as fast as the network allowed, and fan
every write out to every other participant in the group.

Implemented as an in-memory token bucket on the consumer instance:

* A bucket per *connection* is the right granularity — the socket is already
  authenticated and bound to one user, so there is no key to forge, and state
  dies with the connection (no cleanup task, no Redis round-trip per frame).
* A user can still open several sockets. That is deliberate: this caps the
  cheap, high-volume abuse path. Capping a user across connections needs shared
  state (Redis) and is worth adding only if abuse is seen in practice.

Bursts are allowed because real typing is bursty — the bucket refills
continuously, so sustained rate is what is actually capped.
"""

import time


class RateLimitExceeded(Exception):
    """Raised when a connection exceeds its allowance."""

    def __init__(self, retry_after: float):
        self.retry_after = retry_after
        super().__init__(
            f"Rate limit exceeded. Try again in {retry_after:.1f}s."
        )


class TokenBucket:
    """Allow `capacity` events immediately, refilling at `rate` per second.

    Example: ``TokenBucket(capacity=10, rate=1)`` permits a burst of 10 messages
    and then one per second — comfortable for a human typing, restrictive for a
    script.
    """

    __slots__ = ("capacity", "rate", "_tokens", "_last")

    def __init__(self, capacity: int, rate: float):
        self.capacity = float(capacity)
        self.rate = float(rate)
        self._tokens = float(capacity)
        self._last = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

    def consume(self, amount: float = 1.0) -> None:
        """Take one token, or raise ``RateLimitExceeded``."""
        self._refill()
        if self._tokens < amount:
            deficit = amount - self._tokens
            raise RateLimitExceeded(retry_after=deficit / self.rate)
        self._tokens -= amount

    def allows(self, amount: float = 1.0) -> bool:
        """Non-raising variant, for callers that prefer a boolean."""
        try:
            self.consume(amount)
            return True
        except RateLimitExceeded:
            return False


#: Chat sending. A burst of 10 covers natural typing; 1/s sustained is far above
#: human throughput but ~40x below what an unthrottled script achieved.
CHAT_MESSAGE_BUCKET = dict(capacity=10, rate=1.0)

#: Read receipts are cheap but still hit the DB; allow a wider burst.
CHAT_READ_BUCKET = dict(capacity=20, rate=2.0)
