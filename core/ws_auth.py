"""Shared WebSocket JWT authentication.

THE single place a WebSocket resolves a token to a user. Both consumers
(`apps.chat`, `apps.notifications`) delegate here.

Why this file exists
--------------------
Phase 26-01 moved suspension enforcement into the HTTP auth layer
(`core.authentication.CookieJWTAuthentication.get_user`) rather than a
permission class, because DRF's per-view ``permission_classes`` fully REPLACE
the defaults and ~87 views would have bypassed a permission-layer check.

WebSockets never pass through that layer. Each consumer had its own
``_authenticate`` that validated the token signature and loaded the user — but
checked neither ``status`` nor ``is_active``. The result was a hole in the
suspension contract, verified by probe:

    HTTP  /api/v1/chat/conversations/  as suspended → 403 AccountSuspended
    WS    /ws/chat/<conversation>/     as suspended → CONNECTED

so a suspended or deactivated account kept a live chat socket, and kept
receiving notifications, until its 15-minute access token expired.

Keeping this in one function means the two consumers cannot drift apart — a
third consumer should import this rather than write its own.
"""

import logging

from channels.db import database_sync_to_async
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import AccessToken

logger = logging.getLogger(__name__)

#: Close code for "token missing, invalid, or belongs to an account that may not
#: connect". Deliberately identical for all three: a client that cannot connect
#: should not learn *why* from the close code, and the frontend already routes
#: 4001 to re-authentication.
WS_UNAUTHENTICATED = 4001


def token_from_scope(scope) -> str | None:
    """Read the JWT from ``?token=`` or the httpOnly ``access_token`` cookie.

    Cross-origin WebSocket upgrades (frontend and backend on different Railway
    subdomains, both in the Public Suffix List) cause Chrome to drop cookies even
    with SameSite=None, so the query-string token is the reliable path.
    """
    from urllib.parse import parse_qs

    qs = parse_qs(scope.get("query_string", b"").decode())
    if token := qs.get("token", [None])[0]:
        return token
    return scope.get("cookies", {}).get("access_token")


@database_sync_to_async
def _load_active_user(user_id):
    """Return the user only if the account is permitted to hold a connection.

    Mirrors the HTTP contract: a valid signature is not sufficient. Tokens
    outlive a suspension by up to their 15-minute lifetime, so the account state
    must be re-read from the database on every handshake.
    """
    from apps.users.models import User

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return None

    if not user.is_active:
        logger.warning("WS auth rejected: user %s is inactive", user_id)
        return None
    if getattr(user, "status", None) == "suspended":
        logger.warning("WS auth rejected: user %s is suspended", user_id)
        return None
    return user


async def authenticate_ws(scope):
    """Resolve the scope's JWT to a connectable user, or ``None``.

    ``None`` means "close with WS_UNAUTHENTICATED" — the caller decides how.
    """
    token_str = token_from_scope(scope)
    if not token_str:
        return None

    try:
        token = AccessToken(token_str)
        user_id = token["user_id"]
    except (InvalidToken, TokenError):
        return None
    except Exception:
        logger.exception("Unexpected error decoding WebSocket token")
        return None

    return await _load_active_user(user_id)
