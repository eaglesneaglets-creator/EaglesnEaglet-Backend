import pytest
from django.core.cache import cache
from django.http import JsonResponse
from django.test import RequestFactory, override_settings

from core.middleware.security import RateLimitByIPMiddleware


@pytest.mark.django_db
@override_settings(SENSITIVE_RATE_LIMIT_PER_MIN=1)
def test_sensitive_rate_limit_returns_429_with_retry_after():
    cache.clear()
    middleware = RateLimitByIPMiddleware(lambda _request: JsonResponse({"ok": True}))
    factory = RequestFactory()

    first = middleware(factory.post("/api/v1/auth/login/"))
    limited = middleware(factory.post("/api/v1/auth/login/"))

    assert first.status_code == 200
    assert limited.status_code == 429
    assert limited["Retry-After"] == "60"
