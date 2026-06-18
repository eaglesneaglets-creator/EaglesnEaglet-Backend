"""Tests for scanner-traffic classification and middleware behaviour."""

import pytest
from django.core.cache import cache
from django.test import RequestFactory, override_settings

from core.middleware.logging import RequestLoggingMiddleware
from core.middleware.request_noise import (
    is_platform_path,
    is_probe_path,
    resolve_request_log_level,
    should_skip_request_log,
)
from core.middleware.security import RateLimitByIPMiddleware


@pytest.mark.parametrize(
    'path,expected',
    [
        ('/api/v1/health/', True),
        ('/admin/login/', True),
        ('/static/app.js', True),
        ('/.env', False),
        ('/wp-config.php', False),
        ('/v1/.env', False),
    ],
)
def test_is_platform_path(path, expected):
    assert is_platform_path(path) is expected


@pytest.mark.parametrize(
    'path,expected',
    [
        ('/.env', True),
        ('/v1/.env', True),
        ('/wp-config.php', True),
        ('/var/task/package.json', True),
        ('/api/v1/store/products/', False),
        ('/admin/login/', False),
    ],
)
def test_is_probe_path(path, expected):
    assert is_probe_path(path) is expected


@pytest.mark.parametrize(
    'path,status,level',
    [
        ('/.env', 404, None),
        ('/wp-config.php', 404, None),
        ('/api/v1/missing', 404, 'INFO'),
        ('/api/v1/auth/login', 401, 'WARNING'),
        ('/api/v1/auth/login', 500, 'ERROR'),
        ('/api/v1/health/', 200, 'INFO'),
    ],
)
def test_resolve_request_log_level(path, status, level):
    assert resolve_request_log_level(path, status) == level


def test_should_skip_request_log_only_for_non_platform_404():
    assert should_skip_request_log('/.env', 404) is True
    assert should_skip_request_log('/.env', 403) is False
    assert should_skip_request_log('/api/v1/nope', 404) is False


@override_settings(PROBE_FLOOD_RATE_LIMIT_PER_MIN=3)
def test_probe_flood_rate_limit_returns_429_without_hitting_view():
    cache.clear()
    middleware = RateLimitByIPMiddleware(lambda request: _ok_response())
    factory = RequestFactory()

    for _ in range(3):
        request = factory.get('/.env', HTTP_X_FORWARDED_FOR='203.0.113.10')
        response = middleware(request)
        assert response.status_code == 200

    request = factory.get('/.env', HTTP_X_FORWARDED_FOR='203.0.113.10')
    response = middleware(request)
    assert response.status_code == 429
    import json
    payload = json.loads(response.content)
    assert payload['error']['code'] == 429


@override_settings(PROBE_FLOOD_RATE_LIMIT_PER_MIN=2)
def test_platform_paths_not_probe_flood_limited():
    cache.clear()
    middleware = RateLimitByIPMiddleware(lambda request: _ok_response())
    factory = RequestFactory()

    for _ in range(5):
        request = factory.get('/api/v1/health/', HTTP_X_FORWARDED_FOR='203.0.113.11')
        response = middleware(request)
        assert response.status_code == 200


def test_request_logging_middleware_skips_scanner_404_logs(caplog):
    import logging

    caplog.set_level(logging.INFO, logger='apps')
    middleware = RequestLoggingMiddleware(lambda request: _not_found_response())
    factory = RequestFactory()

    request = factory.get('/.env')
    request.user = type('User', (), {'id': None})()
    middleware.process_request(request)
    middleware.process_response(request, _not_found_response())

    assert 'Request error' not in caplog.text
    assert 'Request not found' not in caplog.text


def test_request_logging_middleware_logs_api_404_at_info(caplog):
    import logging

    caplog.set_level(logging.INFO, logger='apps')
    middleware = RequestLoggingMiddleware(lambda request: _not_found_response())
    factory = RequestFactory()

    request = factory.get('/api/v1/does-not-exist')
    request.user = type('User', (), {'id': None})()
    middleware.process_request(request)
    middleware.process_response(request, _not_found_response())

    assert 'Request not found' in caplog.text


def _ok_response():
    from django.http import HttpResponse

    return HttpResponse('ok', status=200)


def _not_found_response():
    from django.http import HttpResponse

    return HttpResponse('not found', status=404)
