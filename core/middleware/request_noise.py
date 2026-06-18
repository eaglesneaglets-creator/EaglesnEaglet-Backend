"""
Classify scanner / junk traffic so middleware can rate-limit and log less.

Public API paths (/api/, /admin/, static) are treated as legitimate platform
traffic. Everything else is typically internet background noise (.env probes,
WordPress scans, etc.).
"""

from __future__ import annotations

import re

# Paths the backend is meant to serve.
PLATFORM_PATH_PREFIXES = (
    '/api/',
    '/admin/',
    '/static/',
    '/media/',
)

# Common automated vulnerability-scan targets (substring or regex).
_PROBE_SUBSTRINGS = (
    '.env',
    'wp-config',
    'wp-json',
    'wp-content',
    'wp_mail',
    '/wp-',
    '/var/task/',
    '/var/www',
    'webmin/',
    'phpmyadmin',
    'phpinfo',
    'docker-compose',
    'serverless.',
    'amplify.',
    'netlify.toml',
    'vercel.json',
    'next.config',
    'nuxt.config',
    'package.json',
    '/webhook',
    '/webhooks/',
    '/trpc/',
    '/threads/',
    '/workspaces/',
    '/waku/',
    '/user/',
    '/test/',
    'mysql.sql',
    'debug.log',
)

_PROBE_REGEXES = (
    r'^/v\d+/',           # /v1/.env — not our /api/v1/ prefix
    r'^/web/',
    r'\.php',
    r'\.ini$',
    r'\.bak$',
    r'\.sql$',
    r'\.yaml$',
    r'\.yml$',
)

_COMPILED_PROBE_REGEXES = tuple(
    re.compile(p, re.IGNORECASE) for p in _PROBE_REGEXES
)


def is_platform_path(path: str) -> bool:
    """True when the path belongs to this Django deployment."""
    return any(path.startswith(prefix) for prefix in PLATFORM_PATH_PREFIXES)


def is_probe_path(path: str) -> bool:
    """True when the path looks like an automated scanner target."""
    lower = path.lower()
    if any(sub in lower for sub in _PROBE_SUBSTRINGS):
        return True
    return any(pattern.search(lower) for pattern in _COMPILED_PROBE_REGEXES)


def should_skip_request_log(path: str, status_code: int) -> bool:
    """
    Suppress middleware logs for junk 404s that would flood Railway log quotas.
    Real API misses (404 under /api/) are still logged at INFO.
    """
    if status_code != 404:
        return False
    if is_platform_path(path):
        return False
    return is_probe_path(path) or not is_platform_path(path)


def resolve_request_log_level(path: str, status_code: int) -> str | None:
    """
    Return logging level name, or None to skip logging entirely.

    Levels:
      - None: do not log (scanner / non-platform 404 noise)
      - ERROR: server failures
      - WARNING: client errors on platform paths
      - INFO: success and benign 404s on /api/
    """
    if should_skip_request_log(path, status_code):
        return None
    if status_code >= 500:
        return 'ERROR'
    if status_code >= 400:
        if status_code == 404 and is_platform_path(path):
            return 'INFO'
        return 'WARNING'
    return 'INFO'


def is_non_platform_path(path: str) -> bool:
    """True for requests outside known platform routes (typical scanner traffic)."""
    return not is_platform_path(path)
