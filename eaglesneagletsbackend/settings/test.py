"""
Django Test Settings

Optimized for fast test execution.
Run with: pytest --ds=eaglesneagletsbackend.settings.test
"""

import os

import dj_database_url

from .base import *

SECRET_KEY = 'test-secret-key-not-for-production'

DEBUG = False

ALLOWED_HOSTS = ['testserver', 'localhost', '127.0.0.1']

# Hubtel doesn't ship a signature, so HUBTEL_WEBHOOK_SECRET is unset by
# default. The few legacy tests that mock _validate_signature still
# behave correctly because the view's `if secret:` branch is skipped.
# HUBTEL_WEBHOOK_SECRET = ""


# Use SQLite for faster tests (or in-memory PostgreSQL)
_test_database_url = os.environ.get('TEST_DATABASE_URL')
DATABASES = {
    'default': (
        dj_database_url.parse(_test_database_url, conn_max_age=0)
        if _test_database_url
        else {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': ':memory:',
        }
    )
}


# Disable migrations for faster tests
class DisableMigrations:
    def __contains__(self, item):
        return True

    def __getitem__(self, item):
        return None

    def setdefault(self, key, default=None):
        return default


MIGRATION_MODULES = DisableMigrations()


# Use simple password hasher for faster tests
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]


# Disable caching
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}


# Use in-memory channel layer
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer'
    }
}


# Disable throttling for tests.
# DEFAULT_THROTTLE_CLASSES only controls the global default — views that set
# throttle_classes explicitly (e.g. RegisterView) are unaffected.
# Setting very high rates for those scopes neutralises per-view throttles too.
REST_FRAMEWORK['DEFAULT_THROTTLE_CLASSES'] = []
REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']['register'] = '10000/day'
REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']['login'] = '10000/day'
REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']['password_reset'] = '10000/day'


# Celery - Run tasks synchronously in tests (eager=False so retry logic is testable)
CELERY_TASK_ALWAYS_EAGER = False
CELERY_TASK_EAGER_PROPAGATES = False


# Email - Use in-memory backend
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'


# Disable logging during tests
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'handlers': {
        'null': {
            'class': 'logging.NullHandler',
        },
    },
    'root': {
        'handlers': ['null'],
        'level': 'CRITICAL',
    },
}


# Simplified JWT for tests
SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'] = timedelta(hours=1)
SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'] = timedelta(days=7)


# Security settings disabled for tests
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
