"""
Django Local Development Settings

Use this for local development only.
Run with: python manage.py runserver --settings=eaglesneagletsbackend.settings.local
"""

from .base import *
from decouple import config, Csv

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY', default='django-insecure-local-dev-key-change-in-production')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1,0.0.0.0,backend', cast=Csv())

# Frontend URL for email links
FRONTEND_URL = config('FRONTEND_URL', default='http://localhost:5173')

# Support email
SUPPORT_EMAIL = config('SUPPORT_EMAIL', default='support@eaglesneaglets.com')


# Database - PostgreSQL for development (mirrors production)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME', default='eaglesneaglets_dev'),
        'USER': config('DB_USER', default='postgres'),
        'PASSWORD': config('DB_PASSWORD', default='postgres'),
        'HOST': config('DB_HOST', default='localhost'),
        'PORT': config('DB_PORT', default='5432'),
        'CONN_MAX_AGE': 60,
        'OPTIONS': {
            'connect_timeout': 10,
        },
    }
}


# Redis Cache - IGNORE_EXCEPTIONS allows graceful fallback when Redis is unavailable
# (e.g., running locally without Docker). Throttling and caching will be disabled
# but the app won't crash.
DJANGO_REDIS_IGNORE_EXCEPTIONS = True
DJANGO_REDIS_LOG_IGNORED_EXCEPTIONS = True

CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': config('REDIS_URL', default='redis://localhost:6379/0'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'IGNORE_EXCEPTIONS': True,
        }
    }
}


# Channel Layers for WebSocket
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [config('REDIS_URL', default='redis://localhost:6379/0')],
        },
    },
}


# CORS Settings - Allow all in development
CORS_ALLOWED_ORIGINS = config(
    'CORS_ALLOWED_ORIGINS',
    default='http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000,http://localhost',
    cast=Csv()
)
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = config('CORS_ALLOW_ALL_ORIGINS', default=False, cast=bool)


# Email Configuration
# Use SMTP if EMAIL_HOST is configured with REAL credentials, otherwise fall back to console
EMAIL_HOST = config('EMAIL_HOST', default='')
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')

# Only use SMTP if we have real credentials (not placeholder values)
_has_real_credentials = (
    EMAIL_HOST and
    EMAIL_HOST_USER and
    EMAIL_HOST_PASSWORD and
    'your-' not in EMAIL_HOST_USER.lower() and
    'your-' not in EMAIL_HOST_PASSWORD.lower() and
    '@example' not in EMAIL_HOST_USER.lower()
)

if _has_real_credentials:
    EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
    EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
    EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
    EMAIL_USE_SSL = config('EMAIL_USE_SSL', default=False, cast=bool)
    EMAIL_TIMEOUT = config('EMAIL_TIMEOUT', default=30, cast=int)
    # Use the actual Gmail address as sender (Gmail requires this)
    DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default=EMAIL_HOST_USER)
    # For display name, you can use: "Eagles & Eaglets <email>"
    if DEFAULT_FROM_EMAIL and '@' in DEFAULT_FROM_EMAIL and 'Eagles' not in DEFAULT_FROM_EMAIL:
        DEFAULT_FROM_EMAIL = f'Eagles & Eaglets <{EMAIL_HOST_USER}>'
else:
    # Fall back to console for development without valid email config
    EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
    DEFAULT_FROM_EMAIL = 'noreply@eaglesneaglets.com'
    if EMAIL_HOST:
        import logging
        logging.getLogger(__name__).warning(
            'EMAIL_HOST is configured but credentials appear to be placeholders. '
            'Using console email backend. Update EMAIL_HOST_USER and EMAIL_HOST_PASSWORD '
            'in .env with real credentials to enable SMTP.'
        )


# Celery - Run tasks synchronously in development
CELERY_BROKER_URL = config('REDIS_URL', default='redis://localhost:6379/0')
CELERY_RESULT_BACKEND = config('REDIS_URL', default='redis://localhost:6379/0')
CELERY_TASK_ALWAYS_EAGER = True  # Run tasks synchronously


# Debug Toolbar (optional)
if DEBUG:
    INSTALLED_APPS += ['debug_toolbar']
    MIDDLEWARE.insert(0, 'debug_toolbar.middleware.DebugToolbarMiddleware')
    INTERNAL_IPS = ['127.0.0.1']


# Simplified logging for development
LOGGING['handlers']['console']['level'] = 'DEBUG'
LOGGING['root']['level'] = 'DEBUG'


# Disable throttling in development
REST_FRAMEWORK['DEFAULT_THROTTLE_CLASSES'] = []


# Allow browsable API in development
REST_FRAMEWORK['DEFAULT_RENDERER_CLASSES'] = [
    'rest_framework.renderers.JSONRenderer',
    'rest_framework.renderers.BrowsableAPIRenderer',
]


# Longer token lifetime for development convenience
SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'] = timedelta(hours=1)
SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'] = timedelta(days=30)


# Security settings relaxed for development
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False


# Google OAuth 2.0 Settings
GOOGLE_OAUTH2_CLIENT_ID = config('GOOGLE_OAUTH2_CLIENT_ID', default='')
GOOGLE_OAUTH2_CLIENT_SECRET = config('GOOGLE_OAUTH2_CLIENT_SECRET', default='')
GOOGLE_OAUTH2_REDIRECT_URI = config('GOOGLE_OAUTH2_REDIRECT_URI', default='http://localhost:5173/auth/google/callback')
