"""
Django Production Settings

SECURITY HARDENED for production deployment.
Run with: DJANGO_SETTINGS_MODULE=eaglesneagletsbackend.settings.production
"""

from .base import *
from decouple import config, Csv
import dj_database_url
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration
from sentry_sdk.integrations.redis import RedisIntegration
from sentry_sdk.integrations.celery import CeleryIntegration

# SECURITY: Must be set via environment variable
SECRET_KEY = config('SECRET_KEY')

DEBUG = False

_allowed_hosts = config('ALLOWED_HOSTS', cast=Csv(), default='')
ALLOWED_HOSTS = [h for h in _allowed_hosts if h] + [
    'healthcheck.railway.app',
    '.up.railway.app',
]
if not any(h for h in ALLOWED_HOSTS if h not in ('healthcheck.railway.app', '.up.railway.app')):
    import warnings
    warnings.warn(
        "ALLOWED_HOSTS env var is not set. Add your Railway backend domain to ALLOWED_HOSTS.",
        RuntimeWarning,
        stacklevel=2,
    )


# =============================================================================
# DATABASE - PostgreSQL with Connection Pooling
# =============================================================================
# Railway (and most PaaS providers) inject DATABASE_URL as a single connection
# string. We parse it first; individual DB_* vars are the fallback for
# environments that configure the connection piece-by-piece.
_database_url = config('DATABASE_URL', default=None)

if _database_url:
    DATABASES = {
        'default': dj_database_url.parse(
            _database_url,
            conn_max_age=600,
            conn_health_checks=True,
            ssl_require=True,
        )
    }
    DATABASES['default']['OPTIONS'] = {
        'connect_timeout': 10,
        'options': '-c statement_timeout=30000',
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': config('PGDATABASE', default=config('DB_NAME', default='postgres')),
            'USER': config('PGUSER', default=config('DB_USER', default='postgres')),
            'PASSWORD': config('PGPASSWORD', default=config('DB_PASSWORD', default='')),
            'HOST': config('PGHOST', default=config('DB_HOST', default='localhost')),
            'PORT': config('PGPORT', default=config('DB_PORT', default='5432')),
            'CONN_MAX_AGE': 600,
            'CONN_HEALTH_CHECKS': True,
            'OPTIONS': {
                'connect_timeout': 10,
                'options': '-c statement_timeout=30000',
            },
        }
    }

# Database connection pooling with pgBouncer (if using)
# DATABASES['default']['OPTIONS']['options'] = '-c search_path=public'


# =============================================================================
# REDIS CACHE - Production Configuration
# =============================================================================
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': config('REDIS_URL', default='redis://localhost:6379'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'SOCKET_CONNECT_TIMEOUT': 5,
            'SOCKET_TIMEOUT': 5,
            'RETRY_ON_TIMEOUT': True,
            'MAX_CONNECTIONS': 50,
            'CONNECTION_POOL_KWARGS': {'max_connections': 50},
        },
        'KEY_PREFIX': 'eaglesneaglets',
    },
    'sessions': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': config('REDIS_URL', default='redis://localhost:6379'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'DB': 1,
        },
        'KEY_PREFIX': 'session',
    },
}

# Use Redis for sessions
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'sessions'


# =============================================================================
# CHANNEL LAYERS - WebSocket
# =============================================================================
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            'hosts': [config('REDIS_URL', default='redis://localhost:6379')],
            'capacity': 1500,
            'expiry': 10,
        },
    },
}


# =============================================================================
# CELERY - Background Tasks
# =============================================================================
CELERY_BROKER_URL = config('REDIS_URL', default='redis://localhost:6379')
CELERY_RESULT_BACKEND = config('REDIS_URL', default='redis://localhost:6379')
CELERY_TASK_ALWAYS_EAGER = False
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True


# =============================================================================
# SECURITY SETTINGS - PRODUCTION HARDENED
# =============================================================================

# HTTPS Settings
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
# Exempt the health check endpoint from SSL redirect so Railway's internal
# health checker (which hits the container directly over HTTP) gets a 200
# instead of a 301, which would cause the healthcheck to fail.
SECURE_REDIRECT_EXEMPT = [r'^api/v1/health/$']

# HSTS (HTTP Strict Transport Security)
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Cookie Security
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 900  # 15 minutes

CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Lax'
CSRF_TRUSTED_ORIGINS = config('CSRF_TRUSTED_ORIGINS', cast=Csv(), default='')

# Content Security
SECURE_CONTENT_TYPE_NOSNIFF = True
# SECURE_BROWSER_XSS_FILTER removed — deprecated; CSP in SecurityHeadersMiddleware provides protection
X_FRAME_OPTIONS = 'DENY'

# Referrer Policy
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Permissions Policy
PERMISSIONS_POLICY = {
    'geolocation': [],
    'microphone': [],
    'camera': [],
}


# =============================================================================
# CORS SETTINGS - Production
# =============================================================================
CORS_ALLOWED_ORIGINS = config('CORS_ALLOWED_ORIGINS', cast=Csv(), default='')
CORS_ALLOW_CREDENTIALS = True
CORS_EXPOSE_HEADERS = ['Content-Disposition']


# =============================================================================
# EMAIL CONFIGURATION
# =============================================================================
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', cast=int, default=587)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', cast=bool, default=True)
EMAIL_USE_SSL = config('EMAIL_USE_SSL', cast=bool, default=False)
EMAIL_TIMEOUT = 30
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='noreply@eaglesneaglets.com')
SERVER_EMAIL = config('SERVER_EMAIL', default='errors@eaglesneaglets.com')


# =============================================================================
# STATIC & MEDIA FILES - AWS S3 or Cloudinary Fallback
# =============================================================================
AWS_ACCESS_KEY_ID = config('AWS_ACCESS_KEY_ID', default=None)
AWS_SECRET_ACCESS_KEY = config('AWS_SECRET_ACCESS_KEY', default=None)
AWS_STORAGE_BUCKET_NAME = config('AWS_STORAGE_BUCKET_NAME', default=None)
AWS_S3_REGION_NAME = config('AWS_S3_REGION_NAME', default='us-east-1')
AWS_S3_CUSTOM_DOMAIN = f'{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com'
AWS_S3_OBJECT_PARAMETERS = {
    'CacheControl': 'max-age=86400',
}
AWS_DEFAULT_ACL = None
AWS_S3_FILE_OVERWRITE = False

CLOUDINARY_API_KEY = config('CLOUDINARY_API_KEY', default='')

if AWS_ACCESS_KEY_ID:
    # Use S3 for static and media in production (Django 5.2+ STORAGES dict)
    STORAGES = {
        "default": {
            "BACKEND": "storages.backends.s3boto3.S3Boto3Storage",
        },
        "staticfiles": {
            "BACKEND": "storages.backends.s3boto3.S3Boto3Storage",
        },
    }
    STATIC_URL = f'https://{AWS_S3_CUSTOM_DOMAIN}/static/'
    MEDIA_URL = f'https://{AWS_S3_CUSTOM_DOMAIN}/media/'
elif CLOUDINARY_API_KEY:
    import cloudinary
    
    CLOUDINARY_STORAGE = {
        'CLOUD_NAME': config('CLOUDINARY_CLOUD_NAME', default=''),
        'API_KEY': CLOUDINARY_API_KEY,
        'API_SECRET': config('CLOUDINARY_API_SECRET', default=''),
    }

    cloudinary.config(
        cloud_name=config('CLOUDINARY_CLOUD_NAME', default=''),
        api_key=CLOUDINARY_API_KEY,
        api_secret=config('CLOUDINARY_API_SECRET', default=''),
        secure=True,
    )

    CLOUDINARY_OPTIMIZATION = {
        'fetch_format': 'auto',
        'quality': 'auto',
        'flags': 'progressive',
    }

    # Django 5.2+ STORAGES dict — replaces deprecated DEFAULT_FILE_STORAGE
    STORAGES = {
        "default": {
            "BACKEND": "cloudinary_storage.storage.MediaCloudinaryStorage",
        },
        "staticfiles": {
            "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
        },
    }

    CLOUDINARY_FOLDERS = {
        'profile_pictures': 'eaglesneaglets/images/profile_pictures',
        'government_ids': 'eaglesneaglets/documents/government_ids',
        'cvs': 'eaglesneaglets/documents/cvs',
        'recommendations': 'eaglesneaglets/documents/recommendations',
        'videos': 'eaglesneaglets/videos',
        'content_images': 'eaglesneaglets/images/content',
        'store_images': 'eaglesneaglets/images/store',
        'misc': 'eaglesneaglets/misc',
    }


# =============================================================================
# ERROR MONITORING - Sentry
# =============================================================================
SENTRY_DSN = config('SENTRY_DSN', default=None)

if SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[
            DjangoIntegration(),
            RedisIntegration(),
            CeleryIntegration(),
        ],
        traces_sample_rate=0.1,
        profiles_sample_rate=0.1,
        send_default_pii=False,
        environment='production',
    )


# =============================================================================
# ADMINS - Error notification
# =============================================================================
ADMINS = [
    ('Admin', config('ADMIN_EMAIL', default='admin@eaglesneaglets.com')),
]
MANAGERS = ADMINS


# =============================================================================
# LOGGING — Production: structured output for Railway log aggregation
# =============================================================================
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {message}',
            'style': '{',
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'mail_admins': {
            'level': 'ERROR',
            'class': 'django.utils.log.AdminEmailHandler',
            'filters': ['require_debug_false'],
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'django.security': {
            'handlers': ['console', 'mail_admins'],
            'level': 'WARNING',
            'propagate': False,
        },
        'apps': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'celery': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}


# =============================================================================
# PERFORMANCE OPTIMIZATIONS
# =============================================================================

# Template caching
TEMPLATES[0]['OPTIONS']['loaders'] = [
    ('django.template.loaders.cached.Loader', [
        'django.template.loaders.filesystem.Loader',
        'django.template.loaders.app_directories.Loader',
    ]),
]
del TEMPLATES[0]['APP_DIRS']


# =============================================================================
# PAYSTACK CONFIGURATION
# =============================================================================
PAYSTACK_SECRET_KEY = config('PAYSTACK_SECRET_KEY', default='')
PAYSTACK_PUBLIC_KEY = config('PAYSTACK_PUBLIC_KEY', default='')


# =============================================================================
# GOOGLE OAUTH 2.0 SETTINGS
# =============================================================================
GOOGLE_OAUTH2_CLIENT_ID = config('GOOGLE_OAUTH2_CLIENT_ID', default='')
GOOGLE_OAUTH2_CLIENT_SECRET = config('GOOGLE_OAUTH2_CLIENT_SECRET', default='')
GOOGLE_OAUTH2_REDIRECT_URI = config('GOOGLE_OAUTH2_REDIRECT_URI', default='')


# =============================================================================
# FRONTEND URL - Required for email verification links
# =============================================================================
FRONTEND_URL = config('FRONTEND_URL', default='')


# =============================================================================
# HEALTH CHECK SETTINGS
# =============================================================================
HEALTH_CHECK_TOKEN = config('HEALTH_CHECK_TOKEN', default=None)
