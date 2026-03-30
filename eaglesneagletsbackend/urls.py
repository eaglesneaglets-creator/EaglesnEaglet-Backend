"""
URL configuration for eaglesneagletsbackend project.
"""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.http import JsonResponse
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView


def health_check(request):
    """
    Deep health check: verifies DB and Redis connectivity.
    Returns 200 only when ALL dependencies are reachable.
    Returns 503 when any dependency is down — Railway will restart the service.
    Used by Docker HEALTHCHECK and Railway's healthcheck probe.
    """
    import logging
    from django.db import connection
    from django.core.cache import cache

    logger = logging.getLogger(__name__)
    db_ok = False
    redis_ok = False

    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
        db_ok = True
    except Exception as e:
        logger.error("Health check: DB unreachable: %s", e)

    try:
        cache.set('health_ping', '1', timeout=5)
        redis_ok = cache.get('health_ping') == '1'
    except Exception as e:
        logger.error("Health check: Redis unreachable: %s", e)

    status = 'ok' if (db_ok and redis_ok) else 'degraded'
    http_status = 200 if (db_ok and redis_ok) else 503

    return JsonResponse(
        {'status': status, 'db': db_ok, 'redis': redis_ok},
        status=http_status,
    )


# API URL patterns
api_v1_patterns = [
    # Health check
    path('health/', health_check, name='health-check'),

    # Authentication
    path('auth/', include('apps.users.urls')),

    # Core app URLs
    path('nests/', include('apps.nests.urls')),
    path('content/', include('apps.content.urls')),
    path('points/', include('apps.points.urls')),
    path('chat/', include('apps.chat.urls')),
    path('store/', include('apps.store.urls')),
    # path('donations/', include('apps.donations.urls')),
    path('notifications/', include('apps.notifications.urls')),
    path('analytics/', include('apps.analytics.urls')),
]

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),

    # API v1
    path('api/v1/', include(api_v1_patterns)),

    # API Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

    # Debug toolbar
    try:
        import debug_toolbar
        urlpatterns = [
            path('__debug__/', include(debug_toolbar.urls)),
        ] + urlpatterns
    except ImportError:
        pass
