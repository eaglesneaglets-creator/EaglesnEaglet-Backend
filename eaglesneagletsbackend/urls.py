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
    Health check endpoint for Docker and load balancers.
    Returns 200 OK if the service is healthy.
    """
    from django.db import connection

    health_status = {
        'status': 'healthy',
        'database': 'ok',
        'cache': 'ok',
    }

    # Check database connection
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
    except Exception as e:
        health_status['status'] = 'unhealthy'
        health_status['database'] = str(e)

    # Check Redis connection
    try:
        from django.core.cache import cache
        cache.set('health_check', 'ok', 10)
        cache.get('health_check')
    except Exception as e:
        health_status['cache'] = str(e)
        # Cache failure is not critical
        if health_status['status'] == 'healthy':
            health_status['status'] = 'degraded'

    status_code = 200 if health_status['status'] == 'healthy' else 503
    return JsonResponse(health_status, status=status_code)


# API URL patterns
api_v1_patterns = [
    # Health check
    path('health/', health_check, name='health-check'),

    # Authentication (to be implemented)
    # path('auth/', include('apps.users.urls')),

    # Core app URLs (to be implemented)
    # path('users/', include('apps.users.api_urls')),
    # path('nests/', include('apps.nests.urls')),
    # path('content/', include('apps.content.urls')),
    # path('points/', include('apps.points.urls')),
    # path('chat/', include('apps.chat.urls')),
    # path('store/', include('apps.store.urls')),
    # path('donations/', include('apps.donations.urls')),
    # path('notifications/', include('apps.notifications.urls')),
    # path('analytics/', include('apps.analytics.urls')),
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
