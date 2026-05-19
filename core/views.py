"""
Core API views — cross-cutting endpoints that don't belong to a single app.
"""

from django.views.decorators.cache import cache_page
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .enums import get_all_enums


@cache_page(60 * 60)  # 1 hour — enums change at deploy time only
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def enums_view(request):
    """
    GET /api/v1/enums/

    Returns every status enum FE consumes + UI semantic groupings.
    Source of truth: core/enums.py.

    FE consumes via useEnums() hook and falls back to bundled defaults
    if this endpoint is unreachable.
    """
    return Response({
        'success': True,
        'data': get_all_enums(),
    })
