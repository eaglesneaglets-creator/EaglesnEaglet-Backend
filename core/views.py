"""
Core API views — cross-cutting endpoints that don't belong to a single app.
"""

import time

import cloudinary
from cloudinary.utils import api_sign_request
from django.views.decorators.cache import cache_page
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .enums import get_all_enums
from .storage import UPLOAD_CONTEXTS, get_folder


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


# Map upload context → cloudinary resource_type. Anything not listed
# defaults to 'auto' so PDFs/docs land as 'raw' automatically.
_CONTEXT_RESOURCE_TYPE = {
    'content_thumbnail': 'image',
    'profile_picture': 'image',
    'store_image': 'image',
}


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def cloudinary_sign_view(request):
    """
    POST /api/v1/uploads/sign/

    Returns short-lived Cloudinary signed upload params so the browser can
    PUT/POST the file directly to Cloudinary — bypassing the BE entirely.
    Replaces the file-through-BE pipeline that hit SSL EOF + 90s retries.

    Request body:
        { "context": "content_thumbnail" | "profile_picture" | ... }

    Response body:
        {
          "cloud_name", "api_key", "timestamp", "signature",
          "folder", "resource_type", "upload_url",
          "use_filename", "unique_filename",
          "max_bytes", "allowed_mime"   ← FE pre-validates against these
        }
    """
    context = request.data.get('context')
    if not context or context not in UPLOAD_CONTEXTS:
        return Response(
            {
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidUploadContext',
                    'message': 'Unknown upload context.',
                    'details': {'allowed': sorted(UPLOAD_CONTEXTS.keys())},
                },
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    rules = UPLOAD_CONTEXTS[context]
    folder = get_folder(rules['folder'])
    resource_type = _CONTEXT_RESOURCE_TYPE.get(context, 'auto')

    # Only params that go into the signature should be passed back to the
    # client in the same shape; if the browser tampers with folder, the
    # signature won't match and Cloudinary rejects the upload.
    timestamp = int(time.time())
    params_to_sign = {
        'timestamp': timestamp,
        'folder': folder,
        'use_filename': 'true',
        'unique_filename': 'true',
    }

    cfg = cloudinary.config()
    signature = api_sign_request(params_to_sign, cfg.api_secret)

    return Response({
        'success': True,
        'data': {
            'cloud_name': cfg.cloud_name,
            'api_key': cfg.api_key,
            'timestamp': timestamp,
            'signature': signature,
            'folder': folder,
            'resource_type': resource_type,
            'use_filename': True,
            'unique_filename': True,
            'upload_url': (
                f'https://api.cloudinary.com/v1_1/{cfg.cloud_name}'
                f'/{resource_type}/upload'
            ),
            'max_bytes': rules['max_bytes'],
            'allowed_mime': sorted(rules['allowed_mime']),
        },
    })
