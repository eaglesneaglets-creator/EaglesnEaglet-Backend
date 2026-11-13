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
from . import object_storage
from .storage import UPLOAD_CONTEXTS, allowed_formats_for, get_folder

# Contexts the browser may upload DIRECTLY to Cloudinary. Direct uploads are
# public 'upload'-type assets, so sensitive identity documents (government IDs,
# CVs, recommendation letters) are deliberately excluded: they must go through
# the server-side KYC endpoints, which store them as private 'authenticated'
# assets readable only via short-lived signed URLs.
DIRECT_UPLOAD_CONTEXTS = frozenset(UPLOAD_CONTEXTS) - {
    'government_id', 'recommendation_letter', 'cv',
}


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
    if not context or context not in DIRECT_UPLOAD_CONTEXTS:
        return Response(
            {
                'success': False,
                'error': {
                    'code': 400,
                    'type': 'InvalidUploadContext',
                    'message': 'Unknown upload context.',
                    'details': {'allowed': sorted(DIRECT_UPLOAD_CONTEXTS)},
                },
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    rules = UPLOAD_CONTEXTS[context]
    folder = get_folder(rules['folder'])
    resource_type = _CONTEXT_RESOURCE_TYPE.get(context, 'auto')

    if object_storage.is_enabled():
        return _sign_bucket_upload(request, rules, folder)

    # Only params that go into the signature should be passed back to the
    # client in the same shape; if the browser tampers with folder, the
    # signature won't match and Cloudinary rejects the upload.
    timestamp = int(time.time())
    params_to_sign = {
        'timestamp': timestamp,
        'folder': folder,
        'use_filename': 'true',
        'unique_filename': 'true',
        # Server-enforced type allowlist: Cloudinary rejects any other format
        # even if the browser skips the client-side MIME check.
        'allowed_formats': allowed_formats_for(rules['allowed_mime']),
    }

    cfg = cloudinary.config()
    signature = api_sign_request(params_to_sign, cfg.api_secret)
    # Everything the browser must send back verbatim (besides file, api_key
    # and signature). FE appends this dict as-is so the two never drift.
    signed_params = {k: str(v) for k, v in params_to_sign.items()}

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
            'signed_params': signed_params,
            'max_bytes': rules['max_bytes'],
            'allowed_mime': sorted(rules['allowed_mime']),
        },
    })


def _sign_bucket_upload(request, rules, folder):
    """Presigned PUT for a direct browser upload to the S3 bucket.

    The browser declares the file's name, MIME type and size; all three are
    validated against the context rules and then baked into the signature
    (Content-Type + Content-Length are signed headers), so a different or
    larger file is rejected by the bucket itself.
    """
    def bad(message):
        return Response(
            {'success': False, 'error': {'code': 400, 'type': 'InvalidUpload', 'message': message}},
            status=status.HTTP_400_BAD_REQUEST,
        )

    content_type = str(request.data.get('content_type') or '').strip().lower()
    filename = str(request.data.get('filename') or 'file')
    try:
        size = int(request.data.get('size'))
    except (TypeError, ValueError):
        return bad('File size is required.')

    if content_type not in rules['allowed_mime']:
        return bad('This file type is not allowed for this upload.')
    if size <= 0 or size > rules['max_bytes']:
        return bad(f"File too large. Max {rules['max_bytes'] // (1024 * 1024)} MB for this upload.")

    key = object_storage.build_key(folder, filename)
    return Response({
        'success': True,
        'data': {
            'provider': 's3',
            'method': 'PUT',
            'upload_url': object_storage.presigned_put(key, content_type, size),
            'headers': {'Content-Type': content_type},
            'key': key,
            'file_url': object_storage.media_url(key),
            'resource_type': content_type.split('/', 1)[0],
            'max_bytes': rules['max_bytes'],
            'allowed_mime': sorted(rules['allowed_mime']),
        },
    })


def media_redirect_view(request, path):
    """
    GET /api/v1/media/<path>

    Stable public URL for a bucket object. The bucket is private, so this
    redirects to a short-lived signed URL. Only the ``public/`` prefix is
    reachable: identity documents under ``private/`` can never be served here.
    A plain Django view (no DRF) so page loads full of images are not throttled.
    """
    from django.http import Http404, HttpResponseNotAllowed, HttpResponseRedirect

    if request.method not in ('GET', 'HEAD'):
        return HttpResponseNotAllowed(['GET', 'HEAD'])
    if not object_storage.is_configured():
        raise Http404
    if not path or '..' in path or path.startswith('/') or chr(92) in path or len(path) > 512:
        raise Http404
    key = object_storage.PUBLIC_PREFIX + path
    response = HttpResponseRedirect(object_storage.presigned_get(key))
    # Let the browser reuse the redirect for most of the signed URL's life.
    response['Cache-Control'] = f'public, max-age={object_storage.PUBLIC_URL_TTL - 600}'
    return response
