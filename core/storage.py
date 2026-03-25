"""
Cloudinary Storage Helpers

Provides folder-based upload routing so each file type is stored
in its own Cloudinary folder, keeping the media library organized.

Includes built-in optimization: automatic format selection (f_auto),
quality compression (q_auto), and responsive image transformations.
"""

import cloudinary
import cloudinary.uploader
from cloudinary.exceptions import Error as CloudinaryError
from cloudinary.utils import cloudinary_url
from django.conf import settings
from rest_framework.exceptions import ValidationError as DRFValidationError


# Folder map – mirrors CLOUDINARY_FOLDERS in settings
FOLDER_MAP = {
    'profile_pictures': 'eaglesneaglets/images/profile_pictures',
    'government_ids': 'eaglesneaglets/documents/government_ids',
    'cvs': 'eaglesneaglets/documents/cvs',
    'recommendations': 'eaglesneaglets/documents/recommendations',
    'videos': 'eaglesneaglets/videos',
    'content_images': 'eaglesneaglets/images/content',
    'store_images': 'eaglesneaglets/images/store',
    'misc': 'eaglesneaglets/misc',
}

# Image preset configs for different use cases
IMAGE_PRESETS = {
    'thumbnail': {'width': 150, 'height': 150, 'crop': 'fill', 'gravity': 'face'},
    'avatar': {'width': 200, 'height': 200, 'crop': 'fill', 'gravity': 'face'},
    'profile': {'width': 400, 'height': 400, 'crop': 'fill', 'gravity': 'face'},
    'card': {'width': 600, 'height': 400, 'crop': 'fill'},
    'banner': {'width': 1200, 'height': 400, 'crop': 'fill'},
    'content': {'width': 800, 'crop': 'limit'},
    'store': {'width': 600, 'height': 600, 'crop': 'pad', 'background': 'white'},
}


def get_folder(file_type: str) -> str:
    """Return the Cloudinary folder path for a given file type."""
    folders = getattr(settings, 'CLOUDINARY_FOLDERS', FOLDER_MAP)
    return folders.get(file_type, folders.get('misc', 'eaglesneaglets/misc'))


def upload_to_cloudinary(file, file_type: str, **kwargs):
    """
    Upload a file to the correct Cloudinary folder with automatic optimization.

    Args:
        file: The file object (InMemoryUploadedFile or similar).
        file_type: One of the keys in FOLDER_MAP (e.g. 'profile_pictures', 'cvs').
        **kwargs: Extra options passed to cloudinary.uploader.upload.

    Returns:
        dict with 'url', 'secure_url', 'public_id', optimized URLs, and full response.
    """
    folder = get_folder(file_type)

    # Determine resource type based on file_type or extension
    resource_type = 'auto'
    filename = str(file).lower()
    
    if file_type in ('profile_pictures', 'content_images', 'store_images'):
        resource_type = 'image'
    elif file_type == 'videos':
        resource_type = 'video'
    elif (
        filename.endswith('.pdf') or
        file_type in ('cvs', 'government_ids', 'recommendations', 'misc') or
        filename.endswith(('.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx'))
    ):
        resource_type = 'raw'  # PDFs and documents must be 'raw' for direct public URL access

    upload_options = {
        'folder': folder,
        'resource_type': resource_type,
        'use_filename': True,
        'unique_filename': True,
    }

    # Apply image-specific optimizations on upload
    if resource_type == 'image':
        upload_options.update({
            'quality': 'auto',          # Automatic quality optimization
            'fetch_format': 'auto',     # Auto-select best format (WebP/AVIF)
            'flags': 'progressive',     # Progressive loading for JPEGs
        })

    # Apply video-specific optimizations
    if resource_type == 'video':
        upload_options.update({
            'resource_type': 'video',
        })

    upload_options.update(kwargs)

    try:
        result = cloudinary.uploader.upload(file, **upload_options)
    except CloudinaryError as exc:
        import logging
        logging.getLogger(__name__).error("Cloudinary upload error (%s %s): %s", resource_type, file_type, exc)
        raise DRFValidationError(
            detail={"file": "File upload failed. Please check your connection and try again."}
        ) from exc

    public_id = result.get('public_id')

    response = {
        'url': result.get('url'),
        'secure_url': result.get('secure_url'),
        'public_id': public_id,
        'resource_type': result.get('resource_type'),
        'format': result.get('format'),
        'bytes': result.get('bytes'),
        'original_filename': result.get('original_filename'),
        'raw': result,
    }

    # Generate optimized URLs for images
    if resource_type == 'image' and public_id:
        response['optimized_url'] = get_optimized_url(public_id)
        response['thumbnail_url'] = get_optimized_url(public_id, preset='thumbnail')

    # Manual thumbnail upload support
    thumbnail = kwargs.get('thumbnail')
    if thumbnail:
        thumb_result = upload_to_cloudinary(thumbnail, file_type='content_images')
        response['thumbnail_url'] = thumb_result.get('secure_url')

    return response


def get_optimized_url(public_id: str, preset: str = None, **transform_kwargs) -> str:
    """
    Generate an optimized Cloudinary URL for an image.

    Uses f_auto (automatic format) and q_auto (automatic quality) by default.
    Optionally apply a named preset or custom transformations.

    Args:
        public_id: The Cloudinary public_id of the image.
        preset: Optional preset name from IMAGE_PRESETS.
        **transform_kwargs: Additional transformation parameters.

    Returns:
        Optimized secure URL string.
    """
    transformation = {
        'fetch_format': 'auto',
        'quality': 'auto',
    }

    if preset and preset in IMAGE_PRESETS:
        transformation.update(IMAGE_PRESETS[preset])

    transformation.update(transform_kwargs)

    url, _ = cloudinary_url(
        public_id,
        secure=True,
        transformation=[transformation],
    )
    return url


def get_responsive_urls(public_id: str, widths: list = None) -> dict:
    """
    Generate multiple optimized URLs at different widths for responsive images.

    Useful for srcset in frontend <img> tags.

    Args:
        public_id: The Cloudinary public_id.
        widths: List of pixel widths. Defaults to common breakpoints.

    Returns:
        dict mapping width to optimized URL.
    """
    if widths is None:
        widths = [320, 640, 768, 1024, 1280]

    urls = {}
    for w in widths:
        url, _ = cloudinary_url(
            public_id,
            secure=True,
            transformation=[{
                'width': w,
                'crop': 'limit',
                'fetch_format': 'auto',
                'quality': 'auto',
            }],
        )
        urls[w] = url

    return urls


def get_video_thumbnail(public_id: str, width: int = 600, height: int = 400) -> str:
    """
    Generate a thumbnail image from the middle of a video.
    """
    url, _ = cloudinary_url(
        public_id,
        secure=True,
        resource_type="video",
        format="jpg",
        transformation=[{
            'width': width,
            'height': height,
            'crop': 'fill',
            'start_offset': 'auto',
            'quality': 'auto',
        }],
    )
    return url
def get_pdf_thumbnail(public_id: str, width: int = 640, height: int = 800) -> str:
    """
    Generate a thumbnail image from first page of a PDF.
    PDF must be uploaded with resource_type='image' or handled via special transformation.
    Note: Cloudinary handles PDF-to-image if resource_type is 'image' or via specific flags.
    """
    url, _ = cloudinary_url(
        public_id,
        secure=True,
        format='jpg',
        transformation=[{
            'width': width,
            'height': height,
            'crop': 'fill',
            'gravity': 'north',
            'page': 1,
            'quality': 'auto',
        }],
    )
    return url



def delete_from_cloudinary(public_id: str, resource_type: str = 'image'):
    """Delete a file from Cloudinary by its public_id."""
    return cloudinary.uploader.destroy(public_id, resource_type=resource_type)
