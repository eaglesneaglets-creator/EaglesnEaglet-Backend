"""
Custom Pagination Classes

Standardized pagination for API responses.
"""

from rest_framework.pagination import PageNumberPagination, CursorPagination
from rest_framework.response import Response


class _PageNumberPaginationBase(PageNumberPagination):
    """Base class with consistent response format for page-number pagination."""

    page_size_query_param = 'page_size'

    def get_paginated_response(self, data):
        return Response({
            'success': True,
            'data': data,
            'meta': {
                'pagination': {
                    'count': self.page.paginator.count,
                    'page': self.page.number,
                    'page_size': self.page_size,
                    'total_pages': self.page.paginator.num_pages,
                    'next': self.get_next_link(),
                    'previous': self.get_previous_link(),
                }
            }
        })


class StandardResultsSetPagination(_PageNumberPaginationBase):
    """Standard pagination with configurable page size."""

    page_size = 20
    max_page_size = 100


class LargeResultsSetPagination(_PageNumberPaginationBase):
    """Larger page sizes for bulk operations."""

    page_size = 50
    max_page_size = 500


class CursorResultsSetPagination(CursorPagination):
    """
    Cursor-based pagination for large datasets.
    More efficient for real-time data and infinite scroll.
    """

    page_size = 20
    ordering = '-created_at'
    cursor_query_param = 'cursor'

    def get_paginated_response(self, data):
        return Response({
            'success': True,
            'data': data,
            'meta': {
                'pagination': {
                    'next': self.get_next_link(),
                    'previous': self.get_previous_link(),
                }
            }
        })
