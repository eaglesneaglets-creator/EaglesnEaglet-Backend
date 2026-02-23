"""
Eagles & Eaglets Backend Package

This module ensures Celery is loaded when Django starts.
"""

# Import Celery app to ensure it's loaded with Django
from .celery import app as celery_app

__all__ = ('celery_app',)
