"""
Django Settings Module

Automatically loads the appropriate settings based on DJANGO_ENV environment variable.
Default: local (development)

Usage:
    - Development: DJANGO_ENV=local (or unset)
    - Production: DJANGO_ENV=production
    - Testing: DJANGO_ENV=test (or use --ds flag with pytest)
"""

import os

env = os.environ.get('DJANGO_ENV', 'local')

if env == 'production':
    from .production import *
elif env == 'test':
    from .test import *
else:
    from .local import *
