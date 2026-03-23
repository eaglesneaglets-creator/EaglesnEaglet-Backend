#!/bin/sh
set -e

echo "=== Starting Celery Worker ==="
exec celery -A eaglesneagletsbackend worker --loglevel=info --concurrency=2
