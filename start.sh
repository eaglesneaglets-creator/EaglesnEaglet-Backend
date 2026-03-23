#!/bin/sh
set -e

echo "=== Running migrations ==="
python manage.py migrate --noinput

echo "=== Creating admin user ==="
python manage.py create_admin || echo "create_admin skipped (already exists or missing env vars)"

echo "=== Seeding badges ==="
python manage.py seed_badges || echo "seed_badges skipped"

echo "=== Starting Daphne ==="
exec daphne -b 0.0.0.0 -p "${PORT:-8000}" eaglesneagletsbackend.asgi:application
