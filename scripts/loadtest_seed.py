"""
Load-test seed script (TEMPORARY — local only).

Creates a realistic-but-bounded dataset so the stress test exercises real
query paths (N+1s, missing indexes) instead of empty tables.

    Seed:     python scripts/loadtest_seed.py
    Teardown: python scripts/loadtest_seed.py --teardown

All seeded rows are tagged by the email prefix LT_PREFIX so teardown is exact.
NOT for production. Idempotent: re-running tops up to the target counts.
"""
import os
import sys
import random

import django

# Ensure the project root (parent of this scripts/ dir) is importable so the
# settings package resolves regardless of the cwd the script is launched from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eaglesneagletsbackend.settings.local')
django.setup()

from django.contrib.auth import get_user_model  # noqa: E402
from django.db import transaction  # noqa: E402
from django.utils.text import slugify  # noqa: E402

from apps.nests.models import Nest  # noqa: E402
from apps.points.models import PointTransaction  # noqa: E402

User = get_user_model()

LT_PREFIX = 'lt_'           # email tag for all seeded users
N_EAGLES = 50               # mentors (each owns a nest)
N_EAGLETS = 450             # mentees
PWD = 'LoadTest123!'        # placeholder — local only, not a real credential


def teardown():
    qs = User.objects.filter(email__startswith=LT_PREFIX)
    n = qs.count()
    # PointTransaction + Nest cascade off the user FK.
    qs.delete()
    print(f'Teardown: removed {n} seeded users (+ cascaded nests/points).')


@transaction.atomic
def seed():
    existing = User.objects.filter(email__startswith=LT_PREFIX).count()
    print(f'Existing seeded users: {existing}')

    eagles = []
    for i in range(N_EAGLES):
        email = f'{LT_PREFIX}eagle{i}@loadtest.local'
        u, created = User.objects.get_or_create(
            email=email,
            defaults=dict(
                first_name=f'Eagle{i}', last_name='LT', role='eagle',
                is_email_verified=True, is_active=True, status='active',
            ),
        )
        if created:
            u.set_password(PWD)
        u.status = 'active'  # ensure login passes the status gate
        u.save()
        eagles.append(u)
    print(f'Eagles ready: {len(eagles)}')

    # One nest per eagle.
    nests = []
    for i, eagle in enumerate(eagles):
        nest, _ = Nest.objects.get_or_create(
            slug=slugify(f'{LT_PREFIX}nest-{i}'),
            defaults=dict(
                name=f'LoadTest Nest {i}', eagle=eagle,
                description='Seeded nest for load testing.',
                is_active=True,
            ),
        )
        nests.append(nest)
    print(f'Nests ready: {len(nests)}')

    eaglets = []
    for i in range(N_EAGLETS):
        email = f'{LT_PREFIX}eaglet{i}@loadtest.local'
        u, created = User.objects.get_or_create(
            email=email,
            defaults=dict(
                first_name=f'Eaglet{i}', last_name='LT', role='eaglet',
                is_email_verified=True, is_active=True, status='active',
            ),
        )
        if created:
            u.set_password(PWD)
        u.status = 'active'  # ensure login passes the status gate
        u.save()
        eaglets.append(u)
    print(f'Eaglets ready: {len(eaglets)}')

    # Point transactions — spread across eaglets so leaderboard/level compute
    # has real volume to aggregate (this is where N+1 / missing-index pain shows).
    target_txns = 5000
    have = PointTransaction.objects.filter(user__email__startswith=LT_PREFIX).count()
    to_make = max(0, target_txns - have)
    bulk = []
    for _ in range(to_make):
        user = random.choice(eaglets)
        nest = random.choice(nests)
        bulk.append(PointTransaction(
            user=user, nest=nest, points=random.randint(5, 100),
            activity_type='assignment', source=PointTransaction.Source.AUTO,
            description='Seeded points.',
        ))
    if bulk:
        PointTransaction.objects.bulk_create(bulk, batch_size=1000)
    print(f'Point transactions: +{to_make} (total now '
          f'{PointTransaction.objects.filter(user__email__startswith=LT_PREFIX).count()})')

    print('\nSeed complete.')
    print(f'Login for load test: {LT_PREFIX}eaglet0@loadtest.local / {PWD}')


if __name__ == '__main__':
    if '--teardown' in sys.argv:
        teardown()
    else:
        seed()
