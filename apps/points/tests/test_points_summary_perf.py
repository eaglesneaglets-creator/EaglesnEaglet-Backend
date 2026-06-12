"""
Tests for the consolidated + cached points summary (perf audit B1/B2).

Behavior contract (must not change):
  * total_points / breakdown / badge_count / rank / streak_days semantics
  * rank: 1-indexed among eaglets, 0 when user has 0 points
  * streak: consecutive days ending today or yesterday, else 0

Perf contract (new):
  * summary computes in <= 4 queries (was 6)
  * summary is cached per-user (second call: 0 queries)
  * cache invalidates when a new PointTransaction or UserBadge lands
"""

from datetime import timedelta

import pytest
from django.core.cache import cache
from django.utils import timezone

from apps.points.models import PointTransaction
from apps.points.services import PointService


@pytest.fixture(autouse=True)
def _clear_cache():
    cache.clear()
    yield
    cache.clear()


def _txn(user, points, days_ago=0):
    t = PointTransaction.objects.create(
        user=user, points=points, activity_type='assignment',
        source=PointTransaction.Source.AUTO, description='t',
    )
    if days_ago:
        PointTransaction.objects.filter(pk=t.pk).update(
            created_at=timezone.now() - timedelta(days=days_ago)
        )
    return t


@pytest.mark.django_db
class TestSummaryCorrectness:
    def test_summary_fields(self, user_factory):
        u = user_factory(email='s1@t.local', role='eaglet')
        _txn(u, 30)
        _txn(u, 20)
        cache.clear()  # txn signals may have warmed/cleared — start clean

        s = PointService.get_user_points_summary(u)
        assert s['total_points'] == 50
        assert s['breakdown'] == {'assignment': 50}
        assert s['badge_count'] >= 0
        assert s['rank'] == 1
        assert s['streak_days'] == 1  # both txns today

    def test_rank_ordering(self, user_factory):
        u1 = user_factory(email='r1@t.local', role='eaglet')
        u2 = user_factory(email='r2@t.local', role='eaglet')
        u3 = user_factory(email='r3@t.local', role='eaglet')
        _txn(u1, 30); _txn(u2, 20); _txn(u3, 10)
        cache.clear()

        assert PointService.get_user_rank(u1) == 1
        assert PointService.get_user_rank(u2) == 2
        assert PointService.get_user_rank(u3) == 3

    def test_rank_zero_points(self, user_factory):
        u = user_factory(email='r0@t.local', role='eaglet')
        assert PointService.get_user_rank(u) == 0

    def test_streak_consecutive_days(self, user_factory):
        u = user_factory(email='st@t.local', role='eaglet')
        _txn(u, 5, days_ago=0)
        _txn(u, 5, days_ago=1)
        _txn(u, 5, days_ago=4)  # gap — breaks the streak
        cache.clear()
        assert PointService.get_user_streak(u) == 2

    def test_streak_stale_returns_zero(self, user_factory):
        u = user_factory(email='st0@t.local', role='eaglet')
        _txn(u, 5, days_ago=3)
        cache.clear()
        assert PointService.get_user_streak(u) == 0


@pytest.mark.django_db
class TestSummaryPerf:
    def test_summary_query_budget(self, user_factory, django_assert_max_num_queries):
        u = user_factory(email='qb@t.local', role='eaglet')
        _txn(u, 10); _txn(u, 15)
        cache.clear()

        with django_assert_max_num_queries(4):
            PointService.get_user_points_summary(u)

    def test_summary_cached_second_call(self, user_factory, django_assert_num_queries):
        u = user_factory(email='cc@t.local', role='eaglet')
        _txn(u, 10)
        cache.clear()

        first = PointService.get_user_points_summary(u)
        with django_assert_num_queries(0):
            second = PointService.get_user_points_summary(u)
        assert first == second

    def test_cache_invalidated_on_new_txn(self, user_factory):
        u = user_factory(email='inv@t.local', role='eaglet')
        _txn(u, 10)
        cache.clear()

        assert PointService.get_user_points_summary(u)['total_points'] == 10
        _txn(u, 5)  # post_save signal must invalidate
        assert PointService.get_user_points_summary(u)['total_points'] == 15
