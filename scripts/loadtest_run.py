"""
Async load harness (local only) — ramps concurrency against a running Daphne
and reports p50/p95/p99 latency + error rate per endpoint at each step.

    python scripts/loadtest_run.py

Targets the authenticated read-heavy endpoints the static audit flagged:
  /points/my/        (5-query summary + O(n^2) rank)
  /points/leaderboard/  (per-request rank scan)
  /notifications/    (list)
  /auth/me/          (access_status compute)
  /points/transactions/

Auth: one cookie login up front (CookieJWTAuthentication), cookie jar reused —
mirrors a real session and avoids the login throttle skewing the run.
"""
import asyncio
import statistics
import time

import httpx

BASE = 'http://127.0.0.1:8000/api/v1'
LOGIN_EMAIL = 'lt_eaglet0@loadtest.local'
LOGIN_PWD = 'LoadTest123!'

ENDPOINTS = [
    ('GET', '/points/my/'),
    ('GET', '/points/leaderboard/'),
    ('GET', '/notifications/'),
    ('GET', '/auth/me/'),
    ('GET', '/points/transactions/'),
]

RAMP = [50, 200, 500]      # concurrent in-flight requests per step
REQUESTS_PER_STEP = 1500   # total requests issued per step


async def login():
    """Return cookies dict from a fresh login."""
    async with httpx.AsyncClient(base_url=BASE, timeout=30) as c:
        r = await c.post('/auth/login/', json={'email': LOGIN_EMAIL, 'password': LOGIN_PWD})
        r.raise_for_status()
        return dict(r.cookies)


async def one_request(client, sem, method, path, results):
    async with sem:
        t0 = time.perf_counter()
        try:
            r = await client.request(method, path)
            dt = (time.perf_counter() - t0) * 1000
            results.append((path, r.status_code, dt))
        except Exception as exc:  # noqa: BLE001 - capture any failure as an error sample
            dt = (time.perf_counter() - t0) * 1000
            results.append((path, f'ERR:{type(exc).__name__}', dt))


async def run_step(cookies, concurrency):
    sem = asyncio.Semaphore(concurrency)
    results = []
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    async with httpx.AsyncClient(base_url=BASE, cookies=cookies, timeout=30, limits=limits) as client:
        tasks = []
        for i in range(REQUESTS_PER_STEP):
            method, path = ENDPOINTS[i % len(ENDPOINTS)]
            tasks.append(one_request(client, sem, method, path, results))
        t0 = time.perf_counter()
        await asyncio.gather(*tasks)
        wall = time.perf_counter() - t0
    return results, wall


def pct(vals, p):
    if not vals:
        return 0.0
    vals = sorted(vals)
    k = int(round((p / 100) * (len(vals) - 1)))
    return vals[k]


def report_step(concurrency, results, wall):
    total = len(results)
    ok = [d for (_, s, d) in results if s == 200]
    bad = [(s, d) for (_, s, d) in results if s != 200]
    lat = [d for (_, s, d) in results if s == 200]
    err_rate = 100 * len(bad) / total if total else 0
    rps = total / wall if wall else 0

    print(f'\n== Concurrency {concurrency} ==============================')
    print(f'  requests {total} | wall {wall:.1f}s | throughput {rps:.0f} req/s | errors {err_rate:.1f}%')
    if lat:
        print(f'  latency ms  p50 {pct(lat,50):.0f}  p95 {pct(lat,95):.0f}  '
              f'p99 {pct(lat,99):.0f}  max {max(lat):.0f}')
    # per-endpoint p95
    by_ep = {}
    for path, s, d in results:
        if s == 200:
            by_ep.setdefault(path, []).append(d)
    for path, ds in sorted(by_ep.items()):
        print(f'    {path:<28} n={len(ds):<5} p95 {pct(ds,95):.0f}ms  mean {statistics.mean(ds):.0f}ms')
    if bad:
        codes = {}
        for s, _ in bad:
            codes[s] = codes.get(s, 0) + 1
        print(f'  error codes: {codes}')


async def main():
    print('Logging in…')
    cookies = await login()
    print(f'Auth cookies: {list(cookies)}')
    print(f'Endpoints under test: {[p for _, p in ENDPOINTS]}')

    for concurrency in RAMP:
        results, wall = await run_step(cookies, concurrency)
        report_step(concurrency, results, wall)


if __name__ == '__main__':
    asyncio.run(main())
