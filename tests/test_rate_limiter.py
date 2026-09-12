"""The token bucket, its key, and the public dependency."""
from typing import Dict

from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient

from finiex_auth.rate_limiter import RateLimiter, build_rate_limit_dependency, client_key


def test_the_limiter_admits_the_configured_rate_and_then_refuses() -> None:
    limiter = RateLimiter(per_minute=3)
    assert [limiter.allow('client-a') for _ in range(4)] == [True, True, True, False]
    # A different client has its own bucket — the limit is per caller, not global.
    assert limiter.allow('client-b') is True
    # Zero disables it: a deployment can turn the limit off without removing the wiring.
    assert all(RateLimiter(per_minute=0).allow('anyone') for _ in range(100))


def test_the_bucket_is_keyed_on_the_originating_client_not_the_proxy() -> None:
    """Behind a reverse proxy every request arrives from 127.0.0.1.

    Keying on the peer would put every caller in the world into one bucket — a global limit wearing
    the costume of a per-client one, which fails exactly when several consumers are active.
    """
    assert client_key('203.0.113.7, 70.41.3.18', '127.0.0.1') == '203.0.113.7'
    assert client_key(None, '127.0.0.1') == '127.0.0.1'
    assert client_key('', None) == 'unknown'


def test_the_public_dependency_answers_429_with_retry_after() -> None:
    router = APIRouter(dependencies=[Depends(build_rate_limit_dependency(RateLimiter(1)))])

    @router.get('/health')
    def health() -> Dict[str, str]:
        return {'status': 'ok'}

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    assert client.get('/health').status_code == 200
    throttled = client.get('/health')
    assert throttled.status_code == 429
    assert throttled.headers['retry-after'] == '60'
    assert throttled.json()['detail'] == 'Too many requests'
