"""The token bucket, its key, and the public dependency."""
from typing import Dict, Optional, Tuple

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.testclient import TestClient

from finiex_auth.rate_limiter import RateLimiter, build_rate_limit_dependency, client_key


def _request(peer: Optional[Tuple[str, int]], forwarded_for: Optional[str] = None) -> Request:
    """A bare request as the ASGI server hands it over: the peer, and whatever headers arrived."""
    headers = [(b'x-forwarded-for', forwarded_for.encode())] if forwarded_for else []
    return Request({'type': 'http', 'client': peer, 'headers': headers})


def test_the_limiter_admits_the_configured_rate_and_then_refuses() -> None:
    limiter = RateLimiter(per_minute=3)
    assert [limiter.allow('client-a') for _ in range(4)] == [True, True, True, False]
    # A different client has its own bucket — the limit is per caller, not global.
    assert limiter.allow('client-b') is True
    # Zero disables it: a deployment can turn the limit off without removing the wiring.
    assert all(RateLimiter(per_minute=0).allow('anyone') for _ in range(100))


def test_the_key_is_the_connection_and_a_forged_header_cannot_change_it() -> None:
    """Every caller can write `X-Forwarded-For`, so the key is never read from it.

    A key taken from the header hands a guesser a fresh bucket per attempt. Resolving a trusted
    proxy's header is the ASGI server's job — uvicorn rewrites the peer before this runs — so even a
    loopback peer carrying the header is keyed on the peer here.
    """
    assert client_key(_request(('198.51.100.4', 50000), '6.6.6.6')) == '198.51.100.4'
    assert client_key(_request(('127.0.0.1', 50000), '6.6.6.6, 203.0.113.7')) == '127.0.0.1'
    assert client_key(_request(None)) == 'unknown'


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
