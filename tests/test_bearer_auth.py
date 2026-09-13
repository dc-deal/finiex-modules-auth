"""The bearer dependency: one refusal for everything, a well-formed 401, no credential anywhere."""
import logging
from typing import Dict, List, Optional, Tuple

import pytest
from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from finiex_auth.bearer_auth import build_bearer_dependency
from finiex_auth.error_factory import AUTH_ERROR_CODES, ErrorFactory, http_exception
from finiex_auth.rate_limiter import RateLimiter
from finiex_auth.token_registry import TokenRegistry

_TOKEN = 'a-token-that-is-not-a-real-credential'


def _app(limiter: Optional[RateLimiter] = None,
         error_factory: ErrorFactory = http_exception) -> FastAPI:
    router = APIRouter(dependencies=[Depends(build_bearer_dependency(
        TokenRegistry({'ide': _TOKEN}), limiter, error_factory))])

    @router.get('/protected')
    def protected(request: Request) -> Dict[str, str]:
        return {'consumer': request.state.consumer}

    app = FastAPI()
    app.include_router(router)
    return app


def test_a_missing_or_wrong_credential_gets_one_well_formed_401() -> None:
    client = TestClient(_app())
    for header in (None, f'Bearer {_TOKEN}-almost', 'Bearer ', f'Basic {_TOKEN}', _TOKEN):
        response = client.get('/protected',
                              headers={'Authorization': header} if header is not None else {})
        assert response.status_code == 401, header
        assert response.headers['www-authenticate'] == 'Bearer'
        assert response.json()['detail'] == 'Not authenticated'    # one message for every refusal


def test_a_valid_credential_passes_and_names_its_consumer() -> None:
    response = TestClient(_app()).get('/protected', headers={'Authorization': f'Bearer {_TOKEN}'})
    assert response.status_code == 200 and response.json() == {'consumer': 'ide'}


def test_the_credential_never_reaches_a_log_line_or_a_response_body(
        caplog: pytest.LogCaptureFixture) -> None:
    """A token prefix in a log file is a prefix an attacker with the log no longer has to guess."""
    client = TestClient(_app())
    with caplog.at_level(logging.DEBUG):
        accepted = client.get('/protected', headers={'Authorization': f'Bearer {_TOKEN}'})
        rejected = client.get('/protected', headers={'Authorization': f'Bearer {_TOKEN}x'})
    # The client address makes the line actionable; the TestClient connects as 'testclient'.
    assert '[AUTH] rejected GET /protected from testclient' in caplog.text
    for text in (caplog.text, accepted.text, rejected.text):
        assert _TOKEN not in text and _TOKEN[:8] not in text


def test_repeated_failures_are_throttled_and_a_valid_caller_never_is() -> None:
    client = TestClient(_app(limiter=RateLimiter(per_minute=2)))
    codes = [client.get('/protected', headers={'Authorization': 'Bearer wrong'}).status_code
             for _ in range(4)]
    assert codes == [401, 401, 429, 429]
    throttled = client.get('/protected', headers={'Authorization': 'Bearer wrong'})
    assert throttled.headers['retry-after'] == '60'     # a 429 a client can back off on
    assert client.get('/protected',
                      headers={'Authorization': f'Bearer {_TOKEN}'}).status_code == 200


def test_a_cors_preflight_never_reaches_the_dependencies() -> None:
    """A browser's preflight carries no `Authorization` — by specification, not by choice.

    The checks are route dependencies, and an `OPTIONS` never matches a `GET` route: without CORS the
    router answers 405, with `CORSMiddleware` the middleware answers before routing. The package can
    therefore never turn a preflight into a 401; and a cross-origin 401 carries the allow-origin
    header, so the page sees the status rather than an opaque CORS error.
    """
    origin = 'http://viewer.example'
    preflight = {'Origin': origin, 'Access-Control-Request-Method': 'GET',
                 'Access-Control-Request-Headers': 'authorization'}
    assert TestClient(_app()).options('/protected', headers=preflight).status_code == 405
    app = _app()
    app.add_middleware(CORSMiddleware, allow_origins=[origin], allow_methods=['GET'],
                       allow_headers=['Authorization'])
    client = TestClient(app)
    answered = client.options('/protected', headers=preflight)
    assert answered.status_code == 200
    assert answered.headers['access-control-allow-origin'] == origin
    refused = client.get('/protected', headers={'Origin': origin})
    assert refused.status_code == 401
    assert refused.headers['access-control-allow-origin'] == origin


def test_varying_the_forwarded_header_does_not_escape_the_failed_attempt_limit() -> None:
    """The attack the key exists to stop: a fresh `X-Forwarded-For` on every guess.

    Were the key read from the header, each attempt below would open its own bucket and no 429
    would ever come — unlimited guessing behind a limit that looks active.
    """
    client = TestClient(_app(limiter=RateLimiter(per_minute=2)))
    codes: List[int] = []
    for attempt in range(4):
        headers = {'Authorization': 'Bearer wrong', 'X-Forwarded-For': f'198.51.100.{attempt}'}
        codes.append(client.get('/protected', headers=headers).status_code)
    assert codes == [401, 401, 429, 429]


def test_a_consumer_factory_receives_the_headers_a_401_cannot_do_without() -> None:
    calls: List[Tuple[int, str, str, Optional[Dict[str, str]]]] = []

    def recording_factory(status_code: int, error: str, detail: str,
                          headers: Optional[Dict[str, str]] = None) -> Exception:
        calls.append((status_code, error, detail, headers))
        return http_exception(status_code, error, detail, headers)

    TestClient(_app(error_factory=recording_factory)).get('/protected')
    assert calls == [(401, 'unauthenticated', 'Not authenticated', {'WWW-Authenticate': 'Bearer'})]


def test_every_code_a_consumer_can_receive_is_in_the_closed_vocabulary() -> None:
    """A consumer maps these onto its own error contract; an unlisted code would fall through it."""
    codes: List[str] = []

    def recording_factory(status_code: int, error: str, detail: str,
                          headers: Optional[Dict[str, str]] = None) -> Exception:
        codes.append(error)
        return http_exception(status_code, error, detail, headers)

    client = TestClient(_app(limiter=RateLimiter(per_minute=1), error_factory=recording_factory))
    for _ in range(2):
        client.get('/protected', headers={'Authorization': 'Bearer wrong'})
    assert codes == ['unauthenticated', 'rate_limited']
    assert set(codes) <= set(AUTH_ERROR_CODES)
    assert AUTH_ERROR_CODES == ('unauthenticated', 'forbidden', 'rate_limited')
