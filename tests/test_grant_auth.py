"""The grant check: surface from the router, name from the first path parameter, exact compare."""
from typing import Dict, Optional

from fastapi import APIRouter, Depends, FastAPI, Request, Security
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from finiex_auth.consumer_token_base import ConsumerTokenBase
from finiex_auth.error_factory import ErrorFactory, http_exception
from finiex_auth.grant_auth import build_grant_dependency
from finiex_auth.token_registry import TokenRegistry


class _Token(ConsumerTokenBase):
    GRANT_SURFACES = ('reports', 'bars')


class _AppError(Exception):
    """Stands in for a consumer's own error contract (FiniexTestingIDE's ApiException)."""

    def __init__(self, status_code: int, error: str, detail: str,
                 headers: Optional[Dict[str, str]] = None) -> None:
        super().__init__(detail)
        self.status_code, self.error, self.detail, self.headers = status_code, error, detail, headers


def _app(error_factory: ErrorFactory = http_exception) -> FastAPI:
    tokens = TokenRegistry({'narrow': _Token(token='n', grants=['reports:source_health']),
                            'wide': _Token(token='w', grants=['reports:*']),
                            'elsewhere': _Token(token='e', grants=['bars:mt5']),
                            'everything': _Token(token='a', grants=['*'])})

    def stand_in_bearer(request: Request) -> None:
        # The bearer dependency's contract, reduced: it puts the consumer on request.state.
        consumer = request.headers.get('x-consumer')
        if consumer:
            request.state.consumer = consumer

    router = APIRouter(dependencies=[
        Depends(stand_in_bearer),
        Security(build_grant_dependency(tokens, error_factory), scopes=['reports'])])

    @router.get('/reports')
    def listing() -> Dict[str, str]:
        return {'filtered': 'in the handler, not gated'}

    @router.get('/reports/{name}')
    def one(name: str) -> Dict[str, str]:
        return {'name': name}

    @router.get('/reports/{name}/rows/{row_id}')
    def row(name: str, row_id: str) -> Dict[str, str]:
        return {'name': name, 'row': row_id}

    app = FastAPI()
    app.include_router(router)

    @app.exception_handler(_AppError)
    def _render(_request: Request, exc: _AppError) -> JSONResponse:
        return JSONResponse({'error': exc.error, 'detail': exc.detail},
                            status_code=exc.status_code, headers=exc.headers)

    return app


def test_a_held_grant_passes_and_a_missing_one_is_refused_debuggably() -> None:
    client = TestClient(_app())
    assert client.get('/reports/source_health', headers={'x-consumer': 'narrow'}).status_code == 200
    refused = client.get('/reports/cost', headers={'x-consumer': 'narrow'})
    assert refused.status_code == 403
    # 403, not 404, and a body that says what is held — a denial one can debug.
    assert refused.json()['detail'] == ("token 'narrow' does not hold 'reports:cost' · holds: "
                                        'reports:source_health')
    assert client.get('/reports/cost', headers={'x-consumer': 'wide'}).status_code == 200


def test_a_nested_route_is_governed_by_what_it_belongs_to() -> None:
    """First path parameter, not last: entitled to a report, therefore to its rows."""
    client = TestClient(_app())
    assert client.get('/reports/source_health/rows/42',
                      headers={'x-consumer': 'narrow'}).status_code == 200
    assert client.get('/reports/cost/rows/42', headers={'x-consumer': 'narrow'}).status_code == 403


def test_a_collection_route_admits_anyone_entitled_to_some_of_what_it_lists() -> None:
    """Partly entitled reaches the handler, which filters; refusing them would hide what they hold."""
    client = TestClient(_app())
    for consumer in ('narrow', 'wide', 'everything'):
        assert client.get('/reports', headers={'x-consumer': consumer}).status_code == 200, consumer


def test_a_collection_route_refuses_a_caller_holding_nothing_on_its_surface() -> None:
    """The floor beneath the handler's filter: a forgotten filter leaks nothing to this caller."""
    refused = TestClient(_app()).get('/reports', headers={'x-consumer': 'elsewhere'})
    assert refused.status_code == 403
    assert refused.json()['detail'] == "token 'elsewhere' holds nothing on 'reports' · holds: bars:mt5"


def test_with_authentication_off_there_is_no_consumer_to_gate() -> None:
    assert TestClient(_app()).get('/reports/cost').status_code == 200


def test_a_consumer_error_contract_receives_the_code_and_renders_its_own_body() -> None:
    client = TestClient(_app(error_factory=_AppError))
    refused = client.get('/reports/cost', headers={'x-consumer': 'narrow'})
    assert refused.status_code == 403
    assert refused.json()['error'] == 'forbidden'
