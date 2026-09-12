"""The walk: an ungated router must fail it, named routes must be present, the walk must not be empty."""
from typing import Dict

import pytest
from fastapi import APIRouter, Depends, FastAPI, Security
from fastapi.testclient import TestClient

from finiex_auth.bearer_auth import build_bearer_dependency
from finiex_auth.consumer_token_base import ConsumerTokenBase
from finiex_auth.grant_auth import build_grant_dependency
from finiex_auth.route_walk import assert_no_identity_route_is_ungated
from finiex_auth.token_registry import TokenRegistry

_EMPTY = {'Authorization': 'Bearer holds-nothing'}


class _Token(ConsumerTokenBase):
    GRANT_SURFACES = ('bars', 'reports')


def _bars_router() -> APIRouter:
    router = APIRouter()

    @router.get('/brokers/{broker}/symbols/{symbol}/bars')
    def read_bars(broker: str, symbol: str) -> Dict[str, str]:
        return {'broker': broker, 'symbol': symbol}

    return router


def _reports_router() -> APIRouter:
    router = APIRouter()

    @router.get('/reports/runs/{run_id}/portfolio')
    def portfolio(run_id: str) -> Dict[str, str]:
        return {'run': run_id}

    @router.get('/reports/runs')
    def runs() -> Dict[str, str]:
        return {}

    return router


def _app(*, forget_the_reports_scope: bool = False) -> FastAPI:
    tokens = TokenRegistry({'empty': _Token(token='holds-nothing', grants=[])})
    bearer = Depends(build_bearer_dependency(tokens))
    grant = build_grant_dependency(tokens)
    app = FastAPI()
    # The integration shape FiniexTestingIDE uses: the surface declared at include time.
    app.include_router(_bars_router(), dependencies=[bearer, Security(grant, scopes=['bars'])])
    reports_guard = [bearer] if forget_the_reports_scope else [
        bearer, Security(grant, scopes=['reports'])]
    app.include_router(_reports_router(), dependencies=reports_guard)
    return app


def test_a_fully_gated_app_passes_and_reports_its_census() -> None:
    app = _app()
    walked = assert_no_identity_route_is_ungated(
        app, TestClient(app), _EMPTY,
        required=[('/brokers/{broker}/symbols/{symbol}/bars', 'get')])
    assert sorted(walked) == [('/brokers/{broker}/symbols/{symbol}/bars', 'get'),
                              ('/reports/runs/{run_id}/portfolio', 'get')]


def test_a_router_mounted_without_its_scope_is_caught_and_named() -> None:
    """Authenticated but ungated: indistinguishable by reading, visible only by walking."""
    app = _app(forget_the_reports_scope=True)
    with pytest.raises(AssertionError, match=r'GET /reports/runs/\{run_id\}/portfolio answered 200'):
        assert_no_identity_route_is_ungated(app, TestClient(app), _EMPTY)


def test_a_named_route_that_is_not_mounted_fails_the_walk() -> None:
    """A router dropping out would otherwise leave the walk green and the surface unreachable."""
    app = _app()
    with pytest.raises(AssertionError, match='not mounted'):
        assert_no_identity_route_is_ungated(app, TestClient(app), _EMPTY,
                                            required=[('/sweeps/{sweep_id}', 'get')])


def test_an_app_with_no_identity_route_is_a_broken_walk_not_a_pass() -> None:
    app = FastAPI()
    with pytest.raises(AssertionError, match='walk itself is broken'):
        assert_no_identity_route_is_ungated(app, TestClient(app), _EMPTY)
