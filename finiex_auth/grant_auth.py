"""The grant check — FastAPI's own scope mechanism, plus the route's identity.

`bearer_auth` answers *who is calling*; this answers *may they reach this*. Both are router-level
dependencies, so a route added later is authenticated and authorised by construction rather than by
someone remembering a decorator.

**A grant is `<surface>:<name>`, and both halves come from FastAPI itself.**

- the **surface** is declared where the router is mounted — `Security(dependency, scopes=['bars'])`,
  either on the `APIRouter` or at `include_router(..., dependencies=[...])` — which is FastAPI's
  `SecurityScopes`, the mechanism it provides for exactly this. Declared for authorization rather
  than inferred from a path, so a `/v2` prefix or a rename cannot move it;
- the **name** is the route's first path parameter, which already *is* a domain identifier:
  `/v1/reports/{name}` carries the report id, `/brokers/{broker}/symbols/{symbol}/bars` the broker.

So a grant names a **thing**, never an address, and the comparison is exact.

A **collection** route (`/v1/reports`) has no identity segment and is not gated here: it is
*filtered* in its handler to what the caller holds (`TokenRegistry.permitted`). Gating it would
answer 403 to a consumer entitled to some of what it lists.

**The one weakness, stated so it is not inherited silently.** Authentication sits on a shared
router, so nothing can forget it. The surface is declared per router, so a router mounted without
its `Security(..., scopes=[...])` is authenticated **but ungated**. Nothing here can detect that
from the inside — which is what `route_walk.assert_no_identity_route_is_ungated` is for, and why
every consuming app's suite calls it.
"""
import logging
from typing import Callable, Optional

from fastapi import Request
from fastapi.security import SecurityScopes

from finiex_auth.error_factory import ErrorFactory, http_exception
from finiex_auth.token_registry import TokenRegistry

logger = logging.getLogger(__name__)


def route_identity(request: Request) -> Optional[str]:
    """The first path parameter of the matched route — the thing being addressed.

    First rather than last: a nested route (`/v1/reports/{name}/rows/{row_id}`) is governed by what
    it belongs to, which is what a grant is about — one is entitled to a report, not to one of its
    rows.
    """
    route = request.scope.get('route')
    template = getattr(route, 'path', '') if route is not None else ''
    params = request.scope.get('path_params') or {}
    for segment in template.strip('/').split('/'):
        if segment.startswith('{') and segment.endswith('}'):
            name = segment[1:-1]
            if name in params:
                return str(params[name])
    return None


def build_grant_dependency(tokens: TokenRegistry,
                           error_factory: ErrorFactory = http_exception) -> Callable[..., None]:
    """The dependency mounted with `Security(..., scopes=['<surface>'])` on a domain router."""

    def require_grant(security_scopes: SecurityScopes, request: Request) -> None:
        consumer = getattr(request.state, 'consumer', None)
        if consumer is None:
            # Authentication is off (scaffold mode, contract tests). There is no consumer to hold a
            # grant — and an app configured that way must already refuse an exposed bind, which is
            # the consuming app's boot check, not this dependency's.
            return
        if not security_scopes.scopes:
            return
        identity = route_identity(request)
        if identity is None:
            return
        grant = f'{security_scopes.scopes[0]}:{identity}'
        if not tokens.may(consumer, grant):
            logger.warning('[AUTH] %s denied %s', consumer, grant)
            # 403 rather than 404: the thing exists, a partner can read the documentation anyway,
            # and a denial they can debug beats one they have to guess at.
            raise error_factory(403, 'forbidden',
                                f'token {consumer!r} does not hold {grant!r} · holds: '
                                f'{tokens.grants_of(consumer)}', None)

    return require_grant
