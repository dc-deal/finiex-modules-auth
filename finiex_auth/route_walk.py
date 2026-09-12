"""The guard against this model's one weakness — call it from every consuming app's suite.

**Authentication is inherited; authorization is not.** The bearer dependency sits on a shared router,
so a route added later cannot forget it. The *surface* half of a grant is declared per router
(`Security(..., scopes=['bars'])`), so a router mounted without it is authenticated **but ungated** —
reachable by any valid token. A router mounted without its scopes looks identical to one mounted
with them, and no amount of reading the code reliably tells the two apart. Only walking the surface
does.

So instead of trusting the declaration, this walks every registered route that carries an identity
segment and asserts that a token holding **nothing** is refused with 403. A new router without a
declared surface then fails in the suite rather than in production.

It lives in the package, not in one app's tests, because shipping the mechanism without the guard
would hand every other consumer the weakness with none of the protection.
"""
import re
from typing import TYPE_CHECKING, Callable, List, Mapping, Optional, Sequence, Tuple

from fastapi import FastAPI

if TYPE_CHECKING:
    from starlette.testclient import TestClient

_PARAMETER = re.compile(r'\{([^}]+)\}')


def assert_no_identity_route_is_ungated(app: FastAPI, client: 'TestClient',
                                        headers: Mapping[str, str], *,
                                        required: Sequence[Tuple[str, str]] = (),
                                        fill: Optional[Callable[[str], str]] = None
                                        ) -> List[Tuple[str, str]]:
    """Raise `AssertionError` unless every identity route answers 403 to a token holding nothing.

    - `headers` authenticate as a consumer whose `grants` is empty — authenticated, entitled to
      nothing. A 401 would prove only authentication, which is the half that cannot be forgotten.
    - `required` names routes, as `(path, method)`, that **must** be present. Named rather than merely
      swept: a router dropping out of the app would otherwise leave the walk green while the surface
      it gated went unreachable. List every identity route your app is meant to have.
    - `fill` supplies a value for each path parameter by name (default `'x'`). Any value will do for
      the grant check, which refuses before the name is resolved — but a parameter typed as `int`
      needs a digit, or FastAPI answers 422 before the grant is ever consulted.

    Returns the `(path, method)` pairs it walked, so a suite can assert on the census as well.
    Raises explicitly rather than with `assert`, which `python -O` would strip into a guard that
    always passes.
    """
    filler = fill if fill is not None else (lambda _name: 'x')
    identity_routes = [(path, method)
                       for path, operations in app.openapi()['paths'].items()
                       for method in operations
                       if '{' in path]
    if not identity_routes:
        raise AssertionError('no identity routes found — the walk itself is broken')
    missing = [route for route in required if route not in identity_routes]
    if missing:
        raise AssertionError(f'named routes are not mounted in this app: {missing}')

    ungated: List[str] = []
    for path, method in identity_routes:
        url = _PARAMETER.sub(lambda match: filler(match.group(1)), path)
        response = client.request(method.upper(), url, headers=dict(headers))
        if response.status_code != 403:
            ungated.append(f'{method.upper()} {path} answered {response.status_code}')
    if ungated:
        raise AssertionError('identity routes a token holding NOTHING was not refused on — is a '
                             'router mounted without Security(..., scopes=[...])?\n  '
                             + '\n  '.join(ungated))
    return identity_routes
