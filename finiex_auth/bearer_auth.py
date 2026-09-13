"""The bearer-token dependency guarding every non-public route."""
import logging
from typing import Callable, Optional

from fastapi import Request

from finiex_auth.error_factory import ErrorFactory, http_exception
from finiex_auth.rate_limiter import RateLimiter, client_key
from finiex_auth.token_registry import TokenRegistry

logger = logging.getLogger(__name__)

# One message for every rejection. A body that distinguished "no header" from "unknown token"
# would answer a question the caller has no right to ask, and the distinction is exactly what a
# guesser probes for.
_DENIED = 'Not authenticated'


def build_bearer_dependency(registry: TokenRegistry,
                            limiter: Optional[RateLimiter] = None,
                            error_factory: ErrorFactory = http_exception
                            ) -> Callable[[Request], None]:
    """The dependency mounted on the protected router — never on individual routes.

    Mounting it on the `APIRouter` is the whole design: a route added later inherits it by
    construction, so the failure it exists to prevent — an endpoint shipped unprotected by
    omission — cannot be reached by forgetting something.

    `limiter`, when given, bounds **failed** attempts per client: a valid call is never throttled
    here, so a busy consumer cannot rate-limit itself by working.

    On success the consumer's name is placed on `request.state.consumer` — attribution without the
    secret, and what the grant dependency reads.
    """

    def require_bearer(request: Request) -> None:
        header = request.headers.get('authorization', '')
        scheme, _, presented = header.partition(' ')
        consumer = (registry.verify(presented.strip())
                    if scheme.lower() == 'bearer' and presented.strip() else None)
        if consumer is None:
            client = client_key(request)
            if limiter is not None:
                if not limiter.allow(client):
                    # Deliberately 429 rather than another 401: the caller has stopped being a
                    # failed login and started being traffic, and an operator reading the log
                    # should see the difference.
                    raise error_factory(429, 'rate_limited', 'Too many attempts', None)
            # The path is logged, the credential never — not even truncated. A prefix in a log
            # file is a prefix an attacker with the log file no longer has to guess. The client
            # address is what makes the line actionable: which caller keeps failing, and — behind
            # a proxy — proof that the originating client arrives rather than the proxy itself.
            logger.warning('[AUTH] rejected %s %s from %s',
                           request.method, request.url.path, client)
            # `WWW-Authenticate` is what makes the 401 well-formed: it tells a conforming client
            # which scheme to retry with, and lets it tell a dead credential from a transport fault.
            raise error_factory(401, 'unauthenticated', _DENIED, {'WWW-Authenticate': 'Bearer'})
        request.state.consumer = consumer

    return require_bearer
