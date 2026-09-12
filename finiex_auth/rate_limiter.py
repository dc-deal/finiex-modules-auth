"""Per-client request throttling for a FastAPI surface."""
import threading
import time
from typing import Callable, Dict, Optional, Tuple

from fastapi import Request

from finiex_auth.error_factory import ErrorFactory, http_exception


class RateLimiter:
    """A token bucket per client key, in process.

    In process rather than in a reverse proxy, deliberately: a limit that lives only in the proxy is
    gone the moment the app is started without one. For a single-process API server a dict plus a
    lock is the whole mechanism — no dependency, no shared store.

    It is defence in depth, not the gate. The gate is the bearer token; this bounds what an
    anonymous caller can do to the routes no token protects, and how fast a credential can be
    guessed.
    """

    def __init__(self, per_minute: int) -> None:
        """`per_minute` ≤ 0 disables the limiter entirely (and it then costs nothing per call)."""
        self._capacity = float(per_minute)
        self._refill_per_second = per_minute / 60.0
        # key -> (tokens available, last refill timestamp)
        self._buckets: Dict[str, Tuple[float, float]] = {}
        # One dict mutated from the event loop and from any thread FastAPI runs a sync dependency
        # on. Cheap to hold correctly, expensive to debug once it is not.
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        """Consume one token for `key`; False when the bucket is empty."""
        if self._capacity <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (self._capacity, now))
            # Refill for the elapsed time, capped at capacity — a client that was idle for an hour
            # gets one minute's worth, not an hour's.
            tokens = min(self._capacity, tokens + (now - last) * self._refill_per_second)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1.0, now)
            return True


def client_key(forwarded_for: Optional[str], peer: Optional[str]) -> str:
    """The identity a bucket is keyed on: the originating client, not the proxy.

    Behind a reverse proxy every request arrives from `127.0.0.1`, so keying on the peer address
    would put every caller in the world into **one** bucket — a global limit wearing the costume of a
    per-client one, which fails exactly when several consumers are active. So the first entry of
    `X-Forwarded-For` wins.

    **This is a trust decision the consuming app owns.** The header is spoofable by anyone who can
    reach the app directly, so it is trustworthy only where the only route in is a proxy that sets
    it — FiniexRAGEngine binds loopback behind Caddy. An app reachable without such a proxy lets a
    caller evade the limit by varying the header. On a loopback-only port that is the local machine
    evading itself; on anything wider it is a real gap, and the bearer token remains the gate.
    """
    if forwarded_for:
        first = forwarded_for.split(',')[0].strip()
        if first:
            return first
    return peer or 'unknown'


def build_rate_limit_dependency(limiter: RateLimiter,
                                error_factory: ErrorFactory = http_exception
                                ) -> Callable[[Request], None]:
    """The limiter as a FastAPI dependency, for the routes no token protects.

    Mount it on the public router rather than on one route, for the same reason the bearer
    dependency sits on the protected one: whatever is added beside it inherits the limit instead of
    needing to remember it.
    """

    def enforce_rate_limit(request: Request) -> None:
        key = client_key(request.headers.get('x-forwarded-for'),
                         request.client.host if request.client else None)
        if not limiter.allow(key):
            # `Retry-After` in seconds: a conforming client backs off on its own instead of
            # hammering a closed door, which is the behaviour the limit exists to produce.
            raise error_factory(429, 'rate_limited', 'Too many requests', {'Retry-After': '60'})

    return enforce_rate_limit
