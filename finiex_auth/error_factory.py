"""How an authentication failure becomes an exception — the one seam each consumer shapes.

The dependencies in this package decide *that* a request fails and *why*. They do not decide what
the failure looks like on the wire, because the consumers disagree about that on purpose:
FiniexRAGEngine answers with FastAPI's own `HTTPException`, FiniexTestingIDE has an error contract of
its own (`ApiException(status_code, error, detail)`, never a raw `HTTPException`). So every
dependency takes an `ErrorFactory` and raises what it returns.

The factory receives four things, and a consumer that wants a correct answer drops none of them:

- `status_code` — 401, 403 or 429;
- `error` — a short code from `AUTH_ERROR_CODES`, for a body that carries one;
- `detail` — the human sentence;
- `headers` — present on exactly the answers that need one. A 401 carries `WWW-Authenticate: Bearer`,
  which is what makes it well-formed (RFC 7235) and how a client tells a dead credential from a
  transport failure; the public limiter's 429 carries `Retry-After`. A factory that discards
  `headers` produces answers a conforming client cannot act on.
"""
from typing import Callable, Dict, Literal, Optional, Tuple, get_args

from fastapi import HTTPException

# Every failure this package can produce — a closed vocabulary, strict where it is produced. The
# tuple is derived rather than restated, so the two can never disagree; a consumer mapping codes
# onto its own error contract enumerates it.
AuthErrorCode = Literal['unauthenticated', 'forbidden', 'rate_limited']
AUTH_ERROR_CODES: Tuple[AuthErrorCode, ...] = get_args(AuthErrorCode)

# (status_code, error, detail, headers) -> the exception the consuming application raises.
ErrorFactory = Callable[[int, str, str, Optional[Dict[str, str]]], Exception]


def http_exception(status_code: int, error: str, detail: str,
                   headers: Optional[Dict[str, str]] = None) -> Exception:
    """The default factory: FastAPI's `HTTPException`, with `detail` as the body.

    `error` has no place in FastAPI's default body, so it is dropped here — deliberately: this
    default reproduces FiniexRAGEngine's answers byte for byte, and a consumer that wants the code
    in its body passes a factory of its own.
    """
    return HTTPException(status_code=status_code, detail=detail, headers=headers)
