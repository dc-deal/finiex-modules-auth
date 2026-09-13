# finiex-auth

Bearer tokens with per-name grants for FastAPI services — one implementation shared by
FiniexRAGEngine and FiniexTestingIDE, because a second copy of a security vocabulary is the one that
stops being updated.

## What it gives you

- **Mandatory grants.** A token without `grants` fails when the configuration is parsed, instead of
  defaulting to everything. Access is granted by writing a name down, never by omission.
- **Grants name things, not routes.** `<surface>:<name>` — `bars:kraken_spot`, `reports:*`, or `*`.
  Compared exactly; no pattern matching against anything a caller sends.
- **Digests only.** The registry holds SHA-256 digests, never tokens, and verifies with
  `hmac.compare_digest` across every entry without early exit.
- **A kill switch** (`active: false`) and a `note` saying who holds each token.
- **Failed-attempt throttling** per client; a valid call is never throttled. Each rejected token is
  logged with method, path and client address — never the credential.
- **Redaction** of credential shapes in text a service publishes (`redaction.redact`).
- **The answering-file guard** (`credential_guard`) and `ResolvedCredential`: refuse a credential
  read from the tracked placeholder, and log which file supplied one without logging the value.
- **The walk** (`route_walk.assert_no_identity_route_is_ungated`) — see below. It is not optional.

## Integration

```python
from fastapi import APIRouter, Depends, FastAPI, Security

from finiex_auth.bearer_auth import build_bearer_dependency
from finiex_auth.consumer_token_base import ConsumerTokenBase
from finiex_auth.grant_auth import build_grant_dependency
from finiex_auth.rate_limiter import RateLimiter
from finiex_auth.token_registry import TokenRegistry


class ConsumerToken(ConsumerTokenBase):
    GRANT_SURFACES = ('bars', 'brokers', 'reports', 'sweeps')   # your app's closed vocabulary


tokens = TokenRegistry(load_my_tokens(), source='user_configs/credentials/api_tokens.json')
bearer = Depends(build_bearer_dependency(tokens, RateLimiter(per_minute=10), my_error_factory))
grant = build_grant_dependency(tokens, my_error_factory)

app = FastAPI()
app.include_router(bars_router, prefix='/api/v1',
                   dependencies=[bearer, Security(grant, scopes=['bars'])])
```

`my_error_factory(status_code, error, detail, headers)` returns the exception your app raises. The
default is FastAPI's `HTTPException`. **Keep `headers`:** a 401 without `WWW-Authenticate: Bearer`
is malformed, and a 429 without `Retry-After` gives a client nothing to back off on.

**The name half of a grant is the route's first path parameter.** `/brokers/{broker}/symbols/{symbol}/bars`
is governed by `{broker}`, so its grants read `bars:kraken_spot`. Where the first parameter is a
generated id (`/reports/runs/{run_id}/…`), `reports:*` is the realistic grant.

**A route with no path parameter is a collection** (`/reports/runs`). The caller needs at least one
grant on its surface, or the answer is 403; a caller entitled to some of what it lists reaches the
handler, which filters the list to what they hold — `tokens.permitted(consumer, 'reports', names)`.
A route declared on the app itself (`@app.get`) rather than on a router gets neither check.

## The walk — call it from your suite

Authentication is inherited; **authorization is not.** A router mounted without its
`Security(..., scopes=[...])` is authenticated but ungated, and reads exactly like one that is
gated. So every consuming app's suite walks its own surface:

```python
def test_no_identity_route_is_ungated() -> None:
    app = build_my_app_with_a_token_holding_nothing()          # grants: []
    assert_no_identity_route_is_ungated(
        app, TestClient(app), {'Authorization': 'Bearer holds-nothing'},
        required=[('/api/v1/brokers/{broker}/symbols/{symbol}/bars', 'get')])
```

The walk calls identity routes. Collection routes are covered by the floor above, which works only
where the router declares its surface — a router carrying nothing but collection routes gives the
walk nothing to call, so test its refusal yourself.

## Browser clients

- **A CORS preflight is never gated.** The checks are route dependencies, and a preflight `OPTIONS`
  never reaches a `GET` route: `CORSMiddleware` answers it before routing (without CORS the router
  answers 405). `allow_headers` must admit `Authorization`; Starlette's `['*']` does.
- **Expose the two headers the answers depend on.** `WWW-Authenticate` (401) and `Retry-After`
  (429) are not CORS-safelisted, so a browser hides them from the page unless the app sets
  `expose_headers=['WWW-Authenticate', 'Retry-After']`.
- **A token in a browser is not a secret.** Whoever loads the page holds whatever it sends. Keep the
  token server-side — a proxy that injects it (backend-for-frontend) — and scope any token a browser
  does hold as though it were public.

## What it deliberately does not do

- **It never learns where credentials live.** `TokenRegistry` takes a mapping; loading it — from an
  overlay config, a credentials cascade or an environment variable — is your app's code.
- **It never chooses an environment variable name.** `parse_token_pairs(raw, env_var)` requires
  one. Two services reading the same name would accept each other's tokens.
- **It never reads `X-Forwarded-For`.** The limiter keys on `request.client.host`, the address
  your ASGI server resolved. Every caller can write that header, so a key read from it would give a
  guesser a fresh bucket per attempt. uvicorn applies the header only when the connection comes
  from a trusted proxy (`--forwarded-allow-ips`, default `127.0.0.1`): behind a proxy on the same
  machine the key is the originating client, on a directly published port it is the connection's
  peer. A proxy on another address is declared in the server, never trusted here.
- **It does not refuse an exposed, unauthenticated bind.** That boot check belongs in your app,
  which knows its bind address.
- **It does not manage users.** It authorises services — a configured token, a consumer name, its
  grants. Human accounts (sign-in, password hashing, sessions, reset, a second factor) are a
  different domain with their own storage: an identity provider over OpenID Connect, or a separate
  package. The seam is the grant — a user system maps roles onto `<surface>:<name>`, and this
  package keeps checking them.

## Versions and changes

Pin a tag: `finiex-auth @ git+https://github.com/dc-deal/finiex-modules-auth.git@v0.3.0`. For development,
`pip install -e` a checkout. Semver: a breaking change is announced to both consumers before either
raises its pin, and **whoever raises a pin runs their full suite and states the pass count.** An
editable install is the one state no pin watches, so each app reports the installed version and
whether it is editable alongside its build information.

Python ≥ 3.12, tested on 3.12 and 3.14. Rules for this repository: [RULES.md](RULES.md).

## Licence

MIT for the code, from `v0.1.1` on (`v0.1.0` shipped without a licence — never pin it). The
**Finiex™** name is not covered by the licence; see the notice in [LICENSE](LICENSE).
