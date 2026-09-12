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
- **Failed-attempt throttling** per client; a valid call is never throttled.
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

## What it deliberately does not do

- **It never learns where credentials live.** `TokenRegistry` takes a mapping; loading it — from an
  overlay config, a credentials cascade or an environment variable — is your app's code.
- **It never chooses an environment variable name.** `parse_token_pairs(raw, env_var)` requires
  one. Two services reading the same name would accept each other's tokens.
- **It does not decide whether to trust `X-Forwarded-For`.** `client_key` keys the limiter on it,
  which is correct behind a proxy that sets it and spoofable anywhere a client can reach the app
  directly. That is your deployment's decision; the bearer token stays the gate either way.
- **It does not refuse an exposed, unauthenticated bind.** That boot check belongs in your app,
  which knows its bind address.

## Versions and changes

Pin a tag: `finiex-auth @ git+https://github.com/dc-deal/finiex-modules-auth.git@v0.1.0`. For development,
`pip install -e` a checkout. Semver: a breaking change is announced to both consumers before either
raises its pin, and **whoever raises a pin runs their full suite and states the pass count.** An
editable install is the one state no pin watches, so each app reports the installed version and
whether it is editable alongside its build information.

Python ≥ 3.12, tested on 3.12 and 3.14. Rules for this repository: [RULES.md](RULES.md).
