# Rules for this repository

Self-contained on purpose: the consuming projects' rulebooks are not all public, and a pointer to a
file nobody outside can open is no rule at all. These are the stricter of both, for a small library.

## The package's own discipline

- **It holds no credential and never learns where one lives.** Loaders stay in the consuming apps.
- **No default for a security decision.** Surfaces, an environment variable name, a credentials
  layout: each is a required parameter or a required subclass declaration. A default nobody chose
  is a decision nobody made, and in authorization that is the one that eventually grants.
- **Credentials never reach a log line, an error message, a response body or a comment** — not even
  a prefix. Only digests are held. Every test that touches a token asserts its absence.
- **Behaviour changes are visible to both consumers.** A change to a status code, a body, a header
  or a log line is a change to two services at once.

## Code

- **Python ≥ 3.12.** Nothing that needs a newer interpreter. The suite runs on 3.12 and 3.14.
- **Fully typed** — every parameter and return, `Optional[X] = None` never a bare `= None`, `Any`
  where a value is genuinely dynamic. `tests/test_typing_contract.py` checks that annotations exist
  and that they resolve; it is not a suggestion.
- **Single quotes** for string literals; double only to avoid escaping, and for docstrings.
- **No `__init__.py`** (PEP 420). Imports are fully qualified from `finiex_auth.`.
- **One behaviour class per file**, file name = class name in snake_case. **A file's name says what
  it is** — a module holding no exception is not called `*_errors`.
- **Closed vocabularies** are a `Literal` alias plus a tuple of its values.
- Imports at the top, grouped standard library → third party → project.
- **Comments explain the why**, in English, compact, with no session or tooling narration.

## Checks

Run from the repository root, so the configurations here are the ones read — never bare:

    python -m pytest
    python -m ruff check .
    python -m pyflakes finiex_auth tests
    python -m vulture --config vulture.toml      # backlog tier: triaged by hand, never a gate

A green exit code is not evidence; **the pass count is.** State it with every change.

## Releases

Semver, a tag per release. **A breaking change is announced to both consumers before either raises
its pin**, and the side that raises a pin runs its own full suite first and states the count.
