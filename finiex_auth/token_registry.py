"""Which bearer tokens are valid, which consumer each belongs to, and what each may reach."""
import hashlib
import hmac
from typing import Dict, List, Mapping, Optional, Sequence, Union

from finiex_auth.auth_errors import AuthConfigurationError
from finiex_auth.consumer_token_base import ConsumerTokenBase


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def parse_token_pairs(raw: str, env_var: str) -> Dict[str, str]:
    """`name:token,name:token` → mapping — the flat form an environment variable can carry.

    `env_var` is the variable's name, and it is **required**: this package never chooses one. Two
    services on one machine reading the same variable would accept each other's tokens, so the name
    is the consuming app's decision, stated where it reads it. The name appears in error messages;
    the raw value never does — a diagnostic that echoes a credential is a credential in a log file.

    A malformed entry raises rather than silently yielding nothing. An empty registry and a broken
    one must not look alike: "empty" is what makes a consuming app refuse to boot, so a typo would
    otherwise produce a confusing refusal instead of a precise complaint.
    """
    tokens: Dict[str, str] = {}
    for entry in raw.split(','):
        entry = entry.strip()
        if not entry:
            continue
        name, separator, token = entry.partition(':')
        name, token = name.strip(), token.strip()
        if not separator or not name or not token:
            raise AuthConfigurationError(
                f'{env_var} entry is not "name:token" (value not shown). '
                f'Expected e.g. "ide:<token>,collector:<token>"')
        if name in tokens:
            raise AuthConfigurationError(
                f'{env_var} names consumer {name!r} twice — one token per consumer')
        tokens[name] = token
    return tokens


class TokenRegistry:
    """Which bearer tokens are valid, and which consumer each one belongs to.

    **One token per consumer, not one shared token.** Only that form can be revoked without
    disrupting everyone else.

    The registry holds **SHA-256 digests**, never the tokens. A configuration file that leaks, a
    memory dump, or a support ticket carrying this object is then not a leaked credential — the same
    reason a provider shows an API key once and never again.

    **Where tokens come from is not this class's business.** The constructor takes a mapping; each
    consuming app keeps its own loader, because each keeps its credentials somewhere else (an
    overlay config, a credentials cascade, an environment variable). A package that learned where a
    credential lives would have to choose, and both choices would be wrong for someone.
    """

    def __init__(self, tokens: Optional[Mapping[str, Union[str, ConsumerTokenBase]]] = None,
                 source: str = 'none') -> None:
        """`tokens` maps consumer name → a `ConsumerTokenBase` subclass, or a plaintext string.

        Both shapes are accepted on purpose, and they mean different things:

        - a **token model** comes from a configuration file, where a scope is mandatory;
        - a **plain string** comes from a flat environment form (`parse_token_pairs`), whose syntax
          has nowhere to put a grant — so it resolves to `'*'`. That path is meant for environments
          the operator owns (a container, CI), never for a consumer, and a consuming app should say
          so in its boot log rather than leave it to be discovered.

        `source` is a label for where they came from — `'environment'`, a file name, `'none'` — so
        boot can say that out loud too.
        """
        self._digests: Dict[str, str] = {}
        self._grants: Dict[str, List[str]] = {}
        self._notes: Dict[str, str] = {}
        self._inactive: List[str] = []
        for name, entry in (tokens or {}).items():
            if isinstance(entry, ConsumerTokenBase):
                if not entry.active:
                    # Never enters the registry: an inactive token cannot authenticate, so a
                    # switched-off consumer is off at the door rather than at each route — and an
                    # example entry carried in a template file cannot be live by accident.
                    self._inactive.append(name)
                    continue
                self._digests[name] = _digest(entry.token)
                self._grants[name] = list(entry.grants)
                self._notes[name] = entry.note
            else:
                self._digests[name] = _digest(entry)
                self._grants[name] = ['*']
                self._notes[name] = ''
        self._source = source

    def may(self, consumer: str, grant: str) -> bool:
        """Whether `consumer` holds `grant` (`"reports:source_health"`, `"bars:kraken_spot"`).

        Exact comparison over a closed vocabulary, widened only by the two wildcards a grant may
        declare: `<surface>:*` and `*`. No pattern matching against anything the caller supplies —
        the surface and the name are the app's own words, not the request's.

        An unknown consumer holds nothing. Reaching this with a name the registry does not carry is
        a bug, and a bug must not grant.
        """
        held = self._grants.get(consumer)
        if not held:
            return False
        surface, _, _name = grant.partition(':')
        return '*' in held or grant in held or f'{surface}:*' in held

    def permitted(self, consumer: str, surface: str, names: Sequence[str]) -> List[str]:
        """The subset of `names` on `surface` this consumer holds — what a listing shows."""
        return [name for name in names if self.may(consumer, f'{surface}:{name}')]

    def holds_any(self, consumer: str, surface: str) -> bool:
        """Whether `consumer` holds anything at all on `surface` — the floor of a collection route.

        A collection route has no identity to compare, so its handler filters the list to what the
        caller holds (`permitted`). This is the floor beneath that filter: a consumer entitled to
        nothing on the surface is refused before the handler runs, so a handler that forgets to
        filter leaks nothing to them.
        """
        held = self._grants.get(consumer)
        if not held:
            return False
        return '*' in held or any(grant.partition(':')[0] == surface for grant in held)

    def grants_of(self, consumer: str) -> str:
        """A one-line rendering of what a consumer holds, for the boot report and a 403."""
        held = self._grants.get(consumer)
        return ', '.join(held) if held else 'nothing'

    def note_of(self, consumer: str) -> str:
        return self._notes.get(consumer, '')

    def inactive_names(self) -> List[str]:
        """Entries present in the configuration but switched off — for the boot report."""
        return sorted(self._inactive)

    def verify(self, presented: str) -> Optional[str]:
        """The consumer name behind `presented`, or None.

        Two properties matter more than the lookup itself, and both are about **time**:

        - the comparison is `hmac.compare_digest`, not `==`. String equality returns at the first
          differing byte, so the response time reports how much of a guess was right;
        - the loop does **not** break on a match. Returning early would make the answer's latency
          depend on the matched consumer's position, which leaks a little of the same thing.

        Comparing digests rather than raw tokens also fixes the compared length, so the input's
        length reveals nothing either.
        """
        presented_digest = _digest(presented)
        matched: Optional[str] = None
        for name, digest in self._digests.items():
            if hmac.compare_digest(presented_digest, digest):
                matched = name
        return matched

    def names(self) -> List[str]:
        """The configured consumer names — for the boot log. Never the tokens."""
        return sorted(self._digests)

    def source(self) -> str:
        """The label the loader passed: where these tokens came from."""
        return self._source

    def is_empty(self) -> bool:
        return not self._digests
