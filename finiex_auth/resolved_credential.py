"""A credential together with the file that answered for it (from FiniexTestingIDE)."""
from dataclasses import dataclass
from typing import Optional


@dataclass
class ResolvedCredential:
    """A token together with the file that answered for it.

    A runtime result of a lookup, not a config schema — hence a dataclass beside the Pydantic token
    model. **The source is the load-bearing half:** with a tracked empty default and a gitignored
    override, "the token is configured" and "the token is empty and no header is sent" are otherwise
    indistinguishable from a log line. Useful on both ends of the wire — a client that must send a
    token, and a server that must know which file supplied the tokens it accepts.
    """
    token: str
    source: Optional[str]

    def is_configured(self) -> bool:
        """Whether a non-empty token was found — i.e. whether one will actually be sent."""
        return bool(self.token)

    def describe_source(self) -> str:
        """Operator-readable provenance, safe to log — never the token itself.

        The answering file, `<file> (empty)` when it answered with nothing, or a statement that no
        file answered at all.
        """
        if not self.source:
            return 'no credentials file found'
        return f'{self.source}' if self.token else f'{self.source} (empty)'
