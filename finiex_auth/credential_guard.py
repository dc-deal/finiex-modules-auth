"""Refuse a credential that was read from the tracked default (from FiniexTestingIDE).

Both consuming projects keep credentials in a cascade: a committed placeholder under a tracked
directory, and the real value in a gitignored override that takes precedence. Without a check the
two are indistinguishable until the far end answers — minutes into a session, with a message that
reads as the other side's fault rather than as our configuration. On a server the trap is sharper:
a tracked empty default token and an absent header are indistinguishable at the point of
comparison, and the failure is silent in the permissive direction.

**The rule is the ANSWERING FILE, not the value.** That catches two hazards with one check: a
placeholder reaching a live path, and a real key committed into the tracked default — the more
expensive of the two. Matching literals would catch only the first, and only until someone renames
them.
"""
from pathlib import Path, PurePath

from finiex_auth.auth_errors import AuthConfigurationError


def assert_real_credential(credential_path: Path, purpose: str, *,
                           tracked_dir: PurePath, override_dir: PurePath) -> None:
    """Refuse a credential that was read from `tracked_dir`.

    `tracked_dir` and `override_dir` are the consuming app's layout — `configs/credentials` and
    `user_configs/credentials` in FiniexTestingIDE — and both are **required**: a package that
    guessed a layout would guard the wrong directory without saying so.

    The directories are compared **part by part from the end, never as substrings**, because
    `configs/credentials` is a substring of `user_configs/credentials` — a substring test refuses
    the real key too, and would fail every live run.

    `purpose` names what was about to happen, so the operator does not have to work out which call
    tripped. The credential itself is never read, so it cannot reach the message.
    """
    path = Path(credential_path)
    tracked_parts = PurePath(tracked_dir).parts
    if path.parent.parts[-len(tracked_parts):] != tracked_parts:
        return

    raise AuthConfigurationError(
        f'{purpose} would run on the tracked default credentials at {path}, which is a '
        f'committed placeholder by design.\n'
        f'  Put the real value in {PurePath(override_dir) / path.name} — it takes '
        f'precedence in the cascade.\n'
        f'  If a real value IS in the tracked file: remove it. That file is committed.'
    )
