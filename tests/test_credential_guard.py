"""The answering-file rule: refuse the tracked default, compared part by part, never by substring."""
from pathlib import Path, PurePath

import pytest

from finiex_auth.auth_errors import AuthConfigurationError
from finiex_auth.credential_guard import assert_real_credential

_LAYOUT = {'tracked_dir': PurePath('configs/credentials'),
           'override_dir': PurePath('user_configs/credentials')}


def test_a_credential_answered_by_the_tracked_default_is_refused_with_directions() -> None:
    with pytest.raises(AuthConfigurationError) as caught:
        assert_real_credential(Path('/app/configs/credentials/rag.json'), 'The signal feed',
                               **_LAYOUT)
    message = str(caught.value)
    assert message.startswith('The signal feed would run on the tracked default credentials')
    assert 'user_configs/credentials/rag.json' in message       # where the real value belongs


def test_the_override_is_accepted_although_the_tracked_path_is_a_substring_of_it() -> None:
    """`configs/credentials` is a substring of `user_configs/credentials` — the trap this avoids."""
    assert_real_credential(Path('/app/user_configs/credentials/rag.json'), 'x', **_LAYOUT)
    assert_real_credential(Path('/app/elsewhere/rag.json'), 'x', **_LAYOUT)


def test_the_layout_is_the_consumers_and_has_no_default() -> None:
    with pytest.raises(TypeError):
        assert_real_credential(Path('/app/configs/credentials/rag.json'), 'x')  # type: ignore[call-arg]
