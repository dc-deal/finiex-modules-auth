"""The registry: digests only, exact grants, the kill switch, and the flat environment form."""
import pytest

from finiex_auth.auth_errors import AuthConfigurationError
from finiex_auth.consumer_token_base import ConsumerTokenBase
from finiex_auth.token_registry import TokenRegistry, parse_token_pairs

_TOKEN = 'a-token-that-is-not-a-real-credential'


class _Token(ConsumerTokenBase):
    GRANT_SURFACES = ('reports', 'pipelines')


def test_the_registry_keeps_digests_and_not_tokens() -> None:
    registry = TokenRegistry({'ide': _TOKEN})
    assert registry.verify(_TOKEN) == 'ide'
    assert registry.verify(_TOKEN + 'x') is None
    assert registry.names() == ['ide']
    # The plaintext is nowhere in the object — a dump of it is not a credential.
    assert _TOKEN not in repr(vars(registry))


def test_a_grant_is_exact_and_widened_only_by_the_two_wildcards() -> None:
    registry = TokenRegistry({
        'narrow': _Token(token='n', grants=['reports:source_health']),
        'surface': _Token(token='s', grants=['reports:*']),
        'all': _Token(token='a', grants=['*'])})

    assert registry.may('narrow', 'reports:source_health')
    assert not registry.may('narrow', 'reports:cost')
    assert not registry.may('narrow', 'pipelines:source_health')    # same name, other surface
    assert registry.may('surface', 'reports:cost') and not registry.may('surface', 'pipelines:x')
    assert registry.may('all', 'pipelines:anything')
    # No pattern matching against what a caller supplies: a prefix or a glob is not a grant.
    assert not registry.may('narrow', 'reports:source')
    assert not registry.may('narrow', 'reports:source_health*')


def test_an_unknown_consumer_holds_nothing() -> None:
    registry = TokenRegistry({'ide': _Token(token='t', grants=['*'])})
    assert not registry.may('someone-else', 'reports:x')
    assert registry.grants_of('someone-else') == 'nothing'


def test_permitted_filters_a_listing_to_what_the_consumer_holds() -> None:
    registry = TokenRegistry({'narrow': _Token(token='n', grants=['reports:a', 'reports:c'])})
    assert registry.permitted('narrow', 'reports', ['a', 'b', 'c']) == ['a', 'c']


def test_an_inactive_token_never_enters_the_registry_and_is_reported() -> None:
    registry = TokenRegistry({'off': _Token(token='t', grants=['*'], active=False),
                              'on': _Token(token='u', grants=['*'], note='Testing IDE')})
    assert registry.verify('t') is None                  # the kill switch works at the door
    assert registry.names() == ['on'] and registry.inactive_names() == ['off']
    assert registry.note_of('on') == 'Testing IDE'


def test_a_flat_string_token_holds_everything_and_says_where_it_came_from() -> None:
    registry = TokenRegistry({'ci': _TOKEN}, source='environment')
    assert registry.may('ci', 'pipelines:x') and registry.grants_of('ci') == '*'
    assert registry.source() == 'environment'
    assert TokenRegistry().source() == 'none' and TokenRegistry().is_empty()


def test_the_flat_form_parses_and_tolerates_whitespace() -> None:
    assert parse_token_pairs(' ide : one , collector : two ', 'SOME_TOKENS') == {
        'ide': 'one', 'collector': 'two'}
    assert parse_token_pairs('', 'SOME_TOKENS') == {}


def test_a_malformed_entry_fails_loudly_naming_the_variable_but_never_the_value() -> None:
    """An empty registry and a broken one must not look alike — and the error must not leak."""
    for broken in ('no-separator-here', ':missing-name', 'name:', 'ide:a,ide:b'):
        with pytest.raises(AuthConfigurationError) as caught:
            parse_token_pairs(broken, 'SOME_TOKENS')
        message = str(caught.value)
        assert 'SOME_TOKENS' in message                  # the app's own variable is named
        assert 'no-separator-here' not in message        # the raw value never is
    # A ValueError, so a consumer catching ValueError around its configuration keeps working.
    assert issubclass(AuthConfigurationError, ValueError)
