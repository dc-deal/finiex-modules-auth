"""Each app declares its own surfaces, and a missing vocabulary is refused rather than defaulted."""
import pytest
from pydantic import ValidationError

from finiex_auth.consumer_token_base import ConsumerTokenBase


class _IdeToken(ConsumerTokenBase):
    GRANT_SURFACES = ('bars', 'brokers', 'reports', 'sweeps')


class _EngineToken(ConsumerTokenBase):
    GRANT_SURFACES = ('reports', 'pipelines', 'logs', 'configs', 'diagnose')


def test_a_subclass_validates_grants_against_its_own_surfaces() -> None:
    token = _IdeToken(token='t', grants=['bars:kraken_spot', 'brokers:*', '*'])
    assert token.grants == ['bars:kraken_spot', 'brokers:*', '*']
    for bad in ('pipelines:crypto', 'bars', 'bars:', 'bar:kraken_spot', ':kraken_spot'):
        with pytest.raises(ValidationError, match='known surface'):
            _IdeToken(token='t', grants=[bad])


def test_two_apps_keep_separate_vocabularies() -> None:
    """The one real decoupling: a grant valid in one service is a typo in the other."""
    _EngineToken(token='t', grants=['pipelines:crypto_sentiment'])
    with pytest.raises(ValidationError):
        _IdeToken(token='t', grants=['pipelines:crypto_sentiment'])


def test_the_error_names_the_surfaces_and_gives_an_example_from_them() -> None:
    with pytest.raises(ValidationError) as caught:
        _IdeToken(token='t', grants=['report:x'])
    message = str(caught.value)
    assert 'Surfaces: bars, brokers, reports, sweeps' in message
    assert '"bars:<name>"' in message


def test_a_subclass_that_declares_no_surfaces_is_refused_when_it_is_defined() -> None:
    """Not at first use: an app with no tokens configured would never parse one."""
    with pytest.raises(TypeError, match='GRANT_SURFACES'):
        # Built through the metaclass rather than with a `class` statement: the definition is
        # meant to fail, so there is nothing to bind and nothing for a dead-code scan to report.
        type('Forgot', (ConsumerTokenBase,), {'__module__': __name__})


def test_the_base_itself_validates_nothing() -> None:
    with pytest.raises(ValidationError, match='GRANT_SURFACES'):
        ConsumerTokenBase(token='t', grants=['*'])


def test_grants_are_mandatory_and_the_defaults_are_in_force() -> None:
    with pytest.raises(ValidationError):
        _IdeToken(token='t')                             # granting is an act, never an omission
    token = _IdeToken(token='t', grants=[])
    assert token.active is True and token.note == '' and token.grants == []
