"""A credential and the file that answered for it — three states a log line must tell apart."""
from finiex_auth.resolved_credential import ResolvedCredential


def test_the_three_states_are_distinguishable_and_none_shows_the_token() -> None:
    real = ResolvedCredential(token='a-secret-value', source='user_configs/credentials/rag.json')
    empty = ResolvedCredential(token='', source='configs/credentials/rag.json')
    absent = ResolvedCredential(token='', source=None)

    assert real.is_configured() and not empty.is_configured() and not absent.is_configured()
    assert real.describe_source() == 'user_configs/credentials/rag.json'
    assert empty.describe_source() == 'configs/credentials/rag.json (empty)'
    assert absent.describe_source() == 'no credentials file found'
    assert 'a-secret-value' not in real.describe_source()
