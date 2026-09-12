"""The one exception this package raises for a setting it cannot trust."""


class AuthConfigurationError(ValueError):
    """A credential setting that is malformed, ambiguous, or answered by the wrong file.

    A `ValueError` subclass so a consumer that already catches `ValueError` around its configuration
    keeps working, and a type of its own so a consumer that wants its own taxonomy can translate it —
    FiniexRAGEngine re-raises it as its `ConfigurationError`, rooted at its own base error.

    **Its message never contains the credential.** Every raise site in this package is written that
    way, because a diagnostic that echoes a secret is a secret in a log file.
    """
