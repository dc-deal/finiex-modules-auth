"""A consumer's credential, and the grant grammar each consuming app validates it against."""
from typing import Any, ClassVar, List, Tuple

from pydantic import BaseModel, field_validator


class ConsumerTokenBase(BaseModel):
    """One consumer's credential: who holds it, what it may reach, and whether it is in force.

    **Subclass it and name your surfaces.** A grant is `<surface>:<name>` — `reports:source_health`,
    `bars:kraken_spot` — with `<surface>:*` for a whole surface and a bare `*` for everything. The
    surfaces are the consuming app's own closed vocabulary, so each app declares them on its
    subclass::

        class ConsumerToken(ConsumerTokenBase):
            GRANT_SURFACES = ('bars', 'brokers', 'reports', 'sweeps')

    A typo like `report:source_health` then fails when the configuration is parsed, at boot, instead
    of turning into a silent denial nobody can see. **A subclass that declares no surfaces is
    refused when it is defined**, not defaulted: an empty vocabulary would accept no grant at all,
    and the obvious "fix" for that is a wildcard vocabulary, which is the defect this exists to
    prevent.

    `grants` is **required**, and that is the point. A token without declared rights would have to
    default to something, and every safe-by-omission default is one someone eventually relies on
    without noticing. Declaring it makes granting an act rather than an oversight: a surface added
    later is reachable by a consumer only once someone writes its name down.

    **Domain names, not routes.** `source_health` is a stable concept; `/v1/reports/source_health`
    is merely its current address, and a grant bound to an address silently stops matching after a
    `/v2` or a rename — a 403 for a consumer who did nothing wrong. Names also compare exactly: no
    wildcard matching against paths, which is where authorization defects live.

    `active` is a kill switch, not documentation: a consumer can be switched off without deleting
    their token. `note` records who holds it — one line that answers the question arriving during a
    rotation, months later: *who is `ide2`, and may I revoke it?*
    """
    # The consuming app's closed vocabulary of surfaces. Declared on the subclass, because the
    # surfaces ARE the app: `reports`/`pipelines` in one service, `bars`/`brokers` in another.
    GRANT_SURFACES: ClassVar[Tuple[str, ...]] = ()

    token: str
    grants: List[str]
    active: bool = True
    note: str = ''

    @classmethod
    def __pydantic_init_subclass__(cls, **kwargs: Any) -> None:
        super().__pydantic_init_subclass__(**kwargs)
        # At definition, not at first use: an app that configures no tokens would otherwise never
        # parse one, and the missing vocabulary would surface only on the day a consumer is added.
        if not cls.GRANT_SURFACES:
            raise TypeError(
                f'{cls.__name__} declares no GRANT_SURFACES. Name the closed vocabulary this app '
                f'gates on, e.g. GRANT_SURFACES = (\'reports\', \'pipelines\')')

    @field_validator('grants')
    @classmethod
    def _grants_name_a_known_surface(cls, value: List[str]) -> List[str]:
        if not cls.GRANT_SURFACES:
            # The base used directly: it has no vocabulary, so it can validate nothing.
            raise ValueError(f'{cls.__name__} declares no GRANT_SURFACES — subclass '
                             f'ConsumerTokenBase and name the surfaces this app gates on')
        example = cls.GRANT_SURFACES[0]
        for grant in value:
            if grant == '*':
                continue
            surface, separator, name = grant.partition(':')
            if not separator or not name or surface not in cls.GRANT_SURFACES:
                raise ValueError(
                    f'grant {grant!r} is not "<surface>:<name>" over a known surface. '
                    f'Surfaces: {", ".join(cls.GRANT_SURFACES)}. Use e.g. "{example}:<name>", '
                    f'"{example}:*", or "*" for everything')
        return value
