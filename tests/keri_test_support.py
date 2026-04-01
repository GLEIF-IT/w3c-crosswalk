"""Small KERIpy helpers shared by unit tests.

These helpers keep the unit tests deterministic while still using real KERIpy
habitats instead of fake signing fixtures.
"""

from __future__ import annotations

from contextlib import contextmanager

from keri.app.habbing import openHby
from keri.core import signing


@contextmanager
def open_test_hab(name: str, raw_salt: bytes):
    """Open a temporary single-sig habitat for unit tests.

    The helper creates the habitat on demand and yields both the habery and the
    habitat so callers can exercise production signing code with real KERI
    primitives.
    """
    salt = signing.Salter(raw=raw_salt).qb64
    with openHby(name=name, salt=salt, temp=True) as hby:
        hab = hby.habByName(name)
        if hab is None:
            hab = hby.makeHab(name=name, icount=1, isith="1", ncount=1, nsith="1")
        yield hby, hab
