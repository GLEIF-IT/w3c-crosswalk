"""Seeder tests for actor witness-role OOBI resolution."""

from __future__ import annotations

from types import SimpleNamespace

from headless_w3c_e2e import seed


def test_parser_has_no_witness_bootstrap_oobi_argument():
    """Witness introduction OOBIs come from the KERIA config iurls."""
    args = seed.parser().parse_args([])

    assert not hasattr(args, "witness_controller_oobi")
    assert not hasattr(args, "witness_oobi")


def test_exchange_witness_oobis_resolves_generated_role_oobis_into_every_actor(monkeypatch):
    """Actor witness OOBIs are generated after AID creation and resolved everywhere."""
    seen_gets: list[tuple[str, str]] = []
    seen_resolves: list[tuple[str, str, str | None]] = []
    seen_operations: list[tuple[str, float]] = []

    class FakeOobis:
        def __init__(self, owner: str):
            self.owner = owner

        def resolve(self, oobi: str, alias: str | None = None) -> dict[str, str]:
            seen_resolves.append((self.owner, oobi, alias))
            return {"name": f"resolve-{self.owner}"}

    class FakeClient:
        def __init__(self, owner: str):
            self.owner = owner

        def oobis(self) -> FakeOobis:
            return FakeOobis(self.owner)

    actors = [
        SimpleNamespace(name="geda", client=FakeClient("geda")),
        SimpleNamespace(name="qvi", client=FakeClient("qvi")),
        SimpleNamespace(name="le", client=FakeClient("le")),
    ]

    def fake_wait_for_oobi(client, name, *, role, timeout):
        seen_gets.append((name, role))
        return [f"http://witness-demo:5642/oobi/{name}-aid/witness/wan"]

    def fake_wait_for_operation(_client, operation, *, timeout):
        seen_operations.append((operation["name"], timeout))

    monkeypatch.setattr(seed, "wait_for_oobi", fake_wait_for_oobi)
    monkeypatch.setattr(seed, "wait_for_operation", fake_wait_for_operation)

    seed.exchange_witness_oobis(actors, timeout=12.5)

    assert seen_gets == [("geda", "witness"), ("qvi", "witness"), ("le", "witness")]
    assert seen_resolves == [
        ("geda", "http://witness-demo:5642/oobi/geda-aid/witness/wan", "geda"),
        ("qvi", "http://witness-demo:5642/oobi/geda-aid/witness/wan", "geda"),
        ("le", "http://witness-demo:5642/oobi/geda-aid/witness/wan", "geda"),
        ("geda", "http://witness-demo:5642/oobi/qvi-aid/witness/wan", "qvi"),
        ("qvi", "http://witness-demo:5642/oobi/qvi-aid/witness/wan", "qvi"),
        ("le", "http://witness-demo:5642/oobi/qvi-aid/witness/wan", "qvi"),
        ("geda", "http://witness-demo:5642/oobi/le-aid/witness/wan", "le"),
        ("qvi", "http://witness-demo:5642/oobi/le-aid/witness/wan", "le"),
        ("le", "http://witness-demo:5642/oobi/le-aid/witness/wan", "le"),
    ]
    assert seen_operations == [
        ("resolve-geda", 12.5),
        ("resolve-qvi", 12.5),
        ("resolve-le", 12.5),
        ("resolve-geda", 12.5),
        ("resolve-qvi", 12.5),
        ("resolve-le", 12.5),
        ("resolve-geda", 12.5),
        ("resolve-qvi", 12.5),
        ("resolve-le", 12.5),
    ]
