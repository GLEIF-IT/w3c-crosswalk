"""Contract tests for export-equivalent CESR credential fixtures."""

from __future__ import annotations

from pathlib import Path

from keri.core import coring, counting, serdering

from vc_isomer.common import load_json_file


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def _parse_exported_credential(path: Path) -> tuple[serdering.SerderACDC, counting.Counter, coring.Prefixer, coring.Seqner, coring.Saider]:
    """Parse one `kli vc export`-equivalent CESR credential stream."""
    stream = path.read_bytes().rstrip(b"\n")
    serder = serdering.SerderACDC(raw=stream)
    attachments = bytearray(stream[serder.size:])
    counter = counting.Counter(qb64b=attachments, strip=True)
    prefixer = coring.Prefixer(qb64b=attachments, strip=True)
    seqner = coring.Seqner(qb64b=attachments, strip=True)
    saider = coring.Saider(qb64b=attachments, strip=True)
    assert not attachments
    return serder, counter, prefixer, seqner, saider


def test_vrd_cesr_fixture_matches_json_fixture_identity():
    """Ensure the VRD CESR fixture matches the canonical JSON fixture."""
    acdc = load_json_file(FIXTURES / "vrd-acdc.json")
    serder, counter, prefixer, seqner, saider = _parse_exported_credential(FIXTURES / "vrd-acdc.cesr")

    assert serder.said == acdc["d"]
    assert serder.sad["s"] == acdc["s"]
    assert counter.code == counting.CtrDex_1_0.SealSourceTriples
    assert counter.count == 1
    assert prefixer.qb64
    assert seqner.sn >= 0
    assert saider.qb64


def test_vrd_auth_cesr_fixture_matches_json_fixture_identity():
    """Ensure the VRD Auth CESR fixture matches the canonical JSON fixture."""
    acdc = load_json_file(FIXTURES / "vrd-auth-acdc.json")
    serder, counter, prefixer, seqner, saider = _parse_exported_credential(FIXTURES / "vrd-auth-acdc.cesr")

    assert serder.said == acdc["d"]
    assert serder.sad["s"] == acdc["s"]
    assert counter.code == counting.CtrDex_1_0.SealSourceTriples
    assert counter.count == 1
    assert prefixer.qb64
    assert seqner.sn >= 0
    assert saider.qb64
