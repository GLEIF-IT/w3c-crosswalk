#!/usr/bin/env python3
"""Validate local Docker witness controller OOBIs before KERIA starts."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import sys
import time
from urllib.error import URLError
from urllib.request import Request, urlopen


CONTENT_TYPE = "application/json+cesr"


@dataclass(frozen=True)
class WitnessProbe:
    name: str
    aid: str
    port: int
    expected_curl: str

    @property
    def url(self) -> str:
        display_name = self.name.capitalize()
        return (
            f"http://127.0.0.1:{self.port}/oobi/{self.aid}/controller"
            f"?name={display_name}&tag=witness"
        )


WITNESSES = (
    WitnessProbe(
        name="wan",
        aid="BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha",
        port=5642,
        expected_curl="http://witness-demo:5642/",
    ),
    WitnessProbe(
        name="wil",
        aid="BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM",
        port=5643,
        expected_curl="http://witness-demo:5643/",
    ),
    WitnessProbe(
        name="wes",
        aid="BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX",
        port=5644,
        expected_curl="http://witness-demo:5644/",
    ),
)


def main() -> int:
    args = parse_args()
    deadline = time.monotonic() + args.timeout
    last_error = "not checked yet"

    while time.monotonic() < deadline:
        try:
            for witness in WITNESSES:
                validate_witness(witness)
        except Exception as exc:  # noqa: BLE001 - health check should report any readiness miss
            last_error = str(exc)
            time.sleep(args.interval)
            continue
        return 0

    print(f"witness OOBIs did not become healthy: {last_error}", file=sys.stderr)
    return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--interval", type=float, default=0.2)
    return parser.parse_args()


def validate_witness(witness: WitnessProbe) -> None:
    payload, content_type = fetch(witness.url)
    if CONTENT_TYPE not in content_type:
        raise ValueError(f"{witness.name} OOBI has content-type {content_type!r}, expected {CONTENT_TYPE}")

    text = payload.decode("utf-8", errors="replace")
    expected_fragments = {
        "inception event": f'"i":"{witness.aid}"',
        "controller route": '"/end/role/add"',
        "loc scheme route": '"/loc/scheme"',
        "Docker witness curl": witness.expected_curl,
    }
    missing = [name for name, fragment in expected_fragments.items() if fragment not in text]
    if missing:
        raise ValueError(
            f"{witness.name} controller OOBI is missing {', '.join(missing)}; "
            "witness curls config is not producing a usable introduction payload"
        )


def fetch(url: str) -> tuple[bytes, str]:
    request = Request(url, headers={"Accept": CONTENT_TYPE}, method="GET")
    try:
        with urlopen(request, timeout=0.75) as response:
            if response.status != 200:
                raise ValueError(f"{url} returned HTTP {response.status}")
            return response.read(), response.headers.get("Content-Type", "")
    except URLError as exc:
        raise ValueError(f"{url} could not be fetched: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
