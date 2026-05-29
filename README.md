# isomer

[![CI](https://github.com/GLEIF-IT/w3c-crosswalk/actions/workflows/ci.yml/badge.svg)](https://github.com/GLEIF-IT/w3c-crosswalk/actions/workflows/ci.yml)

`isomer` is the Python-first integration repo for projecting authoritative
KERI KEL, TEL, and ACDC VRD state into W3C VCDM 1.1 VC-JWT/VP-JWT artifacts
and verifying those artifacts through `did:webs`.

It is an integration product, not a general-purpose W3C verifier. The Python
verifier is authoritative for Isomer profile, TEL status, and ACDC/W3C pair
checks. The Node and Go sidecars provide independent W3C acceptance evidence.

## Reading Path

Read these in order:

1. `docs/isomer-profile.md` - the current W3C projection contract.
2. `docs/verifier-contract.md` - Python, Node, and Go verifier boundaries.
3. `docs/integration-maintainer-guide.md` - live-stack and maintainer mental model.
4. `docs/cli-e2e-walkthrough.md` - manual CLI runbook.
5. `plans/w3c-vrd-isomer-plan.md` - current roadmap.

Everything else is either implementation-specific setup, an ADR, a fixture
note, or a future/issue plan.

## Current State

Implemented:

- VRD Auth and VRD Isomer profile
- live KERI-habitat-backed VC-JWT and VP-JWT issuance
- embedded KERI-backed `eddsa-rdfc-2022` Data Integrity proofs
- `did:webs` issuer and holder verification
- Python verifier operation service
- Node and Go external verifier sidecars
- dashboard webhook target for successful verification events
- fixture contract for JSON ACDCs and export-equivalent CESR streams
- live single-sig integration flow from KERI issuance through W3C verification

Still active work:

- key rotation acceptance across Python, Node, and Go
- TEL-backed revocation rejection across Python, Node, and Go
- OpenID4VP request flow
- mobile and verifier UI surfaces
- production-grade packaging and rollout polish

## Source Map

- `src/vc_isomer/` - Python implementation and CLI.
- `tests/` - contract tests and the live integration test.
- `fixtures/` - stable profile fixtures.
- `apps/isomer-node/` - TypeScript verifier sidecar.
- `apps/isomer-go/` - Go verifier sidecar.
- `apps/isomer-dashboard/` - dashboard/webhook target.
- `packages/webs-did-resolver/` - JavaScript `did:webs` resolver package.
- `docker/` - local verifier and wallet stack wiring.
- `adrs/` - accepted implementation decisions.

## Setup

This repo uses `uv`. The distribution name is `vc-isomer`, the Python import
package is `vc_isomer`, and the CLI entrypoint is `isomer`.

```bash
UV_CACHE_DIR=$PWD/.uv-cache uv sync
```

The default dependency model is portable: packages, pinned Git SHAs, or OCI
images. Do not make repo-local scripts depend on sibling source checkouts.

## Main Commands

Fast Python contract checks:

```bash
make test-fast
```

Portable dependency regression check:

```bash
make portability-check
```

External verifier checks:

```bash
make external-node-sync
make external-node-check
make external-go-check
```

Live integration flow:

```bash
PYTHONUNBUFFERED=1 \
UV_CACHE_DIR=$PWD/.uv-cache \
./.venv/bin/python -m pytest -s -vv \
  -o log_cli=true \
  --log-cli-level=INFO \
  tests/integration/test_single_sig_vrd_isomer.py
```

Portable local stack:

```bash
make local-up
make local-seed
make local-test
make local-down
```

## Boundaries

- `isomer` owns W3C projection, verification, status projection, fixtures, and
  integration orchestration.
- `did-webs-resolver` owns DID and key-state resolution.
- `w3c-signer` is legacy reference material only.
- W3C artifacts are interoperability projections. KERI KEL/TEL/ACDC state is
  the source of truth.
