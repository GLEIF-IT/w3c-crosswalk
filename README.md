# isomer
[![CI](https://github.com/GLEIF-IT/w3c-crosswalk/actions/workflows/ci.yml/badge.svg)](https://github.com/GLEIF-IT/w3c-crosswalk/actions/workflows/ci.yml)

`isomer` is the Python-first integration repo for projecting KERI KEL, TEL,
and ACDC VRD state into VCDM 1.1 JSON-LD credentials, enveloping them as
VC-JWT/VP-JWT artifacts, and verifying them through `did:webs`.


This repo is an integration project rather than a finished interoperability product.

Read
[`docs/integration-maintainer-guide.md`](docs/integration-maintainer-guide.md)
for the live stack, workflow, and projection mental model.

Read [`docs/cli-e2e-walkthrough.md`](docs/cli-e2e-walkthrough.md) for a
copy-pasteable CLI walkthrough of the isomer-specific end-to-end flow.

## CLI

The repo installs one CLI entrypoint:

```bash
isomer --help
```

Current subcommands include:

- `isomer vc issue`
- `isomer vc verify`
- `isomer vc verify-pair`
- `isomer vp issue`
- `isomer vp verify`
- `isomer status project`
- `isomer status serve`
- `isomer verifier serve`
- `isomer verifier worker serve`

All signing commands require a live KERI habitat signer. This repo does not use
demo signers. All verify commands talk to the long-running verifier operation
service rather than invoking verifier logic directly in the CLI process. They
wait for completion and use the process exit code for pass/fail instead of
printing verifier operation documents.

VC-JWTs use the VCDM 1.1 `vc` claim with mirrored `iss`, `sub`, `jti`, `iat`,
and `nbf` claims. VP-JWTs use the VCDM 1.1 `vp` claim with holder signing.
The `vc+jwt` and `vp+jwt` strings in CLI output are result families, not the
JOSE `typ` header; the JOSE header uses `typ: "JWT"` for VCDM 1.1
compatibility.

For an end-to-end CLI walkthrough, including status projection, VC issuance,
and verifier checks, see
[`docs/cli-e2e-walkthrough.md`](docs/cli-e2e-walkthrough.md).

## Local Setup

Bootstrap the environment:

```bash
uv sync
```

Once published, install the package with:

```bash
pip install vc-isomer
```

The default `uv` groups include the live integration dependencies, so a normal
sync installs:

- `keri`
- `did-webs-resolver`
- `vlei`

### Integration Tests

The live integration harness is intended to run entirely from this repo's
`.venv`.

## Publishing

Publishing uses `uv build` and `uv publish` through the repo `Makefile`.

Run the full pre-publish gate:

```bash
make prepublish
```

Publish to PyPI:

```bash
PYPI_TOKEN=... make publish
```

The publish targets refuse to upload from a dirty worktree unless
`ALLOW_DIRTY=1` is set.

## Fixtures

The fixture directory currently contains:

- `vrd-acdc.json`
- `vrd-auth-acdc.json`
- `vrd-acdc.cesr`
- `vrd-auth-acdc.cesr`

The JSON fixtures are real live-issued ACDC SADs from the isomer live test.
The CESR fixtures are exact `kli vc export --said ...` style exports of those
same credentials.

Important distinction:

- the `.cesr` files are export-equivalent only
- they are not full IPEX-grant bundles
- an IPEX grant path also requires KEL material, TEL material, any chained
  source credentials, and the `/ipex/grant` exchange message

See [`fixtures/README.md`](fixtures/README.md) for the fixture contract.

## Testing

### Fast contract tests

These are the normal fast checks for profile projection, JWT behavior, status,
verifier logic, and CESR fixture integrity:

```bash
./.venv/bin/python -m pytest \
  tests/test_cesr_fixtures.py \
  tests/test_profile.py \
  tests/test_jwt.py \
  tests/test_status.py \
  tests/test_verifier.py -q
```

### Live end-to-end test

This is the current flagship integration test:

```bash
PYTHONUNBUFFERED=1 \
UV_CACHE_DIR=$PWD/.uv-cache \
./.venv/bin/python -m pytest -s -vv \
  -o log_cli=true \
  --log-cli-level=INFO \
  tests/integration/test_single_sig_vrd_isomer.py
```

What it currently proves:

- witness-backed single-sig GEDA inception
- delegated single-sig QVI inception
- single-sig LE inception
- real QVI, LE, VRD Auth, and VRD ACDC issuance and admit flows
- `did:webs` service launch from local KERI state
- VC-JWT issuance from the live VRD ACDC
- verifier-operation submission, polling, and final VC-JWT / isomer-pair
  verification through `did:webs`

This test owns the current truth of the repo more than any prose doc.

## Current Boundaries

- `isomer`: W3C issuance, verification, status projection, fixtures, and integration orchestration
- `did-webs-resolver`: DID and key-state resolution
- `wallet`: future issuer/holder integration target
- `sally`: future ACDC-native verification target
- `w3c-signer`: legacy reference only, not a runtime foundation

## Current Gaps

Still not done:

- external secondary verifier integration
- wallet integration
- Sally integration
- broader VP/OpenID4VP workflows
- polished packaging and rollout ergonomics

So the right mental model is:

- this repo already has a real ACDC-to-W3C live path
- the path is test-backed
- but interoperability hardening and ecosystem verification are still active work
