# w3c-crosswalk

`w3c-crosswalk` is the Python-first integration repo for projecting KERI ACDC
VRD credentials into W3C VC-JWT form and verifying them through `did:webs`.

Current repo state:

- canonical crosswalk profile for VRD Auth and VRD
- live KERI-habitat-backed VC-JWT and VP-JWT issuance
- `did:webs`-backed VC-JWT and VP-JWT verification
- crosswalk-specific ACDC/W3C pair verification
- projected credential status service for revocation checks
- fixture contract for JSON ACDCs and export-equivalent CESR streams
- one live end-to-end integration test from single-sig ACDC issuance through
  VC-JWT verification

This repo is real, but it is still an integration project rather than a
finished interoperability product. The verifier is legitimate for the
crosswalk profile, not yet a full ecosystem-grade verifier.

## What Is Here

- [`src/w3c_crosswalk`](src/w3c_crosswalk): current Python implementation
- [`tests`](tests): contract tests plus the live-stack integration test
- [`fixtures`](fixtures): stable contract fixtures
- [`docs/crosswalk-profile.md`](docs/crosswalk-profile.md): current profile note
- [`docs/w3c-vc-libs-options.md`](docs/w3c-vc-libs-options.md): external verifier library options
- [`plans`](plans): execution and architecture plans

The `packages/`, `apps/`, and `scripts/demo/` directories are still repo-shape
placeholders for the longer-term monorepo layout. The active implementation is
in `src/` and `tests/`.

Read
[`docs/integration-maintainer-guide.md`](docs/integration-maintainer-guide.md)
for the live stack, workflow, and projection mental model.

## Local Setup

This repo uses `uv` and expects a local `.venv`.

Bootstrap the environment:

```bash
UV_CACHE_DIR=$PWD/.uv-cache uv sync
```

The default `uv` groups include the live integration dependencies, so a normal
sync installs:

- `keri`
- `did-webs-resolver`
- `vlei`

The live integration harness is intended to run entirely from this repo's
`.venv`. It should not require sibling repository virtualenvs or runtime file
lookups outside `w3c-crosswalk`.

Dependency sources are pinned in `pyproject.toml` through `tool.uv.sources`,
which keeps `uv sync` reproducible even when the latest PyPI releases lag the
live integration work.

### Optional Editable Overrides

If you are intentionally developing one of the dependency repos locally, you can
override the pinned source with an editable install in this environment. For
example:

```bash
uv add --editable ../keripy
uv add --editable ../did-webs-resolver
uv add --editable ../vLEI
```

When using editable overrides, direct interpreter invocations such as
`./.venv/bin/python -m pytest ...` remain the least ambiguous path.

## CLI

The repo installs one CLI entrypoint:

```bash
crosswalk --help
```

Current subcommands include:

- `issue-vc`
- `issue-vp`
- `verify-vc`
- `verify-vp`
- `verify-crosswalk`
- `status-project`
- `status-revoke`
- `status-serve`
- `verifier-serve`

All signing commands require a live KERI habitat signer. This repo does not use
demo signers.

## Fixtures

The fixture directory currently contains:

- `vrd-acdc.json`
- `vrd-auth-acdc.json`
- `vrd-acdc.cesr`
- `vrd-auth-acdc.cesr`

The JSON fixtures are real live-issued ACDC SADs from the crosswalk live test.
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
  tests/integration/test_single_sig_vrd_crosswalk.py
```

What it currently proves:

- witness-backed single-sig GEDA inception
- delegated single-sig QVI inception
- single-sig LE inception
- real QVI, LE, VRD Auth, and VRD ACDC issuance and admit flows
- `did:webs` service launch from local KERI state
- VC-JWT issuance from the live VRD ACDC
- VC-JWT verification through the crosswalk verifier and `did:webs`

This test owns the current truth of the repo more than any prose doc.

## Current Boundaries

- `w3c-crosswalk`: W3C issuance, verification, status projection, fixtures, and integration orchestration
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
