# Fixture Contract

This directory holds language-neutral fixture data for the isomer profile and
verifier contract tests.

## Purpose

- `vrd-acdc.json`: canonical VRD ACDC fixture used to test W3C projection,
  status projection, and verifier behavior.
- `vrd-auth-acdc.json`: canonical VRD Auth ACDC fixture used to test edge and
  authorization-specific projection rules.
- `vrd-acdc.cesr`: exact `kli vc export --said <VRD SAID>` style CESR stream
  for the canonical VRD credential fixture.
- `vrd-auth-acdc.cesr`: exact `kli vc export --said <VRD Auth SAID>` style CESR
  stream for the canonical VRD Auth fixture.

## Maintenance Rules

- Keep these fixtures stable unless the isomer profile itself changes.
- Treat them as contract inputs shared across Python now and `keri-ts` later.
- Prefer adding a new fixture over mutating an existing one when testing a new
  scenario or regression.
- If a fixture changes, update the related tests and any profile docs that
  describe the expected output shape.
- The `.cesr` fixtures are export-equivalent only. They intentionally match
  `kli vc export` output and do not try to represent the larger IPEX wire
  package used during `/ipex/grant`.

## Runtime Expectations

- Files in this directory are consumed as-is by unit tests and by helper code
  that loads fixture ACDCs from disk.
- Unlike the integration asset templates, these fixtures are not rendered or
  rewritten at runtime.
- `*.acdc.cesr` files contain the raw ACDC plus one seal-source-triple
  attachment, matching `keri.app.signing.serialize(...)`.
- These `.cesr` exports are not sufficient to simulate IPEX receipt on their
  own. IPEX grant delivery additionally streams issuer and subject KEL
  material, TEL material, chained source credentials, and the `/ipex/grant`
  exchange message as seen in KERIpy's `vc/export.py`, `credentialing.py`, and
  `ipex/grant.py`.
