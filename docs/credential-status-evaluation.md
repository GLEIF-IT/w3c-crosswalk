# Credential Status Evaluation

This note evaluates candidate credential status patterns for `isomer`
and maps them to ACDC, IPEX, and KERI-native registry concepts.

For how the current local status projection is wired into the live integration
stack today, see
[`integration-maintainer-guide.md`](docs/integration-maintainer-guide.md).

## Verdict

The best near-term direction is:

1. Treat the KERI TEL registry as the canonical source of truth for credential
   status.
2. Project that status into a W3C-facing Bitstring Status List publication
   model for interoperability.
3. Avoid treating issuer witness queries as the long-term primary verifier
   contract.

The key mental model is that credential status should be registry state, not a
one-off issuer lookup.

## Why This Matters In ACDC And IPEX

KERI, ACDC, and IPEX already have the right domain concepts for this problem:

- ACDCs are issued against TEL-backed registries rather than ad hoc revocation
  files.
- IPEX supports privacy-preserving issuance and exchange flows, including bulk
  issuance patterns.
- ACDC validation architecture already distinguishes registrar and observer
  roles, which is a better long-term fit than forcing every verifier to query
  an issuer-controlled endpoint.
- The ecosystem still needs a stronger production credential-status story, so
  `isomer` should avoid baking in a weak mental model too early.

Bulk issuance helps preserve privacy on the issuance side, but it does not by
itself solve credential status correlation. A verifier-facing status pattern
still needs to minimize phone-home behavior and avoid leaking too much about
individual credentials.

## Working Design Hypothesis

The strongest domain-aligned approach is:

- TEL registry state is the source of truth.
- Observer-style status publication or retrieval is preferable to direct issuer
  witness checking.
- W3C `credentialStatus` should be a projection of TEL state, not a separate
  source of truth.
- The initial W3C projection should use Bitstring Status List because it is the
  best current standards-aligned option.

This means the W3C status layer should be understood as an interoperability
surface, not the authoritative status engine.

## Option Evaluation

### Bitstring Status List

Pros:

- Best first step for W3C interoperability because it is the main
  standards-aligned status method in the current W3C VC ecosystem.
- Better privacy shape than one-endpoint-per-credential status checking because
  many credentials can share one published status list.
- Better fit than CRLs for bulk issuance because it scales well and reduces
  verifier correlation pressure.
- Can represent more than simple revocation if we map TEL state carefully,
  including suspension-oriented or richer state semantics.
- Works well as a publication format layered on top of KERI registry truth.

Cons:

- It is still only a projection layer and does not by itself encode KERI/TEL
  semantics or registry governance.
- Requires deliberate mapping from TEL state transitions into W3C status
  semantics.
- Privacy can still be weakened by poor operational choices such as tiny or
  issuer-unique lists.

### Regular CRLs

Pros:

- Easy to explain, audit, and operate.
- Familiar to operators coming from PKI and revocation list workflows.
- Acceptable for low-scale, low-privacy environments where simple revoked/not
  revoked status is enough.

Cons:

- Poor fit for privacy-sensitive or bulk-issued ACDCs because explicit
  identifiers can leak more than we want.
- Expresses revocation more naturally than richer lifecycle states such as
  suspension or other TEL transitions.
- Pushes the system toward heavier download or repeated lookup patterns without
  offering strong privacy upside.
- Feels more like retrofitted PKI than KERI/ACDC-native registry state.

### Bloom Filters

Pros:

- Compact publication model for large sets.
- Attractive on paper for denylist-style membership checks.
- Potentially privacy-friendlier than explicit enumerated revocation lists.

Cons:

- False positives are a serious problem in credential systems because a valid
  credential can appear revoked.
- Awkward for multi-state lifecycle handling such as suspend, unsuspend, and
  other registry transitions.
- Weak standards and ecosystem alignment for W3C VC status today.
- Creates custom verification semantics and interoperability debt early.

### Cryptographic Accumulators

Pros:

- Strong privacy ceiling because holders can potentially prove non-revocation
  without verifier phone-home behavior.
- Good conceptual fit for privacy-preserving selective disclosure flows.
- Strong long-term candidate for high-privacy status proofs if the ecosystem
  matures around it.

Cons:

- Operationally and cryptographically much more complex than bitstrings.
- Witness and proof freshness management is harder than the other options.
- Tooling, deployment, and standards maturity are weaker for practical VC
  interoperability today.
- High risk of overengineering before the KERI/ACDC ecosystem has settled the
  simpler production model.

## KERI And ACDC Idiomatic Mapping

The most KERI-native framing is:

- The authoritative state is in the credential registry TEL.
- Status should be retrieved from or projected by an observer-capable service,
  not by querying issuer witnesses as the permanent verifier pattern.
- Witnesses help secure key event and registry event availability, but they are
  not the ideal domain abstraction for verifier-facing credential status.
- ACDC/W3C status should be modeled as a projection of registry state into a
  verifier-consumable representation.

This matters because "query an issuer witness for credential status" is a
workable early production mental model, but it is likely the wrong final one.
It is too close to phone-home validation and does not cleanly express the
registrar/observer separation already present in ACDC architecture.

## Missed Opportunities To Consider

- Separate the status authority from the credential issuer so a dedicated KERI
  AID or service role publishes status for one or more registries.
- Support holder-stapled status artifacts in IPEX exchanges so verifiers do not
  always need live lookups.
- Model status as a richer state machine instead of only revoked/not revoked.
- Use blinded or privacy-preserving registry patterns for especially sensitive
  credential classes.
- Treat W3C status publication as one projection among several, with native
  KERI clients consuming TEL state more directly.
- Explore accumulators later for premium privacy tiers rather than as the first
  production implementation.

## Recommendation

Start with this architecture:

1. Keep TEL registry state as the source of truth.
2. Introduce a dedicated status package and service boundary.
3. Publish W3C-facing status using Bitstring Status List as the first
   interoperable projection.
4. Design the internal model so future publication formats can be added without
   changing the canonical registry semantics.

Do not lock the ecosystem into a permanent "ask the issuer witness" status
model. That is good enough for today's early deployments, but it is too narrow
and too issuer-centric to be the long-term credential status architecture for
KERI, ACDC, and IPEX.

## Sources

- [ACDC Specification](https://trustoverip.github.io/kswg-acdc-specification/)
- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model/)
- [W3C Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/)
