# ADR-003 - Use Pinned Local JSON-LD Contexts for `isomer-node` Verification

## Status

Implemented

## Context

`isomer-node` verifies Isomer VCDM 1.1 VC-JWT and VP-JWT artifacts as an
independent Node-based W3C acceptance sidecar. Its verification flow includes
embedded `DataIntegrityProof` verification, which depends on JSON-LD expansion,
RDF conversion, and URDNA2015 canonicalization.

That means JSON-LD context loading is not a cosmetic concern. It directly
affects the byte sequence that is hashed and signed during proof verification.

`isomer-node` currently uses a local pinned context loader in
[`../apps/isomer-node/src/local-contexts.ts`](../apps/isomer-node/src/local-contexts.ts)
instead of fetching remote contexts at verification time. The loader recognizes
only the small set of contexts used by current Isomer artifacts:

- `https://www.w3.org/2018/credentials/v1`
- `https://w3id.org/security/data-integrity/v2`
- `https://www.gleif.org/contexts/isomer-v1.jsonld`

This behavior matches the actual role of the sidecar today:

- it is an external verifier for the closed Isomer profile,
- it is not a general-purpose verifier for arbitrary ecosystem credentials,
- it is expected to validate the same known artifact shapes that the Python
  Isomer implementation emits.

The question is whether production hardening should replace this pinned loader
with remote context fetches at verification time.

That broader fetch model has real costs:

1. Verification becomes dependent on third-party network reachability.
2. The verifier gains a larger SSRF-style fetch surface.
3. Debugging and incident response get harder because context availability and
   content become runtime variables.
4. Mutable or drifting remote context behavior can change verification outcomes
   without any local code change.
5. The verifier moves away from deterministic closed-world validation and
   toward open-world trust assumptions it does not otherwise need.

For the current Isomer profile, those costs do not buy corresponding value.
The sidecar's job is to verify Isomer artifacts predictably, not to accept
arbitrary external credential profiles by default.

## Decision

Keep `isomer-node` on pinned local JSON-LD context loading by default.

Specifically:

- `isomer-node` must continue using a local context loader for current Isomer
  profile verification.
- Verification must not fetch arbitrary remote JSON-LD contexts at runtime.
- The recognized context set should remain explicit and versioned in source.
- Adding support for a new context is a conscious profile/update decision, not
  an implicit runtime behavior change.
- This local context model is treated as a production strength for the current
  Isomer verifier role: deterministic, offline-stable, and narrower in attack
  surface.

This decision is scoped to the current Isomer sidecar role.

It does **not** say that no future verifier may ever support broader context
resolution. It says that the current `isomer-node` production posture is
closed-world by design.

## Consequences

`isomer-node` verification remains deterministic for the current Isomer
artifact set.

Production verification does not depend on remote context hosts being up,
reachable, or unchanged.

The sidecar keeps a smaller network and security surface because verification
does not perform arbitrary runtime context fetches.

Maintainers can reason about proof verification from repo-tracked assets
instead of debugging remote context behavior during incidents.

The sidecar is explicitly a verifier for the Isomer profile, not a generic
open-world W3C verifier.

When Isomer artifacts introduce a new context, maintainers must vendor or pin
that context explicitly and update the loader intentionally.

## Other Options Considered

### Fetch arbitrary remote JSON-LD contexts at verification time

Rejected.

That option weakens determinism, expands runtime trust and network dependence,
and adds unnecessary attack surface for the current closed-world Isomer use
case.

### Support a controlled future expansion model

Deferred, not rejected.

If `isomer-node` later needs to verify a broader set of credential profiles,
the safer expansion path would be:

- explicit allowlisting,
- vendored mirrors or pinned caches,
- strict timeout and size limits,
- and a clear failure policy for unknown contexts.

That is a separate future decision, not part of the current production posture.
