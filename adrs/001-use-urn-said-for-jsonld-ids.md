# ADR-001 - Use `urn:said:` For JSON-LD IDs Derived From ACDC SAIDs

## Status

Implemented

## Context

Isomer projects KERI/ACDC credentials into W3C VCDM 1.1 JSON-LD credentials and
signs them with `eddsa-rdfc-2022` Data Integrity proofs. That means the emitted
credential must survive JSON-LD expansion, RDF conversion, and URDNA2015
canonicalization across multiple implementations.

A raw ACDC SAID such as `EABC...` is a KERI-native identifier string, but it is
not an absolute IRI. In JSON-LD, any field used as an `id` is processed as an
`@id` value. Bare SAIDs in those positions are therefore interpreted as
**relative** IRIs.

Relative IRIs in RDF identifier positions are **not safe** for this profile:

- JSON-LD to RDF processing expects `@id` values to be absolute IRIs or blank
  node identifiers.
- External JSON-LD implementations can skip or degrade relative subject/object
  references during RDF conversion.
- Once that happens, URDNA2015 canonicalization and Data Integrity proof
  verification can drift across implementations even if the original JSON looks
  superficially correct.

This matters because the Data Integrity pipeline depends on four invariants:

1. The W3C JSON-LD document must convert into one exact RDF dataset.
2. That RDF dataset must carry the same meaning across implementations.
3. The proof hash and signature must be computed over that same exact dataset.
4. If one implementation drops, rewrites, or resolves an identifier
   differently, verification fails even when the source JSON appears
   superficially similar.

This failure mode was observed most clearly for nested
`credentialSubject.legalEntityCredential.id`, where a bare SAID caused
cross-implementation interoperability risk. The same semantic problem applies
to any W3C JSON-LD `id` field carrying a raw SAID, including the top-level VC
`id`.

We still need to preserve the original SAID value because it is the KERI/ACDC
source identifier used by pair verification, status projection, and maintainer
inspection.

## Decision

When a KERI/ACDC SAID is emitted into a W3C JSON-LD field whose meaning is
identifier-like, represent it as `urn:said:<SAID>`.

Apply this rule to the current Isomer profile wherever a SAID becomes a W3C
`id`, including:

- the top-level VC `id`
- nested credential references such as
  `credentialSubject.legalEntityCredential.id`

Do not treat `urn:said:<SAID>` as a replacement for the underlying KERI-native
SAID in internal logic. Keep the raw SAID in explicit provenance and status
fields where the profile needs the original value as data rather than as a
JSON-LD identifier.

## Consequences

JSON-LD `id` values derived from SAIDs become absolute IRIs and are safe for
RDF conversion and URDNA2015 canonicalization.

Python, Node, and Go verifiers have a stable identifier form to process during
Data Integrity verification.

The W3C projection remains faithful to the original KERI identifier because the
SAID payload is preserved losslessly inside the URN suffix.

The profile must distinguish between two representations of the same source
identifier:

- raw SAID for KERI-native provenance and status data
- `urn:said:<SAID>` for W3C JSON-LD `id` positions

Callers and tests must not compare a W3C JSON-LD `id` field directly to a raw
SAID without normalizing the representation.

This ADR does not imply that every SAID-shaped string in the credential should
be rewritten as a URN. The rule is specific to fields that are emitted as W3C
JSON-LD identifiers.

## Other Options Considered

Using bare SAIDs directly in W3C JSON-LD `id` fields.

That option was rejected because bare SAIDs are not absolute IRIs and therefore
are not a reliable cross-implementation representation for JSON-LD/RDF-based
proof processing.
