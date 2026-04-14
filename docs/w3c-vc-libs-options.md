# W3C VC Library Options

This note captures realistic candidates for a secondary W3C VC verifier so
`w3c-crosswalk` is not relying only on its own hand-rolled VC-JWT verifier.

## Verdict

The strongest practical secondary-verifier candidates are currently:

1. `did-jwt-vc` for a lightweight ecosystem cross-check
2. Veramo `@veramo/credential-w3c` for a fuller TypeScript verifier stack
3. TrustBloc `vc-go` / `vcs` if we want a more production-grade independent
   implementation and are willing to accept higher integration cost

Python is weak here for VC-JWT interoperability. The only Python-side option
worth serious consideration is DIDKit's Python binding, and even that is
really a Rust verifier exposed through Python rather than a native Python
ecosystem choice.

## Current `w3c-crosswalk` verifier legitimacy

Our verifier in [`src/w3c_crosswalk/verifier.py`](src/w3c_crosswalk/verifier.py)
is legitimate as a project verifier because it:

- resolves issuer DID state through `did:webs`
- verifies EdDSA signatures against the resolved JWK
- checks projected status/revocation
- verifies embedded VC-JWTs inside VP-JWTs
- enforces crosswalk-specific ACDC/W3C equivalence rules

It is not yet a spec-grade or ecosystem-grade verifier because it does not try
to implement the full breadth of JOSE/VC validation expected by external W3C
libraries, and our emitted VC-JWT shape is still a crosswalk-specific profile.

## Primary Candidates

### 1. `did-jwt-vc`

- Source: [GitHub](https://github.com/decentralized-identity/did-jwt-vc)
- Package: [npm `did-jwt-vc`](https://www.npmjs.com/package/did-jwt-vc)
- Ecosystem fit: DIF-adjacent, direct JWT VC verifier, relatively lightweight
- Strengths:
  - purpose-built for VC/VP over JWT
  - easy to use as a sidecar verification harness
  - likely the fastest route to an independent second opinion
- Weaknesses:
  - historically aligned with the older JWT-VC model (`iss`, `sub`, `vc`, `vp`)
  - may reject or misinterpret our current VC-JWT payload shape
- Recommendation:
  - this should be the first external verifier we try
  - if it fails, treat that as signal about payload interoperability, not just
    library weakness

### 2. Veramo `@veramo/credential-w3c`

- Docs: [Veramo verifiable data](https://veramo.io/docs/basics/verifiable_data/)
- API: [Credential plugin docs](https://veramo.io/docs/api/credential-w3c.credentialplugin/)
- Package: [npm `@veramo/credential-w3c`](https://www.npmjs.com/package/@veramo/credential-w3c)
- Ecosystem fit: widely known SSI framework, more complete stack than a small
  one-off verifier
- Strengths:
  - supports verifying credentials and presentations
  - gives us a realistic independent verifier stack, not just a tiny helper
  - likely more future-proof if we add broader W3C workflows later
- Weaknesses:
  - heavier than `did-jwt-vc`
  - introduces more framework surface than we need for a narrow cross-check
  - may still expect a more mainstream VC-JWT shape than our current profile
- Recommendation:
  - best second choice if `did-jwt-vc` is too old, too narrow, or too awkward

### 3. TrustBloc `vc-go` / `vcs`

- Repo family: [TrustBloc VCS](https://github.com/trustbloc/vcs)
- Ecosystem fit: serious verifier/issuer stack, not just a sample utility
- Strengths:
  - strong “independent implementation” value
  - useful if we want a production-oriented cross-check instead of only a JS
    library harness
- Weaknesses:
  - significantly higher setup and integration cost
  - Go sidecar is heavier than a Node harness for our current needs
- Recommendation:
  - consider this if we want stronger assurance after a TypeScript-side check
  - not the first thing to integrate

## Python Options

### 4. DIDKit Python

- Package: [PyPI `didkit`](https://pypi.org/project/didkit/)
- Underlying project family: SpruceID SSI / DIDKit
- Ecosystem fit: the only Python-adjacent option that is plausibly worth
  trying for real verification work
- Strengths:
  - independent implementation lineage from our code
  - Python-callable
  - backed by the broader SSI/DIDKit stack rather than a tiny utility
- Weaknesses:
  - not a native Python verifier in spirit; it is Rust exposed to Python
  - more opaque to debug than a TypeScript harness
  - may still require alignment with expected VC-JWT conventions
- Recommendation:
  - best Python-side honorable mention
  - worth trying only if staying in Python matters more than speed of adoption

## Honorable Mentions

### 5. SpruceID `ssi`

- Repo: [SpruceID SSI](https://github.com/spruceid/ssi)
- Strengths:
  - substantial SSI implementation
  - good independent implementation lineage
- Weaknesses:
  - less convenient for our repo than DIDKit or a JS verifier harness
  - better thought of as the core behind DIDKit than as our first integration

### 6. `@cef-ebsi/verifiable-credential`

- Package: [npm `@cef-ebsi/verifiable-credential`](https://www.npmjs.com/package/%40cef-ebsi/verifiable-credential)
- Strengths:
  - real JWT VC verification library
  - independent from our code
- Weaknesses:
  - EBSI-specific validation semantics
  - not a clean generic verifier for our crosswalk profile
- Recommendation:
  - useful as a comparison point, not a first-choice verifier

### 7. `vc-verifier` (Python)

- Package: [PyPI `vc-verifier`](https://pypi.org/project/vc-verifier/)
- Strengths:
  - active Python verifier project
  - useful if we later care about Data Integrity and `did:web`
- Weaknesses:
  - current focus is Data Integrity, not VC-JWT
  - not the right secondary verifier for our current JWT-first cross-check need

### 8. GS1 `vc-verifier-core`

- Repo: [GS1 vc-verifier-core](https://github.com/gs1us-technology/vc-verifier-core)
- Strengths:
  - shows how a real verifier composes external VC libraries
  - useful reference architecture
- Weaknesses:
  - example verifier, not the cleanest drop-in library for us
  - better as a reference than as the first integration target

## Recommended Next Step

1. Add a small Node-based secondary verification harness using `did-jwt-vc`.
2. Feed it the VC-JWTs produced by the live crosswalk integration test.
3. Record whether it accepts or rejects them, and why.
4. If it rejects them, compare the failure against [W3C VC JOSE/COSE](https://www.w3.org/TR/vc-jose-cose/) expectations before changing our payload shape.
5. If `did-jwt-vc` proves too outdated for the shape we want, move to Veramo as
   the next serious cross-check.

## Working Mental Model

- Our current verifier is necessary because it knows about crosswalk-specific
  lineage, ACDC provenance, and projected KERI status.
- An external verifier is still valuable because it tells us whether our
  VC-JWTs are understandable outside the crosswalk codebase.
- The real question is not “can another library verify Ed25519 JWTs?”
- The real question is “does our emitted VC-JWT shape interoperate with an
  independent W3C ecosystem implementation?”
