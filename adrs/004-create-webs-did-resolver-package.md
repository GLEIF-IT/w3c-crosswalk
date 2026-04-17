# ADR-004 - Create A Shared JavaScript `did:webs` Resolver Package

## Status

Implemented

## Context

`apps/isomer-node` verifies Isomer VC-JWT and VP-JWT artifacts through standard
Node JWT tooling. After the 2026-04-17 maintainability cleanup, the sidecar now
has clearer command, runtime, JWT, proof, and status seams, and ADR-003
explicitly keeps JSON-LD context loading local and pinned.

That cleanup left one remaining architectural mismatch: `did:webs` method
resolution still lived inside the app as a local `DidWebsResolver` adapter in
`apps/isomer-node/src/did-resolver.ts`.

That local class worked, but it was not the ecosystem-typical JavaScript DID
shape. The normal JS pattern is:

```ts
import { Resolver } from "did-resolver";
import { getResolver } from "some-did-method-package";

const resolver = new Resolver({
  ...getResolver(...)
});
```

The repo already had two sources of truth for the resolver behavior we cared
about:

- Python `did:webs` helper logic in `src/vc_isomer/didwebs.py` and
  `tests/test_didwebs.py`
- Node helper logic in the former `apps/isomer-node/src/did-resolver.ts` and
  its tests

Those implementations proved the required semantics:

- canonicalize malformed local `did:webs:host:port:...` values into `%3A`
  host-port form
- build resolver URLs that leave the DID raw and let the transport apply one
  encoding layer
- accept resolver envelope responses or raw DID documents
- find verification methods by full ID or fragment
- derive a JWK view from Multikey Ed25519 verification methods for local JWK
  consumers
- normalize older `JsonWebKey` Ed25519 method types and string relationship
  references into the narrower shape common JS JWT consumers actually accept

At the same time, the old app-local resolver had two problems:

1. It packaged method logic in the wrong place.
2. It cached by bare DID, which becomes incorrect once query-bearing DID URLs
   such as `?versionId=...` matter.

The goal is therefore not to make the verifier smarter. The goal is to move
`did:webs` method resolution into a reusable `getResolver(...)` package and
leave VC/VP verification policy in the verifier app.

## Decision

Add `packages/webs-did-resolver` as a standalone TypeScript package.

The package owns only `did:webs` method resolution and tightly related method
helpers:

- `getResolver({ resolverUrl, ... })`
- DID canonicalization helpers
- resolver URL construction
- resolver response parsing and validation
- verification-method lookup
- explicit JWK derivation from supported Multikey methods
- narrow DID document compatibility normalization for common JS JWT consumers

The package must:

- integrate through `did-resolver`'s standard method-registry shape
- preserve DID URL query parameters during resolution, including `versionId`
- strip only fragments before resolution requests
- keep normalization minimal and method-scoped
- limit DID document mutation to the Ed25519 method and relationship shaping
  repeatedly needed by common JS JWT consumers such as `did-jwt-vc`
- avoid package-owned persistent caching in v1

`apps/isomer-node` now consumes the package through:

```ts
new Resolver(getResolver({ resolverUrl }))
```

The sidecar still owns VC/VP verification, embedded Data Integrity proof
verification, status checks, local JSON-LD contexts, and Effection runtime
orchestration.

## Consequences

`isomer-node` becomes more ecosystem-typical without changing its W3C-side
verification model.

`did:webs` method resolution becomes reusable outside the Node sidecar.

`versionId` support is now correct by construction because the resolver package
preserves query-bearing DID URLs and avoids the old cache-by-bare-DID behavior.

The interop seam is narrower and easier to reason about:

- method-specific DID logic in `packages/webs-did-resolver`
- verifier policy in `apps/isomer-node`

The package does not attempt to become a verifier framework. It does not own:

- VC/VP JWT validation
- Data Integrity proof verification
- credential status evaluation
- JSON-LD context loading
- Hono or Effection runtime concerns

## Other Options Considered

### Keep `DidWebsResolver` app-local

Rejected.

It works, but it hides reusable method logic inside one app and keeps the JS
DID integration story less standard than it should be.

### Expand the package to own verifier-policy concerns

Rejected.

That would mix method resolution with VC/VP verification policy and recreate
the layering problem in a different package.

### Keep cache-by-bare-DID behavior

Rejected.

That is wrong once query-bearing DID URLs such as `?versionId=...` are part of
the contract.

### Avoid any resolved-document compatibility normalization

Rejected.

In theory that separation is cleaner. In practice, the live `did:webs`
documents still need a narrow amount of shaping before common JS JWT consumers
reliably recognize their Ed25519 verification methods.

### Mutate resolved DID documents into a broad app-specific verifier shape

Rejected.

The package may normalize the specific Ed25519 method seams required for common
JS JWT consumption, but it should not grow into a general verifier-policy or
application-shaping layer.
