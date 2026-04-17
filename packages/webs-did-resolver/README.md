# webs-did-resolver

Small JavaScript `did:webs` method resolver package for use with
[`did-resolver`](https://www.npmjs.com/package/did-resolver).

It owns only method resolution and tightly related method helpers:

- `getResolver({ resolverUrl })` for `new Resolver({ ...getResolver(...) })`
- `canonicalizeDidWebs(...)`
- `canonicalizeDidWebsDidUrl(...)`
- `buildResolutionUrl(...)`
- `parseDidWebsResolution(...)`
- `findVerificationMethod(...)`
- `publicJwkFromMethod(...)`

It does not own VC/VP verification, Data Integrity verification, status checks,
JSON-LD context loading, or runtime orchestration.

The package does include one narrow interoperability layer for common JS JWT
consumers such as `did-jwt-vc`: it normalizes resolved Ed25519 verification
methods and expands `assertionMethod` / `authentication` references when live
`did:webs` resolver output still arrives in older or string-reference-heavy
forms.

## Example

```ts
import { Resolver } from "did-resolver";
import { getResolver } from "webs-did-resolver";

const resolver = new Resolver(getResolver({
  resolverUrl: "http://127.0.0.1:7678/1.0/identifiers"
}));

const result = await resolver.resolve("did:webs:issuer#key-1");
```

## Notes

- Query-bearing DID URLs are preserved during resolution, so `?versionId=...`
  reaches the resolver service.
- The package does not add its own persistent cache. Latest-key vs historical
  resolution is controlled by the DID URL and the backing resolver service.
- `publicJwkFromMethod(...)` can derive an Ed25519 OKP JWK from a Multikey
  `publicKeyMultibase` method when a local consumer needs a JWK view.
- Resolved DID documents are normalized only as far as needed for common JS
  JWT verifier compatibility; broader verifier policy still belongs above this
  package.
