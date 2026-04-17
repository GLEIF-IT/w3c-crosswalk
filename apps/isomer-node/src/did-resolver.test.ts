/**
 * Resolver normalization tests for the `did:webs` adapter layer.
 *
 * These tests focus on the interop seam where resolver output is normalized
 * into the JWK-oriented material expected by the Node JWT stack.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { DidWebsResolver, findVerificationMethod, publicJwkFromMethod } from "./did-resolver.js";

// Stable public JWK fixture representing a resolver result that is already in a
// did-jwt-friendly form.
const PUBLIC_JWK = {
  kty: "OKP",
  crv: "Ed25519",
  x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
};

test("publicJwkFromMethod returns an existing JWK unchanged", () => {
  const method = {
    id: "did:webs:issuer#key-1",
    type: "JsonWebKey2020",
    publicKeyJwk: PUBLIC_JWK
  };

  assert.deepEqual(publicJwkFromMethod(method), PUBLIC_JWK);
});

test("findVerificationMethod resolves document-scoped references", () => {
  const didDocument = {
    verificationMethod: [{
      id: "did:webs:issuer#key-1",
      type: "JsonWebKey2020",
      publicKeyJwk: PUBLIC_JWK
    }]
  };

  assert.deepEqual(
    findVerificationMethod(didDocument, "#key-1"),
    didDocument.verificationMethod[0]
  );
});

test("DidWebsResolver normalizes resolved DID documents", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    return new Response(JSON.stringify({
      didDocument: {
        id: "did:webs:issuer",
        verificationMethod: [{
          id: "did:webs:issuer#key-1",
          type: "Multikey",
          publicKeyMultibase: "z6MkpTHR8VNsBxYAAWHut2Geadd9jccv8Wz8C9kvQ7AYx8aL"
        }],
        assertionMethod: ["#key-1"]
      }
    }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };

  try {
    const resolver = new DidWebsResolver("http://resolver.test/1.0/identifiers");
    const result = await resolver.resolve("did:webs:issuer");
    const didDocument = result.didDocument as Record<string, unknown>;
    const methods = didDocument.verificationMethod as Array<Record<string, unknown>>;

    assert.equal(Array.isArray(methods), true);
    assert.equal(typeof methods[0]?.publicKeyJwk, "object");
    assert.equal(Array.isArray(didDocument.assertionMethod), true);
    assert.equal(typeof (didDocument.assertionMethod as Array<unknown>)[0], "object");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("DidWebsResolver caches by base DID", async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return new Response(JSON.stringify({
      didDocument: {
        id: "did:webs:issuer",
        verificationMethod: [{
          id: "did:webs:issuer#key-1",
          type: "JsonWebKey2020",
          publicKeyJwk: PUBLIC_JWK
        }]
      }
    }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };

  try {
    const resolver = new DidWebsResolver("http://resolver.test/1.0/identifiers");
    await resolver.resolve("did:webs:issuer#key-1");
    await resolver.resolve("did:webs:issuer#key-2");
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
