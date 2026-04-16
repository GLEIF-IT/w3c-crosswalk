import test from "node:test";
import assert from "node:assert/strict";
import { DidWebsResolver } from "./did-resolver.js";

const PUBLIC_JWK = {
  kty: "OKP",
  crv: "Ed25519",
  x: "11qYAYKxCrfVS_3u3lIBX7hLTXruxN4B0qVd2zSYXK0"
};

test("did:webs resolver normalizes KERI key methods for did-jwt", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({
    didDocument: {
      id: "did:webs:example.com:dws:Eabc",
      verificationMethod: [{
        id: "#key-1",
        type: "JsonWebKey",
        controller: "did:webs:example.com:dws:Eabc",
        publicKeyJwk: PUBLIC_JWK
      }],
      assertionMethod: ["#key-1"]
    },
    didDocumentMetadata: {},
    didResolutionMetadata: {}
  }), { status: 200 }) as unknown as Response;

  try {
    const resolver = new DidWebsResolver("http://resolver.test/1.0/identifiers");
    const result = await resolver.resolve("did:webs:example.com:dws:Eabc");
    const didDocument = result.didDocument as Record<string, unknown>;
    const methods = didDocument.verificationMethod as Record<string, unknown>[];

    assert.equal(methods[0].type, "JsonWebKey2020");
    assert.deepEqual(didDocument.assertionMethod, [methods[0]]);
    assert.deepEqual(didDocument.authentication, [methods[0]]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
