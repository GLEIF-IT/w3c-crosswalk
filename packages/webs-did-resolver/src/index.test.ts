import assert from "node:assert/strict";
import test from "node:test";
import { Resolver } from "did-resolver";
import {
  DidWebsResolverError,
  buildResolutionUrl,
  canonicalizeDidWebs,
  canonicalizeDidWebsDidUrl,
  findVerificationMethod,
  getResolver,
  parseDidWebsResolution,
  publicJwkFromMethod
} from "./index.js";

const PUBLIC_JWK = {
  kty: "OKP",
  crv: "Ed25519",
  x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
};

const MULTIKEY_METHOD = {
  id: "did:webs:issuer#key-1",
  type: "Multikey",
  publicKeyMultibase: "z6MkpTHR8VNsBxYAAWHut2Geadd9jccv8Wz8C9kvQ7AYx8aL"
};

test("canonicalizeDidWebs repairs malformed host-port DIDs", () => {
  assert.equal(
    canonicalizeDidWebs(
      "did:webs:127.0.0.1:59649:dws:EDiRogF6HnCw35tZ_lbGxGPQr527od6D_Uc6LNr6Xi_d"
    ),
    "did:webs:127.0.0.1%3A59649:dws:EDiRogF6HnCw35tZ_lbGxGPQr527od6D_Uc6LNr6Xi_d"
  );
});

test("canonicalizeDidWebsDidUrl preserves query and fragment while normalizing DID", () => {
  assert.equal(
    canonicalizeDidWebsDidUrl(
      "did:webs:127.0.0.1:59649:dws:issuer?versionId=2#key-1"
    ),
    "did:webs:127.0.0.1%3A59649:dws:issuer?versionId=2#key-1"
  );
});

test("buildResolutionUrl strips fragment and preserves query", () => {
  assert.equal(
    buildResolutionUrl(
      "http://127.0.0.1:59650/1.0/identifiers",
      "did:webs:127.0.0.1:59649:dws:issuer?versionId=2#key-1"
    ),
    "http://127.0.0.1:59650/1.0/identifiers/did:webs:127.0.0.1%3A59649:dws:issuer?versionId=2"
  );
});

test("buildResolutionUrl preserves the single-encoding contract for the DID segment", () => {
  const url = buildResolutionUrl(
    "http://127.0.0.1:59650/1.0/identifiers",
    "did:webs:127.0.0.1%3A59649:dws:issuer"
  );

  assert.equal(
    encodeURIComponent(url.split("/").at(-1) ?? ""),
    "did%3Awebs%3A127.0.0.1%253A59649%3Adws%3Aissuer"
  );
});

test("parseDidWebsResolution accepts a resolver envelope", () => {
  const result = parseDidWebsResolution("did:webs:issuer", {
    didDocument: {
      id: "did:webs:issuer",
      verificationMethod: [MULTIKEY_METHOD]
    },
    didDocumentMetadata: { versionId: "2" },
    didResolutionMetadata: { contentType: "application/did+ld+json" }
  }, 200);

  assert.equal(result.didDocument?.id, "did:webs:issuer");
  assert.deepEqual(result.didDocumentMetadata, { versionId: "2" });
  assert.deepEqual(result.didResolutionMetadata, { contentType: "application/did+ld+json" });
});

test("parseDidWebsResolution normalizes JsonWebKey methods and relationship references for JWT consumers", () => {
  const result = parseDidWebsResolution("did:webs:issuer", {
    didDocument: {
      id: "did:webs:issuer",
      verificationMethod: [{
        id: "did:webs:issuer#key-1",
        type: "JsonWebKey",
        controller: "did:webs:issuer",
        publicKeyJwk: PUBLIC_JWK
      }],
      assertionMethod: ["#key-1"]
    }
  }, 200);

  const didDocument = result.didDocument as Record<string, unknown>;
  const methods = didDocument.verificationMethod as Array<Record<string, unknown>>;
  const assertionMethod = didDocument.assertionMethod as Array<Record<string, unknown>>;
  const authentication = didDocument.authentication as Array<Record<string, unknown>>;

  assert.equal(methods[0]?.type, "JsonWebKey2020");
  assert.equal(assertionMethod[0]?.id, "did:webs:issuer#key-1");
  assert.equal(authentication[0]?.id, "did:webs:issuer#key-1");
});

test("parseDidWebsResolution accepts a raw DID document", () => {
  const result = parseDidWebsResolution("did:webs:issuer", {
    id: "did:webs:issuer",
    verificationMethod: [MULTIKEY_METHOD]
  }, 200);

  assert.equal(result.didDocument?.id, "did:webs:issuer");
  assert.deepEqual(result.didDocumentMetadata, {});
  assert.deepEqual(result.didResolutionMetadata, {});
});

test("parseDidWebsResolution rejects missing verificationMethod", () => {
  assert.throws(
    () => parseDidWebsResolution("did:webs:issuer", { id: "did:webs:issuer" }, 200),
    (error: unknown) => error instanceof DidWebsResolverError &&
      error.message === "resolver response did not contain a usable didDocument for did:webs:issuer"
  );
});

test("parseDidWebsResolution rejects mismatched didDocument ids", () => {
  assert.throws(
    () => parseDidWebsResolution("did:webs:issuer?versionId=2", {
      id: "did:webs:other",
      verificationMethod: [MULTIKEY_METHOD]
    }, 200),
    (error: unknown) => error instanceof DidWebsResolverError &&
      error.message === "resolved didDocument.id did not match requested did:webs DID did:webs:issuer"
  );
});

test("parseDidWebsResolution rejects HTTP failures", () => {
  assert.throws(
    () => parseDidWebsResolution("did:webs:issuer", { error: "not found" }, 404),
    (error: unknown) => error instanceof DidWebsResolverError &&
      error.code === "notFound"
  );
});

test("findVerificationMethod matches full and fragment references", () => {
  const didDocument = {
    verificationMethod: [
      { id: "did:webs:issuer#key-1", type: "JsonWebKey2020", publicKeyJwk: PUBLIC_JWK }
    ]
  };

  assert.deepEqual(findVerificationMethod(didDocument, "did:webs:issuer#key-1"), didDocument.verificationMethod[0]);
  assert.deepEqual(findVerificationMethod(didDocument, "#key-1"), didDocument.verificationMethod[0]);
  assert.deepEqual(findVerificationMethod(didDocument, "key-1"), didDocument.verificationMethod[0]);
});

test("publicJwkFromMethod returns an existing JWK unchanged", () => {
  const method = {
    id: "did:webs:issuer#key-1",
    type: "JsonWebKey2020",
    publicKeyJwk: PUBLIC_JWK
  };

  assert.deepEqual(publicJwkFromMethod(method), PUBLIC_JWK);
});

test("publicJwkFromMethod derives a JWK from an Ed25519 Multikey method", () => {
  assert.deepEqual(publicJwkFromMethod(MULTIKEY_METHOD), {
    kty: "OKP",
    crv: "Ed25519",
    x: "lJZrfAjkBXdfjebMHEUI9usijlNo6rXI7VeM4XItq7E"
  });
});

test("parseDidWebsResolution synthesizes publicKeyJwk for Multikey methods when possible", () => {
  const result = parseDidWebsResolution("did:webs:issuer", {
    didDocument: {
      id: "did:webs:issuer",
      verificationMethod: [MULTIKEY_METHOD],
      assertionMethod: ["#key-1"]
    }
  }, 200);

  const didDocument = result.didDocument as Record<string, unknown>;
  const methods = didDocument.verificationMethod as Array<Record<string, unknown>>;

  assert.deepEqual(methods[0]?.publicKeyJwk, {
    kty: "OKP",
    crv: "Ed25519",
    x: "lJZrfAjkBXdfjebMHEUI9usijlNo6rXI7VeM4XItq7E"
  });
  assert.equal(methods[0]?.type, "Multikey");
});

test("publicJwkFromMethod rejects unsupported multicodec keys", () => {
  assert.throws(
    () => publicJwkFromMethod({
      id: "did:webs:issuer#key-2",
      type: "Multikey",
      publicKeyMultibase: "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"
    }),
    (error: unknown) => error instanceof DidWebsResolverError &&
      error.message === "only Ed25519 publicKeyMultibase methods are supported"
  );
});

test("Resolver resolves did:webs documents through getResolver", async () => {
  const seen: string[] = [];
  const resolver = new Resolver(getResolver({
    resolverUrl: "http://resolver.test/1.0/identifiers",
    fetch: async (input) => {
      seen.push(String(input));
      return new Response(JSON.stringify({
        didDocument: {
          id: "did:webs:issuer",
          verificationMethod: [MULTIKEY_METHOD]
        }
      }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
  }));

  const result = await resolver.resolve("did:webs:issuer#key-1");
  assert.equal(result.didDocument?.id, "did:webs:issuer");
  assert.deepEqual(seen, ["http://resolver.test/1.0/identifiers/did:webs:issuer"]);
});

test("Resolver preserves versionId-qualified DID URLs as distinct requests", async () => {
  const seen: string[] = [];
  const resolver = new Resolver(getResolver({
    resolverUrl: "http://resolver.test/1.0/identifiers",
    fetch: async (input) => {
      seen.push(String(input));
      const request = String(input);
      return new Response(JSON.stringify({
        didDocument: {
          id: "did:webs:issuer",
          verificationMethod: [MULTIKEY_METHOD]
        },
        didDocumentMetadata: request.includes("versionId=2") ? { versionId: "2" } : {}
      }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
  }));

  const latest = await resolver.resolve("did:webs:issuer#key-1");
  const versioned = await resolver.resolve("did:webs:issuer?versionId=2#key-1");

  assert.deepEqual(seen, [
    "http://resolver.test/1.0/identifiers/did:webs:issuer",
    "http://resolver.test/1.0/identifiers/did:webs:issuer?versionId=2"
  ]);
  assert.deepEqual(latest.didDocumentMetadata, {});
  assert.deepEqual(versioned.didDocumentMetadata, { versionId: "2" });
});
