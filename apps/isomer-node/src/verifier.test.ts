/**
 * Semantic contract tests for VC-JWT and VP-JWT verification behavior.
 *
 * These tests lock the Node sidecar's W3C-facing meaning: claim validation,
 * proof verification orchestration, status handling, and recursive VP handling.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { createVerifierContext, type VerifierDependencies, verifyVcOp, verifyVpOp } from "./verifier.js";
import type { SidecarConfig } from "./types.js";
import { run } from "effection";

// Sample resolved verification method returned by the did:webs seam.
const RESOLVED_METHOD = {
  id: "did:webs:issuer#key-1",
  type: "JsonWebKey2020",
  publicKeyJwk: {
    kty: "OKP",
    crv: "Ed25519",
    x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  }
};

// Minimal DID document shape used by the verifier tests when proof resolution
// reaches into a resolved did:webs document.
const DID_DOCUMENT = {
  verificationMethod: [RESOLVED_METHOD]
};

// Representative projected VC payload used across the VC verification tests.
const VC_PAYLOAD = {
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/data-integrity/v2",
    "https://www.gleif.org/contexts/isomer-v1.jsonld"
  ],
  id: "urn:example:vc",
  type: ["VerifiableCredential", "VleiCredential"],
  issuer: "did:webs:issuer",
  issuanceDate: "2026-01-01T00:00:00Z",
  credentialSubject: {
    id: "did:webs:holder"
  },
  credentialStatus: {
    id: "https://status.example/credentials/test-vc"
  },
  proof: {
    type: "DataIntegrityProof",
    cryptosuite: "eddsa-rdfc-2022",
    verificationMethod: "did:webs:issuer#key-1",
    proofValue: "z2VfUX"
  }
};

// Representative VP payload used for recursive embedded-credential checks.
const VP_PAYLOAD = {
  holder: "did:webs:holder"
};

test("verifyVcOp returns a fully successful result when all checks pass", async () => {
  const context = createTestVerifierContext();

  const result = await run(() => verifyVcOp(context, encodeJwt({
    iss: "did:webs:issuer",
    sub: "did:webs:holder",
    jti: "urn:example:vc",
    iat: 1704067200,
    nbf: 1704067200,
    vc: cloneValue(VC_PAYLOAD)
  }, { kid: "did:webs:issuer#key-1" })));

  assert.equal(result.ok, true);
  assert.equal(result.kind, "vc+jwt");
  assert.deepEqual(result.errors, []);
  assert.equal(result.checks.jwtEnvelopeValid, true);
  assert.equal(result.checks.signatureValid, true);
  assert.equal(result.checks.dataIntegrityProofValid, true);
  assert.equal(result.checks.statusActive, true);
});

test("verifyVcOp fails when JWT iss does not match vc.issuer", async () => {
  const context = createTestVerifierContext();

  const result = await run(() => verifyVcOp(context, encodeJwt({
    iss: "did:webs:other",
    sub: "did:webs:holder",
    jti: "urn:example:vc",
    iat: 1704067200,
    nbf: 1704067200,
    vc: cloneValue(VC_PAYLOAD)
  }, { kid: "did:webs:issuer#key-1" })));

  assert.equal(result.ok, false);
  assert.deepEqual(result.errors, ["JWT iss does not match vc.issuer"]);
  assert.equal(result.checks.jwtEnvelopeValid, false);
});

test("verifyVcOp fails when JWT jti does not match vc.id", async () => {
  const context = createTestVerifierContext();

  const result = await run(() => verifyVcOp(context, encodeJwt({
    iss: "did:webs:issuer",
    sub: "did:webs:holder",
    jti: "urn:example:other",
    iat: 1704067200,
    nbf: 1704067200,
    vc: cloneValue(VC_PAYLOAD)
  }, { kid: "did:webs:issuer#key-1" })));

  assert.equal(result.ok, false);
  assert.deepEqual(result.errors, ["JWT jti does not match vc.id"]);
});

test("verifyVcOp fails when JWT sub does not match credentialSubject.id", async () => {
  const context = createTestVerifierContext();

  const result = await run(() => verifyVcOp(context, encodeJwt({
    iss: "did:webs:issuer",
    sub: "did:webs:other",
    jti: "urn:example:vc",
    iat: 1704067200,
    nbf: 1704067200,
    vc: cloneValue(VC_PAYLOAD)
  }, { kid: "did:webs:issuer#key-1" })));

  assert.equal(result.ok, false);
  assert.deepEqual(result.errors, ["JWT sub does not match credentialSubject.id"]);
});

test("verifyVcOp fails when status marks the credential revoked", async () => {
  const context = createTestVerifierContext({
    fetchStatus: function* (url) {
      assert.equal(url, "https://status.example/credentials/test-vc");
      return { revoked: true, credSaid: "test-vc" };
    },
    checkStatus: (status, errors) => {
      if (status?.revoked) {
        errors.push(`credential ${String(status.credSaid ?? "unknown")} is revoked`);
        return false;
      }
      return true;
    }
  });

  const result = await run(() => verifyVcOp(context, encodeJwt({
    iss: "did:webs:issuer",
    sub: "did:webs:holder",
    jti: "urn:example:vc",
    iat: 1704067200,
    nbf: 1704067200,
    vc: cloneValue(VC_PAYLOAD)
  }, { kid: "did:webs:issuer#key-1" })));

  assert.equal(result.ok, false);
  assert.deepEqual(result.errors, ["credential test-vc is revoked"]);
  assert.equal(result.checks.statusActive, false);
});

test("verifyVpOp succeeds for a valid VP with one valid nested VC", async () => {
  const context = createTestVerifierContext();
  const embedded = encodeJwt({
    iss: "did:webs:issuer",
    sub: "did:webs:holder",
    jti: "urn:example:vc",
    iat: 1704067200,
    nbf: 1704067200,
    vc: cloneValue(VC_PAYLOAD)
  }, { kid: "did:webs:issuer#key-1" });

  const result = await run(() => verifyVpOp(context, encodeJwt({
    iss: "did:webs:holder",
    aud: "https://verifier.example",
    nonce: "expected-nonce",
    iat: 1704067200,
    vp: {
      ...cloneValue(VP_PAYLOAD),
      verifiableCredential: [embedded]
    }
  }), { audience: "https://verifier.example", nonce: "expected-nonce" }));

  assert.equal(result.ok, true);
  assert.equal(result.kind, "vp+jwt");
  assert.equal(result.checks.embeddedCredentialsVerified, 1);
  assert.equal(result.nested.length, 1);
  assert.equal(result.nested[0]?.ok, true);
});

test("verifyVpOp fails when audience does not match expected value", async () => {
  const context = createTestVerifierContext();

  const result = await run(() => verifyVpOp(context, encodeJwt({
    iss: "did:webs:holder",
    aud: "https://verifier.example",
    nonce: "expected-nonce",
    iat: 1704067200,
    vp: {
      ...cloneValue(VP_PAYLOAD),
      verifiableCredential: []
    }
  }), { audience: "https://other.example", nonce: "expected-nonce" }));

  assert.equal(result.ok, false);
  assert.deepEqual(result.errors, ["JWT aud does not match expected audience"]);
});

test("verifyVpOp fails when nonce does not match expected value", async () => {
  const context = createTestVerifierContext();

  const result = await run(() => verifyVpOp(context, encodeJwt({
    iss: "did:webs:holder",
    aud: "https://verifier.example",
    nonce: "expected-nonce",
    iat: 1704067200,
    vp: {
      ...cloneValue(VP_PAYLOAD),
      verifiableCredential: []
    }
  }), { audience: "https://verifier.example", nonce: "wrong-nonce" }));

  assert.equal(result.ok, false);
  assert.deepEqual(result.errors, ["JWT nonce does not match expected nonce"]);
});

test("verifyVpOp rejects non-string embedded credentials", async () => {
  const context = createTestVerifierContext();

  const result = await run(() => verifyVpOp(context, encodeJwt({
    iss: "did:webs:holder",
    aud: "https://verifier.example",
    nonce: "expected-nonce",
    iat: 1704067200,
    vp: {
      ...cloneValue(VP_PAYLOAD),
      verifiableCredential: [{}]
    }
  }), { audience: "https://verifier.example", nonce: "expected-nonce" }));

  assert.equal(result.ok, false);
  assert.deepEqual(result.errors, ["only nested VC-JWT strings are supported"]);
});

test("verifyVpOp surfaces nested VC verification errors", async () => {
  const context = createTestVerifierContext();
  const embedded = encodeJwt({
    iss: "did:webs:issuer",
    sub: "did:webs:wrong",
    jti: "urn:example:vc",
    iat: 1704067200,
    nbf: 1704067200,
    vc: cloneValue(VC_PAYLOAD)
  }, { kid: "did:webs:issuer#key-1" });

  const result = await run(() => verifyVpOp(context, encodeJwt({
    iss: "did:webs:holder",
    aud: "https://verifier.example",
    nonce: "expected-nonce",
    iat: 1704067200,
    vp: {
      ...cloneValue(VP_PAYLOAD),
      verifiableCredential: [embedded]
    }
  }), { audience: "https://verifier.example", nonce: "expected-nonce" }));

  assert.equal(result.ok, false);
  assert.deepEqual(result.errors, ["nested credential: JWT sub does not match credentialSubject.id"]);
});

/**
 * Build one verifier context with defaults that make semantic tests easy to
 * override one seam at a time.
 */
function createTestVerifierContext(
  overrides: Partial<VerifierDependencies> = {}
) {
  return createVerifierContext(
    {
      resolverUrl: "http://resolver.test/1.0/identifiers",
      resourceRoot: "/tmp/resources"
    } satisfies Pick<SidecarConfig, "resolverUrl" | "resourceRoot">,
    {
      resolver: {
        resolve: async () => ({
          didDocument: cloneValue(DID_DOCUMENT),
          didDocumentMetadata: {},
          didResolutionMetadata: {}
        }),
        resolveOp: function* () {
          return {
            didDocument: cloneValue(DID_DOCUMENT),
            didDocumentMetadata: {},
            didResolutionMetadata: {}
          };
        }
      } as never,
      contexts: {} as never,
      dependencies: {
        ...defaultDependencies(),
        ...overrides
      }
    }
  );
}

/**
 * Return the default seam implementations used across verifier tests.
 */
function defaultDependencies(): VerifierDependencies {
  return {
    verifyCredentialJwtOp: function* () {},
    verifyPresentationJwtOp: function* () {},
    verifyDataIntegrityProof: async () => true,
    fetchStatus: function* () {
      return { revoked: false };
    },
    checkStatus: (status, errors) => {
      if (status?.revoked) {
        errors.push("revoked");
        return false;
      }
      return true;
    }
  };
}

/**
 * Encode one JWT-like payload for structural verifier tests.
 *
 * The tests here intentionally lock local validation semantics, not real
 * signing, so the signature part is a fixed dummy value.
 */
function encodeJwt(payload: Record<string, unknown>, header: Record<string, unknown> = {}): string {
  return [
    Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT", ...header })).toString("base64url"),
    Buffer.from(JSON.stringify(payload)).toString("base64url"),
    "signature"
  ].join(".");
}

/**
 * Deep-clone one JSON fixture so each test can mutate safely.
 */
function cloneValue<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
