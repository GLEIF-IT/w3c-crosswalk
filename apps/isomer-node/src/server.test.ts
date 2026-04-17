/**
 * HTTP contract tests for the isomer-node sidecar routes.
 *
 * These tests intentionally lock the public route behavior: health, bad-body
 * handling, required-token failures, and request forwarding into the verifier
 * seam.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { createApp, type RequestVerifier } from "./server.js";
import type { SidecarConfig, VcVerificationResult, VpVerificationResult } from "./types.js";

// Shared sidecar config used across route contract tests.
const CONFIG: SidecarConfig = {
  host: "127.0.0.1",
  port: 8787,
  resolverUrl: "http://resolver.test/1.0/identifiers",
  resourceRoot: "/tmp/resources"
};

test("health route reports service readiness", async () => {
  const app = createApp(CONFIG, undefined as never, createStubVerifier({}));

  const response = await app.fetch(new Request("http://localhost/healthz"));

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true, service: "isomer-node" });
});

test("vc route rejects requests without token", async () => {
  const app = createApp(CONFIG, undefined as never, createStubVerifier({}));

  const response = await app.fetch(new Request("http://localhost/verify/vc", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({})
  }));

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    ok: false,
    error: "verification request requires token"
  });
});

test("vc route treats malformed json like an empty request", async () => {
  const app = createApp(CONFIG, undefined as never, createStubVerifier({}));

  const response = await app.fetch(new Request("http://localhost/verify/vc", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{not-json"
  }));

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    ok: false,
    error: "verification request requires token"
  });
});

test("vc route returns verifier results", async () => {
  const result: VcVerificationResult = {
    ok: true,
    kind: "vc+jwt",
    errors: [],
    warnings: [],
    payload: { id: "urn:example:vc" },
    checks: {
      jwtEnvelopeValid: true,
      signatureValid: true,
      dataIntegrityProofValid: true,
      statusActive: true
    }
  };
  let receivedToken: string | undefined;

  const app = createApp(CONFIG, undefined as never, createStubVerifier({
    verifyVc: function* (token) {
      receivedToken = token;
      return result;
    }
  }));

  const response = await app.fetch(new Request("http://localhost/verify/vc", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: "vc-token" })
  }));

  assert.equal(receivedToken, "vc-token");
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), result);
});

test("vp route forwards audience and nonce", async () => {
  const result: VpVerificationResult = {
    ok: true,
    kind: "vp+jwt",
    errors: [],
    warnings: [],
    payload: { holder: "did:webs:holder" },
    checks: {
      jwtEnvelopeValid: true,
      signatureValid: true,
      embeddedCredentialsVerified: 1
    },
    nested: [{
      ok: true,
      kind: "vc+jwt",
      errors: [],
      warnings: [],
      payload: { id: "urn:example:vc" },
      checks: {
        jwtEnvelopeValid: true,
        signatureValid: true,
        dataIntegrityProofValid: true,
        statusActive: true
      }
    }]
  };
  let received: { token?: string; audience?: string; nonce?: string } = {};

  const app = createApp(CONFIG, undefined as never, createStubVerifier({
    verifyVp: function* (token, options) {
      received = {
        token,
        audience: options.audience,
        nonce: options.nonce
      };
      return result;
    }
  }));

  const response = await app.fetch(new Request("http://localhost/verify/vp", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      token: "vp-token",
      audience: "https://verifier.example",
      nonce: "expected-nonce"
    })
  }));

  assert.deepEqual(received, {
    token: "vp-token",
    audience: "https://verifier.example",
    nonce: "expected-nonce"
  });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), result);
});

/**
 * Create a stub request verifier for route tests.
 *
 * The helper defaults to successful no-op results so each test overrides only
 * the branch it cares about.
 */
function createStubVerifier(overrides: {
  verifyVc?: RequestVerifier["verifyVc"];
  verifyVp?: RequestVerifier["verifyVp"];
}): RequestVerifier {
  return {
    verifyVc: overrides.verifyVc ?? (function* () {
        return {
          ok: true,
          kind: "vc+jwt" as const,
          errors: [],
          warnings: [],
          payload: null,
          checks: {
            jwtEnvelopeValid: true,
            signatureValid: true,
            dataIntegrityProofValid: true,
            statusActive: true
          }
        };
      }),
    verifyVp: overrides.verifyVp ?? (
      function* () {
        return {
          ok: true,
          kind: "vp+jwt" as const,
          errors: [],
          warnings: [],
          payload: null,
          checks: {
            jwtEnvelopeValid: true,
            signatureValid: true,
            embeddedCredentialsVerified: 0
          },
          nested: []
        };
      })
  };
}
