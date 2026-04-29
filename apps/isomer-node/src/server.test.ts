/**
 * HTTP contract tests for the isomer-node sidecar routes.
 *
 * These tests intentionally lock the public route behavior: health, bad-body
 * handling, required-token failures, and request forwarding into the verifier
 * seam.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { createApp, type RequestVerifier } from "./server.js";
import type { SidecarConfig, VcVerificationResult, VpVerificationResult } from "./types.js";

// Shared sidecar config used across route contract tests.
const CONFIG: SidecarConfig = {
  host: "127.0.0.1",
  port: 8787,
  resolverUrl: "http://resolver.test/1.0/identifiers",
  resourceRoot: "/tmp/resources",
  verifierId: "isomer-node-test"
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

test("vc route returns 202 and stores a pending operation", async () => {
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

  let operationName = "";
  const logs = await captureConsoleLogs(async () => {
    const response = await app.fetch(new Request("http://localhost/verify/vc", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: "vc-token" })
    }));

    assert.equal(response.status, 202);
    const operation = await response.json();
    operationName = operation.name;
    assert.match(operation.name, /^verify-vc\./);
    assert.equal(operation.done, false);
    assert.equal(operation.metadata.state, "pending");

    const listResponse = await app.fetch(new Request("http://localhost/operations"));
    assert.equal(listResponse.status, 200);
    const listBody = await listResponse.json() as Array<{ name: string }>;
    assert.deepEqual(listBody.map((item) => item.name), [operation.name]);

    const filteredResponse = await app.fetch(new Request("http://localhost/operations?type=verify-vc"));
    assert.equal(filteredResponse.status, 200);
    const filteredBody = await filteredResponse.json() as Array<{ name: string }>;
    assert.deepEqual(filteredBody.map((item) => item.name), [operation.name]);

    const completed = await waitForOperation(app, operation.name);
    assert.equal(receivedToken, "vc-token");
    assert.equal(completed.done, true);
    assert.equal(completed.metadata.state, "completed");
    assert.deepEqual(completed.response, result);
  });

  const received = findLog(logs, "verification.received", { operationName });
  assert.equal(received.verifier, "isomer-node-test");
  assert.equal(received.route, "/verify/vc");
  assert.equal(received.artifactKind, "vc+jwt");
  assert.equal(received.token, "vc-token");
  assert.equal(received.tokenLength, "vc-token".length);
  assert.equal(received.tokenSha256, tokenHash("vc-token"));
  const resultLog = findLog(logs, "verification.result", { operationName });
  assert.equal(resultLog.ok, true);
  assert.equal(resultLog.kind, "vc+jwt");
  const skipped = findLog(logs, "webhook.skipped", { artifactKind: "vc+jwt" });
  assert.equal(skipped.reason, "no_webhook_url");
});

test("vc route records failed background verification operations", async () => {
  const app = createApp(CONFIG, undefined as never, createStubVerifier({
    verifyVc: function* () {
      throw new Error("verification crashed");
    }
  }));

  let operationName = "";
  const logs = await captureConsoleLogs(async () => {
    const response = await app.fetch(new Request("http://localhost/verify/vc", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: "vc-token" })
    }));

    assert.equal(response.status, 202);
    const operation = await response.json();
    operationName = operation.name;
    const failed = await waitForOperation(app, operation.name);
    assert.equal(failed.done, true);
    assert.equal(failed.metadata.state, "failed");
    assert.equal(failed.error.code, 500);
    assert.equal(failed.error.message, "verification crashed");
  });

  const resultLog = findLog(logs, "verification.result", { operationName });
  assert.equal(resultLog.ok, false);
  assert.deepEqual(resultLog.errors, ["verification crashed"]);
  assert.deepEqual(resultLog.error, { code: 500, message: "verification crashed" });
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

  const logs = await captureConsoleLogs(async () => {
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

  const receivedLog = findLog(logs, "verification.received", { artifactKind: "vp+jwt" });
  assert.equal(receivedLog.route, "/verify/vp");
  assert.equal(receivedLog.token, "vp-token");
  const resultLog = findLog(logs, "verification.result", { artifactKind: "vp+jwt" });
  assert.equal(resultLog.ok, true);
  assert.equal(resultLog.kind, "vp+jwt");
});

test("vp route sends webhook only after successful presentation verification", async () => {
  const result: VpVerificationResult = {
    ok: true,
    kind: "vp+jwt",
    errors: [],
    warnings: [],
    payload: { holder: "did:webs:holder" },
    checks: {
      jwtEnvelopeValid: true,
      signatureValid: true,
      embeddedCredentialsVerified: 0
    },
    nested: []
  };
  let webhookCalls = 0;

  const app = createApp(
    { ...CONFIG, webhookUrl: "http://dashboard.test/webhooks/presentations" },
    undefined as never,
    createStubVerifier({ verifyVp: function* () { return result; } }),
    {
      sendPresentation: async () => { webhookCalls += 1; return null; },
      sendCredential: async () => null
    }
  );

  const logs = await captureConsoleLogs(async () => {
    const response = await app.fetch(new Request("http://localhost/verify/vp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: "vp-token" })
    }));

    assert.equal(response.status, 200);
    assert.equal(webhookCalls, 1);
    assert.deepEqual(await response.json(), result);
  });
  assert.equal(findLog(logs, "verification.received", { artifactKind: "vp+jwt" }).token, "vp-token");
  assert.equal(findLog(logs, "verification.result", { artifactKind: "vp+jwt" }).ok, true);
});

test("vc route sends webhook after successful credential verification", async () => {
  let webhookCalls = 0;
  const app = createApp(
    { ...CONFIG, webhookUrl: "http://dashboard.test/webhooks/presentations" },
    undefined as never,
    createStubVerifier({}),
    {
      sendPresentation: async () => null,
      sendCredential: async () => { webhookCalls += 1; return null; }
    }
  );

  let operationName = "";
  const logs = await captureConsoleLogs(async () => {
    const response = await app.fetch(new Request("http://localhost/verify/vc", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: "vc-token" })
    }));

    assert.equal(response.status, 202);
    const operation = await response.json();
    operationName = operation.name;
    const completed = await waitForOperation(app, operation.name);
    assert.equal(completed.metadata.state, "completed");
    assert.equal(webhookCalls, 1);
  });
  assert.equal(findLog(logs, "verification.received", { operationName }).token, "vc-token");
  assert.equal(findLog(logs, "verification.result", { operationName }).ok, true);
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

async function waitForOperation(
  app: ReturnType<typeof createApp>,
  name: string
): Promise<any> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const response = await app.fetch(new Request(`http://localhost/operations/${name}`));
    assert.equal(response.status, 200);
    const operation = await response.json();
    if (operation.done === true) {
      return operation;
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`operation ${name} did not complete`);
}

async function captureConsoleLogs(callback: () => Promise<void>): Promise<Array<Record<string, any>>> {
  const original = console.log;
  const lines: string[] = [];
  console.log = (message?: unknown) => {
    lines.push(String(message));
  };
  try {
    await callback();
  } finally {
    console.log = original;
  }
  return lines.map((line) => JSON.parse(line) as Record<string, any>);
}

function findLog(
  logs: Array<Record<string, any>>,
  event: string,
  fields: Record<string, unknown> = {}
): Record<string, any> {
  const match = logs.find((item) => (
    item.event === event &&
    Object.entries(fields).every(([key, value]) => item[key] === value)
  ));
  if (match === undefined) {
    throw new Error(`missing log ${event} with ${JSON.stringify(fields)} in ${JSON.stringify(logs)}`);
  }
  return match;
}

function tokenHash(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex").slice(0, 16);
}
