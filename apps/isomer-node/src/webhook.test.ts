/**
 * Contract tests for Node sidecar webhook event construction.
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  buildCredentialVerifiedEvent,
  buildPresentationVerifiedEvent,
  createWebhookDispatcher
} from "./webhook.js";
import type { SidecarConfig, VcVerificationResult, VpVerificationResult } from "./types.js";

const CONFIG: SidecarConfig = {
  host: "127.0.0.1",
  port: 8787,
  resolverUrl: "http://resolver.test/1.0/identifiers",
  resourceRoot: "/tmp/resources",
  verifierId: "node-test"
};

test("buildPresentationVerifiedEvent includes verifier metadata and decoded credential payloads", () => {
  const result: VpVerificationResult = {
    ok: true,
    kind: "vp+jwt",
    errors: [],
    warnings: [],
    payload: {
      id: "urn:example:vp",
      holder: "did:webs:holder",
      verifiableCredential: ["raw-vc-jwt"]
    },
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
      payload: {
        id: "urn:example:vc",
        issuer: "did:webs:issuer",
        type: ["VerifiableCredential", "VRDCredential"],
        credentialSubject: { id: "did:webs:holder" }
      },
      checks: {
        jwtEnvelopeValid: true,
        signatureValid: true,
        dataIntegrityProofValid: true,
        statusActive: true
      }
    }]
  };

  const event = buildPresentationVerifiedEvent(CONFIG, result);

  assert.equal(event.type, "isomer.presentation.verified.v1");
  assert.deepEqual((event.verifier as Record<string, unknown>).language, "TypeScript/Node.js");
  const presentation = event.presentation as Record<string, unknown>;
  assert.deepEqual(presentation.credentialTypes, ["VerifiableCredential", "VRDCredential"]);
  assert.equal(JSON.stringify(event).includes("raw-vc-jwt"), false);
});

test("buildCredentialVerifiedEvent includes verifier metadata and decoded credential payload", () => {
  const result: VcVerificationResult = {
    ok: true,
    kind: "vc+jwt",
    errors: [],
    warnings: [],
    payload: {
      id: "urn:example:vc",
      issuer: "did:webs:issuer",
      type: ["VerifiableCredential", "VRDCredential"],
      credentialSubject: { id: "did:webs:holder" }
    },
    checks: {
      jwtEnvelopeValid: true,
      signatureValid: true,
      dataIntegrityProofValid: true,
      statusActive: true
    }
  };

  const event = buildCredentialVerifiedEvent(CONFIG, result);

  assert.equal(event.type, "isomer.presentation.verified.v1");
  assert.deepEqual((event.verifier as Record<string, unknown>).language, "TypeScript/Node.js");
  const presentation = event.presentation as Record<string, unknown>;
  assert.equal(presentation.kind, "vc+jwt");
  assert.equal(presentation.holder, "did:webs:holder");
  assert.deepEqual(presentation.credentialTypes, ["VerifiableCredential", "VRDCredential"]);
  assert.deepEqual(event.verification, {
    ok: true,
    kind: "vc+jwt",
    checks: result.checks,
    warnings: [],
    nested: []
  });
});

test("webhook dispatcher logs full request body and response", async () => {
  const result = credentialResult();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ ok: true }), { status: 202 });
  try {
    const logs = await captureConsoleLogs(async () => {
      const warning = await createWebhookDispatcher({
        ...CONFIG,
        webhookUrl: "http://dashboard.test/webhooks/presentations"
      }).sendCredential(result);
      assert.equal(warning, null);
    });

    const request = findLog(logs, "webhook.request");
    assert.equal(request.webhookUrl, "http://dashboard.test/webhooks/presentations");
    assert.equal(request.artifactKind, "vc+jwt");
    assert.equal(request.body.presentation.credentials[0].id, "urn:example:vc");
    const response = findLog(logs, "webhook.response", { eventId: request.eventId });
    assert.equal(response.httpStatus, 202);
    assert.equal(response.ok, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("webhook dispatcher logs skipped and error outcomes", async () => {
  const result = credentialResult();
  const skippedLogs = await captureConsoleLogs(async () => {
    const warning = await createWebhookDispatcher(CONFIG).sendCredential(result);
    assert.equal(warning, null);
  });
  const skipped = findLog(skippedLogs, "webhook.skipped");
  assert.equal(skipped.reason, "no_webhook_url");
  assert.equal(skipped.artifactKind, "vc+jwt");

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("dashboard offline");
  };
  try {
    const errorLogs = await captureConsoleLogs(async () => {
      const warning = await createWebhookDispatcher({
        ...CONFIG,
        webhookUrl: "http://dashboard.test/webhooks/presentations"
      }).sendCredential(result);
      assert.equal(warning, "dashboard webhook failed: dashboard offline");
    });
    const error = findLog(errorLogs, "webhook.error");
    assert.equal(error.error, "dashboard offline");
    assert.equal(error.artifactKind, "vc+jwt");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

function credentialResult(): VcVerificationResult {
  return {
    ok: true,
    kind: "vc+jwt",
    errors: [],
    warnings: [],
    payload: {
      id: "urn:example:vc",
      issuer: "did:webs:issuer",
      type: ["VerifiableCredential", "VRDCredential"],
      credentialSubject: { id: "did:webs:holder" }
    },
    checks: {
      jwtEnvelopeValid: true,
      signatureValid: true,
      dataIntegrityProofValid: true,
      statusActive: true
    }
  };
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
