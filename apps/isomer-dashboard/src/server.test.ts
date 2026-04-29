/**
 * API contract tests for the Isomer verifier dashboard service.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { createApp } from "./server.js";
import { PresentationStore } from "./store.js";

test("dashboard accepts events and lists presentations newest first", async () => {
  const app = createApp(new PresentationStore());

  const older = sampleEvent("evt-1", "2026-01-01T00:00:00Z", "Python");
  const newer = sampleEvent("evt-2", "2026-01-02T00:00:00Z", "Go");

  assert.equal((await postEvent(app, older)).status, 202);
  assert.equal((await postEvent(app, newer)).status, 202);

  const response = await app.fetch(new Request("http://localhost/api/presentations"));
  assert.equal(response.status, 200);
  const events = await response.json() as Array<Record<string, unknown>>;
  assert.deepEqual(events.map((event) => event.eventId), ["evt-2", "evt-1"]);
});

test("dashboard dedupes events by eventId", async () => {
  const app = createApp(new PresentationStore());
  const event = sampleEvent("evt-1", "2026-01-01T00:00:00Z", "Python");

  assert.equal((await postEvent(app, event)).status, 202);
  const duplicate = await postEvent(app, event);
  assert.equal(duplicate.status, 200);
  assert.equal((await duplicate.json()).duplicate, true);

  const response = await app.fetch(new Request("http://localhost/api/presentations"));
  const events = await response.json() as unknown[];
  assert.equal(events.length, 1);
});

test("dashboard rejects malformed webhook events", async () => {
  const app = createApp(new PresentationStore());

  const response = await app.fetch(new Request("http://localhost/webhooks/presentations", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ type: "wrong" })
  }));

  assert.equal(response.status, 400);
  assert.equal((await response.json()).ok, false);
});

test("dashboard filters by language and credential type", async () => {
  const app = createApp(new PresentationStore());
  await postEvent(app, sampleEvent("evt-1", "2026-01-01T00:00:00Z", "Python", "VRDCredential"));
  await postEvent(app, sampleEvent("evt-2", "2026-01-02T00:00:00Z", "Go", "OtherCredential"));

  const response = await app.fetch(new Request("http://localhost/api/presentations?language=Python&credentialType=VRDCredential"));
  const events = await response.json() as Array<Record<string, unknown>>;

  assert.equal(events.length, 1);
  assert.equal(events[0]?.eventId, "evt-1");
});

async function postEvent(app: ReturnType<typeof createApp>, event: Record<string, unknown>): Promise<Response> {
  return app.fetch(new Request("http://localhost/webhooks/presentations", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(event)
  }));
}

function sampleEvent(
  eventId: string,
  verifiedAt: string,
  language: string,
  credentialType = "VRDCredential"
): Record<string, unknown> {
  return {
    type: "isomer.presentation.verified.v1",
    eventId,
    verifiedAt,
    verifier: {
      id: language.toLowerCase(),
      label: `Isomer ${language}`,
      language,
      libraries: [{ name: "test-lib" }]
    },
    presentation: {
      holder: "did:webs:holder",
      credentialTypes: ["VerifiableCredential", credentialType],
      payload: { holder: "did:webs:holder" },
      credentials: []
    },
    verification: {
      ok: true,
      kind: "vp+jwt",
      checks: { signatureValid: true },
      warnings: [],
      nested: []
    }
  };
}
