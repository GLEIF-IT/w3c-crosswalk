/**
 * Webhook event construction for successful verification events.
 *
 * The dashboard is an observer, so webhook delivery is best-effort and never
 * changes verification truth. Events deliberately omit raw JWT tokens.
 */
import { randomUUID } from "node:crypto";
import { cloneJson, isRecord } from "./jwt.js";
import { logVerifierEvent } from "./observability.js";
import type { SidecarConfig, VcVerificationResult, VpVerificationResult } from "./types.js";

const PRESENTATION_VERIFIED_EVENT = "isomer.presentation.verified.v1";

export interface WebhookDispatcher {
  sendPresentation: (result: VpVerificationResult) => Promise<string | null>;
  sendCredential: (result: VcVerificationResult) => Promise<string | null>;
}

export function createWebhookDispatcher(config: SidecarConfig): WebhookDispatcher {
  return {
    sendPresentation: (result) => sendWebhook(config, buildPresentationVerifiedEvent(config, result)),
    sendCredential: (result) => sendWebhook(config, buildCredentialVerifiedEvent(config, result))
  };
}

export function buildPresentationVerifiedEvent(
  config: SidecarConfig,
  result: VpVerificationResult
): Record<string, unknown> {
  const credentials = result.nested.map(credentialEntry);
  return {
    type: PRESENTATION_VERIFIED_EVENT,
    eventId: randomUUID(),
    verifiedAt: new Date().toISOString(),
    verifier: nodeVerifierMetadata(config),
    presentation: {
      kind: result.kind,
      id: stringField(result.payload, "id"),
      holder: stringField(result.payload, "holder"),
      credentialTypes: credentialTypes(credentials),
      payload: presentationPayload(result.payload, credentials),
      credentials
    },
    verification: {
      ok: result.ok,
      kind: result.kind,
      checks: cloneJson(result.checks),
      warnings: [...result.warnings],
      nested: result.nested.map(nestedVerificationSummary)
    }
  };
}

export function buildCredentialVerifiedEvent(
  config: SidecarConfig,
  result: VcVerificationResult
): Record<string, unknown> {
  const credential = credentialEntry(result);
  const credentials = [credential];
  return {
    type: PRESENTATION_VERIFIED_EVENT,
    eventId: randomUUID(),
    verifiedAt: new Date().toISOString(),
    verifier: nodeVerifierMetadata(config),
    presentation: {
      kind: result.kind,
      id: credential.id,
      holder: credential.subject,
      credentialTypes: credentialTypes(credentials),
      payload: isRecord(result.payload) ? cloneJson(result.payload) : null,
      credentials
    },
    verification: {
      ok: result.ok,
      kind: result.kind,
      checks: cloneJson(result.checks),
      warnings: [...result.warnings],
      nested: []
    }
  };
}

async function sendWebhook(
  config: SidecarConfig,
  event: Record<string, unknown>
): Promise<string | null> {
  const eventId = typeof event.eventId === "string" ? event.eventId : null;
  const artifactKind = artifactKindFromEvent(event);
  if (!config.webhookUrl) {
    logVerifierEvent("webhook.skipped", {
      verifier: config.verifierId,
      eventId,
      artifactKind,
      reason: "no_webhook_url"
    });
    return null;
  }

  logVerifierEvent("webhook.request", {
    verifier: config.verifierId,
    webhookUrl: config.webhookUrl,
    eventId,
    artifactKind,
    body: event
  });
  try {
    const response = await fetch(config.webhookUrl, {
      method: "POST",
      headers: {
        "accept": "application/json",
        "content-type": "application/json"
      },
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(3000)
    });
    logVerifierEvent("webhook.response", {
      verifier: config.verifierId,
      webhookUrl: config.webhookUrl,
      eventId,
      artifactKind,
      httpStatus: response.status,
      ok: response.ok
    });
    if (!response.ok) {
      return `dashboard webhook returned HTTP ${response.status}`;
    }
    return null;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logVerifierEvent("webhook.error", {
      verifier: config.verifierId,
      webhookUrl: config.webhookUrl,
      eventId,
      artifactKind,
      error: message
    });
    return `dashboard webhook failed: ${message}`;
  }
}

function nodeVerifierMetadata(config: SidecarConfig): Record<string, unknown> {
  return {
    id: config.verifierId,
    label: config.verifierLabel ?? "Isomer Node",
    type: "isomer-node",
    language: "TypeScript/Node.js",
    libraries: [
      { name: "did-jwt-vc", role: "VC-JWT and VP-JWT envelope verification" },
      { name: "did-resolver", role: "DID resolver interface" },
      { name: "webs-did-resolver", role: "did:webs resolution" },
      { name: "jsonld", role: "JSON-LD canonicalization" }
    ]
  };
}

function credentialEntry(nested: VcVerificationResult): Record<string, unknown> {
  const payload = isRecord(nested.payload) ? nested.payload : {};
  const subject = isRecord(payload.credentialSubject) ? payload.credentialSubject : {};
  return {
    kind: nested.kind,
    id: stringField(payload, "id"),
    issuer: stringField(payload, "issuer"),
    subject: stringField(subject, "id"),
    types: stringList(payload.type),
    payload: cloneJson(payload)
  };
}

function presentationPayload(
  payload: Record<string, unknown> | null,
  credentials: Record<string, unknown>[]
): Record<string, unknown> | null {
  if (!isRecord(payload)) {
    return null;
  }
  const cleaned = cloneJson(payload);
  cleaned.verifiableCredential = credentials.map((credential) => ({
    kind: credential.kind,
    id: credential.id,
    issuer: credential.issuer,
    types: credential.types
  }));
  return cleaned;
}

function nestedVerificationSummary(nested: VcVerificationResult): Record<string, unknown> {
  return {
    ok: nested.ok,
    kind: nested.kind,
    checks: cloneJson(nested.checks),
    warnings: [...nested.warnings],
    errors: [...nested.errors]
  };
}

function credentialTypes(credentials: Record<string, unknown>[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const credential of credentials) {
    for (const item of stringList(credential.types)) {
      if (!seen.has(item)) {
        seen.add(item);
        result.push(item);
      }
    }
  }
  return result;
}

function stringField(value: Record<string, unknown> | null, key: string): string | null {
  if (!isRecord(value)) {
    return null;
  }
  const field = value[key];
  return typeof field === "string" ? field : null;
}

function stringList(value: unknown): string[] {
  if (typeof value === "string") {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === "string");
  }
  return [];
}

function artifactKindFromEvent(event: Record<string, unknown>): string | null {
  const presentation = event.presentation;
  if (isRecord(presentation) && typeof presentation.kind === "string") {
    return presentation.kind;
  }
  const verification = event.verification;
  if (isRecord(verification) && typeof verification.kind === "string") {
    return verification.kind;
  }
  return null;
}
