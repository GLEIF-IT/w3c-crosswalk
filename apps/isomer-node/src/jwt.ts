/**
 * Local JWT parsing and JSON narrowing helpers.
 *
 * These helpers stop at structural decoding. They do not perform cryptographic
 * verification; that work stays in the JWT VC and verifier layers.
 */
import { base64UrlDecode } from "./base58.js";
import type { JwtParts } from "./types.js";

/**
 * Decode one compact JWT into its parsed header, parsed payload, signing input,
 * and detached signature bytes.
 */
export function decodeJwt(token: string): JwtParts {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("expected compact JWT with three parts");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const header = JSON.parse(Buffer.from(encodedHeader, "base64url").toString("utf8"));
  const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));

  if (!isRecord(header) || !isRecord(payload)) {
    throw new Error("JWT header and payload must be JSON objects");
  }

  return {
    header,
    payload,
    signingInput: new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`),
    signature: base64UrlDecode(encodedSignature),
  };
}

/**
 * Narrow a value to a plain JSON object.
 */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Return a non-empty string view when the value is string-like enough for the
 * verifier contract.
 */
export function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/**
 * Return a plain-object view when the value is a JSON object.
 */
export function asRecord(value: unknown): Record<string, unknown> | undefined {
  return isRecord(value) ? value : undefined;
}

/**
 * Deep-clone one JSON-compatible value.
 *
 * The verifier uses this before canonicalization so proof verification can
 * remove or rewrite fields without mutating the original payload.
 */
export function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
