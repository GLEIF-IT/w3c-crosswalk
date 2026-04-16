import { base64UrlDecode } from "./base58.js";
import type { JwtParts } from "./types.js";

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

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function asRecord(value: unknown): Record<string, unknown> | undefined {
  return isRecord(value) ? value : undefined;
}

export function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
