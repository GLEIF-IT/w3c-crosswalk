/**
 * Structured JSON logging helpers for local verifier diagnostics.
 */
import { createHash } from "node:crypto";
import type { SidecarConfig, VerificationResult } from "./types.js";

const TOKEN_HASH_HEX_LENGTH = 16;

export function tokenObservability(token: string): Record<string, unknown> {
  return {
    token,
    tokenLength: token.length,
    tokenSha256: createHash("sha256").update(token, "utf8").digest("hex").slice(0, TOKEN_HASH_HEX_LENGTH)
  };
}

export function logVerifierEvent(
  event: string,
  fields: Record<string, unknown>
): void {
  console.log(JSON.stringify({ event, ...fields }));
}

export function logVerificationResult(
  config: SidecarConfig,
  artifactKind: "vc+jwt" | "vp+jwt",
  result: VerificationResult,
  operationName?: string
): void {
  logVerifierEvent("verification.result", {
    verifier: config.verifierId,
    artifactKind,
    ...(operationName ? { operationName } : {}),
    ok: result.ok,
    kind: result.kind,
    checks: result.checks,
    warnings: result.warnings,
    errors: result.errors
  });
}

export function logVerificationError(
  config: SidecarConfig,
  artifactKind: "vc+jwt" | "vp+jwt",
  error: unknown,
  operationName?: string
): void {
  const message = error instanceof Error ? error.message : String(error);
  logVerifierEvent("verification.result", {
    verifier: config.verifierId,
    artifactKind,
    ...(operationName ? { operationName } : {}),
    ok: false,
    kind: artifactKind,
    checks: {},
    warnings: [],
    errors: [message],
    error: {
      code: 500,
      message
    }
  });
}
