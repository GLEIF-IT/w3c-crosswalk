/**
 * Projected W3C credential status checks for the Node sidecar.
 *
 * Status is a lifecycle decision layered on top of cryptographic verification.
 * This module fetches the projected Isomer status document and applies the
 * narrow revocation rule the sidecar cares about.
 */
import type { Operation } from "effection";
import { promiseToOperation } from "./effection.js";
import { isRecord } from "./jwt.js";

/**
 * Fetch one projected credential status document from the Isomer status URL.
 *
 * Returns `null` when a VC has no `credentialStatus` URL at all.
 */
export function* fetchStatus(url: string | undefined): Operation<Record<string, unknown> | null> {
  if (!url) {
    return null;
  }
  return yield* promiseToOperation(async (signal) => {
    const response = await fetch(url, { headers: { Accept: "application/json" }, signal });
    const body = await response.json();
    if (!response.ok) {
      throw new Error(`credential status returned HTTP ${response.status}`);
    }
    if (!isRecord(body)) {
      throw new Error("credential status response was not a JSON object");
    }
    return body;
  });
}

/**
 * Evaluate one projected status document and append revocation errors when
 * needed.
 */
export function checkStatus(status: Record<string, unknown> | null, errors: string[]): boolean {
  if (status === null) {
    return true;
  }
  if (Boolean(status.revoked)) {
    errors.push(`credential ${String(status.credSaid ?? status.credentialSaid ?? "unknown")} is revoked`);
    return false;
  }
  return true;
}
