import { action, type Operation } from "effection";
import { isRecord } from "./jwt.js";

export function* fetchStatus(url: string | undefined): Operation<Record<string, unknown> | null> {
  if (!url) {
    return null;
  }
  return yield* action<Record<string, unknown>>((resolve, reject) => {
    const controller = new AbortController();
    fetch(url, { headers: { Accept: "application/json" }, signal: controller.signal })
      .then(async (response) => {
        const body = await response.json();
        if (!response.ok) {
          throw new Error(`credential status returned HTTP ${response.status}`);
        }
        if (!isRecord(body)) {
          throw new Error("credential status response was not a JSON object");
        }
        resolve(body);
      })
      .catch(reject);
    return () => controller.abort();
  });
}

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
