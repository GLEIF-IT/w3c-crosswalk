/**
 * Small Effection helpers for the Node sidecar.
 *
 * The sidecar mostly relies on promise-based libraries, so this file provides
 * the narrow bridge needed to run them inside Effection operations with abort
 * semantics.
 */
import { action, type Operation } from "effection";

/**
 * Wrap one abort-aware promise loader as an Effection operation.
 *
 * The returned operation aborts the underlying loader when the Effection scope
 * closes before the promise resolves.
 */
export function promiseToOperation<T>(
  load: (signal: AbortSignal) => Promise<T>
): Operation<T> {
  return action<T>((resolve, reject) => {
    const controller = new AbortController();
    load(controller.signal).then(resolve).catch(reject);
    return () => controller.abort();
  });
}
