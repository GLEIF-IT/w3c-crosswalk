/**
 * CLI ownership for the `isomer-node` sidecar.
 *
 * This module translates a small flag surface into the runtime config consumed
 * by `server.ts`. It intentionally avoids broader command routing so the
 * sidecar stays easy to launch from tests, Make targets, and CI.
 */
import { cwd, env } from "node:process";
import type { Operation } from "effection";
import { serveSidecar } from "../server.js";
import type { SidecarConfig } from "../types.js";

/**
 * Parse the sidecar CLI arguments into the runtime config contract.
 *
 * The parser accepts only `--key value` pairs, ignores unknown flags silently,
 * and applies defaults for host, port, and resource root. `--resolver-url`
 * remains required because the sidecar is not meaningful without the Isomer
 * `did:webs` resolver seam.
 */
export function parseArgs(argv: string[]): SidecarConfig {
  const values = new Map<string, string>();
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) {
      continue;
    }
    const key = item.slice(2);
    const value = argv[index + 1];
    if (value && !value.startsWith("--")) {
      values.set(key, value);
      index += 1;
    }
  }

  const resolverUrl = values.get("resolver-url");
  if (!resolverUrl) {
    throw new Error("--resolver-url is required");
  }

  return {
    host: values.get("host") ?? "127.0.0.1",
    port: Number(values.get("port") ?? "8787"),
    resolverUrl,
    resourceRoot: values.get("resource-root") ?? cwd(),
    webhookUrl: values.get("webhook-url") ?? env.ISOMER_WEBHOOK_URL,
    verifierId: values.get("verifier-id") ?? env.ISOMER_VERIFIER_ID ?? "isomer-node",
    verifierLabel: values.get("verifier-label") ?? env.ISOMER_VERIFIER_LABEL
  };
}

/**
 * Run the sidecar serve command from the parsed CLI argument list.
 *
 * This is the CLI-to-runtime bridge used by the process entrypoint.
 */
export function* serveCommand(argv: string[]): Operation<void> {
  yield* serveSidecar(parseArgs(argv));
}
