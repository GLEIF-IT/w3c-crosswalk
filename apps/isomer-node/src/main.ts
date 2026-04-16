import { cwd } from "node:process";
import { runServer } from "./server.js";
import type { SidecarConfig } from "./types.js";

function parseArgs(argv: string[]): SidecarConfig {
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
    resourceRoot: values.get("resource-root") ?? cwd()
  };
}

await runServer(parseArgs(process.argv.slice(2)));
