/**
 * Entrypoint for the isomer-node sidecar process.
 *
 * This module stays intentionally small. The real CLI contract lives in
 * `commands/serve.ts`; this file only bridges the Node process into Effection's
 * root operation runner.
 */
import { main } from "effection";
import { serveCommand } from "./commands/serve.js";

await main(function*() {
  yield* serveCommand(process.argv.slice(2));
});
