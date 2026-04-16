import { serve } from "@hono/node-server";
import { action, main, type Operation, run } from "effection";
import { Hono } from "hono";
import { ExternalVerifier } from "./verifier.js";
import type { SidecarConfig, VerifyRequest } from "./types.js";

export function createApp(config: SidecarConfig): Hono {
  const app = new Hono();
  const verifier = new ExternalVerifier({
    resolverUrl: config.resolverUrl,
    resourceRoot: config.resourceRoot
  });

  app.get("/healthz", (context) => {
    return context.json({ ok: true, service: "isomer-node" });
  });

  app.post("/verify/vc", async (context) => {
    const body = await parseBody(context.req.json<VerifyRequest>());
    if (typeof body.token !== "string" || body.token.length === 0) {
      return context.json({ ok: false, error: "verification request requires token" }, 400);
    }
    return context.json(await run(() => verifier.verifyVc(body.token as string)));
  });

  app.post("/verify/vp", async (context) => {
    const body = await parseBody(context.req.json<VerifyRequest>());
    if (typeof body.token !== "string" || body.token.length === 0) {
      return context.json({ ok: false, error: "verification request requires token" }, 400);
    }
    const audience = typeof body.audience === "string" ? body.audience : undefined;
    const nonce = typeof body.nonce === "string" ? body.nonce : undefined;
    return context.json(await run(() => verifier.verifyVp(body.token as string, { audience, nonce })));
  });

  return app;
}

export function* startServer(config: SidecarConfig): Operation<void> {
  const app = createApp(config);
  const server = serve({
    fetch: app.fetch,
    hostname: config.host,
    port: config.port
  });
  console.log(`isomer-node listening on http://${config.host}:${config.port}`);
  try {
    yield* action<void>((resolve, reject) => {
      server.once("close", () => resolve(undefined));
      server.once("error", reject);
      return () => server.close();
    });
  } finally {
    server.close();
  }
}

export async function runServer(config: SidecarConfig): Promise<void> {
  await main(function*() {
    yield* startServer(config);
  });
}

async function parseBody(promise: Promise<VerifyRequest>): Promise<VerifyRequest> {
  try {
    return await promise;
  } catch {
    return {};
  }
}
