/**
 * HTTP surface for the isomer-node verifier sidecar.
 *
 * This module owns the small external API used by integration tests and manual
 * verifier-side acceptance checks. It wraps verifier operations behind a Hono
 * app and keeps request validation deliberately narrow: health, VC verify, and
 * VP verify only.
 */
import { serve } from "@hono/node-server";
import { action, type Operation, run } from "effection";
import { Hono } from "hono";
import { createVerifierContext, type VerifierContext, verifyVcOp, verifyVpOp } from "./verifier.js";
import type {
  SidecarConfig,
  VcVerificationResult,
  VerifyRequest,
  VpVerificationResult
} from "./types.js";

/**
 * Verification hooks bound to the HTTP request layer.
 *
 * The interface exists mostly as a test seam so server tests can exercise the
 * route contract without constructing the full verifier pipeline.
 */
export interface RequestVerifier {
  verifyVc: (token: string) => Operation<VcVerificationResult>;
  verifyVp: (
    token: string,
    options: { audience?: string; nonce?: string }
  ) => Operation<VpVerificationResult>;
}

/**
 * Create the Hono app that exposes the sidecar HTTP contract.
 *
 * The default verifier context and request verifier are injected here so tests
 * can replace them with stubs while production callers keep the one-line setup.
 */
export function createApp(
  config: SidecarConfig,
  verifier = createVerifierContext(config),
  requestVerifier = createRequestVerifier(verifier)
): Hono {
  const app = new Hono();

  app.get("/healthz", (context) => {
    return context.json({ ok: true, service: "isomer-node" });
  });

  app.post("/verify/vc", async (context) => {
    const body = await parseBody(context.req.json<VerifyRequest>());
    if (!hasToken(body)) {
      return context.json({ ok: false, error: "verification request requires token" }, 400);
    }
    return context.json(await run(() => requestVerifier.verifyVc(body.token)));
  });

  app.post("/verify/vp", async (context) => {
    const body = await parseBody(context.req.json<VerifyRequest>());
    if (!hasToken(body)) {
      return context.json({ ok: false, error: "verification request requires token" }, 400);
    }
    const audience = typeof body.audience === "string" ? body.audience : undefined;
    const nonce = typeof body.nonce === "string" ? body.nonce : undefined;
    return context.json(await run(() => requestVerifier.verifyVp(body.token, { audience, nonce })));
  });

  return app;
}

/**
 * Start the HTTP sidecar and keep it alive until the server closes or errors.
 *
 * The returned Effection operation owns the server lifecycle so tests and CLI
 * callers can use the same runtime boundary.
 */
export function* serveSidecar(
  config: SidecarConfig,
  verifier?: VerifierContext
): Operation<void> {
  const app = createApp(config, verifier);
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

/**
 * Parse one request body and degrade malformed JSON to an empty request object.
 *
 * This keeps the route-level error contract simple: malformed bodies behave the
 * same as missing-token bodies and receive the same 400 response.
 */
async function parseBody(promise: Promise<VerifyRequest>): Promise<VerifyRequest> {
  try {
    return await promise;
  } catch {
    return {};
  }
}

/**
 * Determine whether the request carries a non-empty token string.
 */
function hasToken(request: VerifyRequest): request is VerifyRequest & { token: string } {
  return typeof request.token === "string" && request.token.length > 0;
}

/**
 * Adapt a verifier context into the narrower HTTP-layer verification hooks.
 */
function createRequestVerifier(verifier: VerifierContext): RequestVerifier {
  return {
    verifyVc: (token) => verifyVcOp(verifier, token),
    verifyVp: (token, options) => verifyVpOp(verifier, token, options)
  };
}
