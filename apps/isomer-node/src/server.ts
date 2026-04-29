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
import { createVerifierRuntime, type VerifierRuntime, verifyVcOp, verifyVpOp } from "./verifier.js";
import type {
  SidecarConfig,
  VcVerificationResult,
  VerifyRequest,
  VpVerificationResult
} from "./types.js";
import { InMemoryOperationMonitor } from "./operations.js";
import {
  logVerificationError,
  logVerificationResult,
  logVerifierEvent,
  tokenObservability
} from "./observability.js";
import { createWebhookDispatcher, type WebhookDispatcher } from "./webhook.js";

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
 * The default verifier runtime and request verifier are injected here so tests
 * can replace them with stubs while production callers keep the one-line setup.
 */
export function createApp(
  config: SidecarConfig,
  runtime = createVerifierRuntime(config),
  requestVerifier = createRequestVerifier(runtime),
  webhook = createWebhookDispatcher(config),
  operations = new InMemoryOperationMonitor()
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
    const operation = operations.submit("verify-vc", async (operationName) => {
      try {
        const result = await run(() => requestVerifier.verifyVc(body.token));
        if (result.ok) {
          const warning = await webhook.sendCredential(result);
          if (warning) {
            result.warnings.push(warning);
          }
        }
        logVerificationResult(config, "vc+jwt", result, operationName);
        return result;
      } catch (error) {
        logVerificationError(config, "vc+jwt", error, operationName);
        throw error;
      }
    });
    logVerifierEvent("verification.received", {
      verifier: config.verifierId,
      route: "/verify/vc",
      artifactKind: "vc+jwt",
      operationName: operation.name,
      ...tokenObservability(body.token)
    });
    return context.json(operation, 202);
  });

  app.get("/operations", (context) => {
    const type = context.req.query("type");
    return context.json(operations.list(type));
  });

  app.get("/operations/:name", (context) => {
    const operation = operations.get(context.req.param("name"));
    if (operation === undefined) {
      return context.json({ ok: false, error: "operation not found" }, 404);
    }
    return context.json(operation);
  });

  app.post("/verify/vp", async (context) => {
    const body = await parseBody(context.req.json<VerifyRequest>());
    if (!hasToken(body)) {
      return context.json({ ok: false, error: "verification request requires token" }, 400);
    }
    const audience = typeof body.audience === "string" ? body.audience : undefined;
    const nonce = typeof body.nonce === "string" ? body.nonce : undefined;
    logVerifierEvent("verification.received", {
      verifier: config.verifierId,
      route: "/verify/vp",
      artifactKind: "vp+jwt",
      ...tokenObservability(body.token)
    });
    try {
      const result = await run(() => requestVerifier.verifyVp(body.token, { audience, nonce }));
      if (result.ok) {
        const warning = await webhook.sendPresentation(result);
        if (warning) {
          result.warnings.push(warning);
        }
      }
      logVerificationResult(config, "vp+jwt", result);
      return context.json(result);
    } catch (error) {
      logVerificationError(config, "vp+jwt", error);
      throw error;
    }
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
  runtime?: VerifierRuntime
): Operation<void> {
  const app = createApp(config, runtime);
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
 * Adapt a verifier runtime into the narrower HTTP-layer verification hooks.
 */
function createRequestVerifier(runtime: VerifierRuntime): RequestVerifier {
  return {
    verifyVc: (token) => verifyVcOp(runtime, token),
    verifyVp: (token, options) => verifyVpOp(runtime, token, options)
  };
}
