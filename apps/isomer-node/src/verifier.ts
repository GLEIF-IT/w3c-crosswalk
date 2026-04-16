import { verifyCredential, verifyPresentation } from "did-jwt-vc";
import type { Operation } from "effection";
import { DidWebsResolver, findVerificationMethod, promiseOp } from "./did-resolver.js";
import { verifyDataIntegrityProof } from "./data-integrity.js";
import { asRecord, asString, decodeJwt, isRecord } from "./jwt.js";
import { LocalContextLoader } from "./local-contexts.js";
import { checkStatus, fetchStatus } from "./status.js";
import type { VerificationResult } from "./types.js";

export class ExternalVerifier {
  readonly #resolver: DidWebsResolver;
  readonly #contexts: LocalContextLoader;

  constructor({ resolverUrl, resourceRoot }: { resolverUrl: string; resourceRoot: string }) {
    this.#resolver = new DidWebsResolver(resolverUrl);
    this.#contexts = new LocalContextLoader(resourceRoot);
  }

  *verifyVc(token: string): Operation<VerificationResult> {
    const errors: string[] = [];
    let payload: Record<string, unknown> | null = null;
    const checks: Record<string, unknown> = {
      jwtEnvelopeValid: false,
      signatureValid: false,
      dataIntegrityProofValid: false,
      statusActive: false
    };

    try {
      const decoded = decodeJwt(token);
      payload = asRecord(decoded.payload.vc) ?? null;
      if (!payload) {
        throw new Error("missing vc claim");
      }
      validateVcClaims(decoded.payload, payload);
      checks.jwtEnvelopeValid = true;

      yield* promiseOp(verifyCredential(token, this.#resolver, { policies: { format: true } }));
      checks.signatureValid = true;

      const issuer = asString(decoded.payload.iss) ?? asString(payload.issuer);
      const kid = asString(decoded.header.kid);
      if (!issuer || !kid) {
        throw new Error("VC-JWT requires issuer and kid");
      }
      const didResolution = yield* this.#resolver.resolveOp(issuer);
      const didDocument = didResolution.didDocument as unknown as Record<string, unknown>;
      const method = findVerificationMethod(didDocument, kid);
      checks.dataIntegrityProofValid = yield* promiseOp(verifyDataIntegrityProof(payload, method, this.#contexts));

      const status = yield* fetchStatus(statusUrl(payload));
      checks.statusActive = checkStatus(status, errors);
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }

    return {
      ok: errors.length === 0,
      kind: "vc+jwt",
      errors,
      warnings: [],
      payload,
      checks
    };
  }

  *verifyVp(token: string, options: { audience?: string; nonce?: string } = {}): Operation<VerificationResult> {
    const errors: string[] = [];
    let payload: Record<string, unknown> | null = null;
    const checks: Record<string, unknown> = {
      jwtEnvelopeValid: false,
      signatureValid: false,
      embeddedCredentialsVerified: 0
    };
    const nested: VerificationResult[] = [];

    try {
      const decoded = decodeJwt(token);
      payload = asRecord(decoded.payload.vp) ?? null;
      if (!payload) {
        throw new Error("missing vp claim");
      }
      validateVpClaims(decoded.payload, payload, options);
      checks.jwtEnvelopeValid = true;

      yield* promiseOp(verifyPresentation(token, this.#resolver, {
        domain: options.audience,
        challenge: options.nonce,
        policies: { format: true }
      }));
      checks.signatureValid = true;

      const credentials = payload.verifiableCredential;
      if (!Array.isArray(credentials)) {
        throw new Error("vp.verifiableCredential must be a list");
      }
      for (const credential of credentials) {
        if (typeof credential !== "string") {
          errors.push("only nested VC-JWT strings are supported");
          continue;
        }
        const result = yield* this.verifyVc(credential);
        nested.push(result);
        if (!result.ok) {
          errors.push(...result.errors.map((item) => `nested credential: ${item}`));
        }
      }
      checks.embeddedCredentialsVerified = nested.filter((result) => result.ok).length;
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }

    return {
      ok: errors.length === 0,
      kind: "vp+jwt",
      errors,
      warnings: [],
      payload,
      checks,
      nested
    };
  }
}

function validateVcClaims(jwtPayload: Record<string, unknown>, vc: Record<string, unknown>): void {
  const issuer = asString(vc.issuer);
  const id = asString(vc.id);
  const subject = asRecord(vc.credentialSubject);
  if (issuer && jwtPayload.iss !== issuer) {
    throw new Error("JWT iss does not match vc.issuer");
  }
  if (id && jwtPayload.jti !== id) {
    throw new Error("JWT jti does not match vc.id");
  }
  if (subject && asString(subject.id) && jwtPayload.sub !== subject.id) {
    throw new Error("JWT sub does not match credentialSubject.id");
  }
  if (typeof jwtPayload.nbf !== "number" || typeof jwtPayload.iat !== "number") {
    throw new Error("VC-JWT requires numeric iat and nbf");
  }
}

function validateVpClaims(
  jwtPayload: Record<string, unknown>,
  vp: Record<string, unknown>,
  options: { audience?: string; nonce?: string }
): void {
  const holder = asString(vp.holder);
  if (holder && jwtPayload.iss !== holder) {
    throw new Error("JWT iss does not match vp.holder");
  }
  if (options.audience && jwtPayload.aud !== options.audience) {
    throw new Error("JWT aud does not match expected audience");
  }
  if (options.nonce && jwtPayload.nonce !== options.nonce) {
    throw new Error("JWT nonce does not match expected nonce");
  }
  if (typeof jwtPayload.iat !== "number") {
    throw new Error("VP-JWT requires numeric iat");
  }
}

function statusUrl(vc: Record<string, unknown>): string | undefined {
  const status = vc.credentialStatus;
  return isRecord(status) ? asString(status.id) : undefined;
}
