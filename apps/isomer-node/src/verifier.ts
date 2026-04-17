/**
 * Core verification pipeline for the isomer-node sidecar.
 *
 * The pipeline order matters:
 * 1. decode and validate JWT claim structure,
 * 2. verify JWT envelope and signature through `did-jwt-vc`,
 * 3. resolve the proof verification method through `did:webs`,
 * 4. verify the embedded Data Integrity proof,
 * 5. fetch and evaluate projected credential status,
 * 6. recurse into nested VC-JWTs when verifying a VP-JWT.
 *
 * This file owns W3C-side acceptance only. It does not attempt Python Isomer's
 * TEL-aware ACDC/W3C pair semantics.
 */
import type { Operation } from "effection";
import { verifyDataIntegrityProof } from "./data-integrity.js";
import { verifyCredentialJwtOp, verifyPresentationJwtOp } from "./did-jwt-vc.js";
import { DidWebsResolver, findVerificationMethod } from "./did-resolver.js";
import { promiseToOperation } from "./effection.js";
import { asRecord, asString, decodeJwt, isRecord } from "./jwt.js";
import { LocalContextLoader } from "./local-contexts.js";
import { checkStatus, fetchStatus } from "./status.js";
import type {
  SidecarConfig,
  VcChecks,
  VcVerificationResult,
  VerificationResult,
  VpChecks,
  VpVerificationResult
} from "./types.js";

/**
 * Runtime-owned effectful collaborators used by the verifier workflows.
 *
 * The runtime owns the long-lived resolver/context state plus the effectful
 * verification steps. Tests replace these seams at runtime construction time
 * instead of reaching through a nested dependency bag.
 */
export interface VerifierRuntime {
  resolver: DidWebsResolver;
  contexts: LocalContextLoader;
  verifyCredentialJwtOp: (token: string) => Operation<void>;
  verifyPresentationJwtOp: (
    token: string,
    options: { audience?: string; nonce?: string }
  ) => Operation<void>;
  verifyDataIntegrityProofOp: (
    document: Record<string, unknown>,
    method: Record<string, unknown>
  ) => Operation<boolean>;
  fetchStatusOp: (url: string | undefined) => Operation<Record<string, unknown> | null>;
}

/**
 * Construct one verifier runtime from config and optional test hooks.
 */
export function createVerifierRuntime(
  config: Pick<SidecarConfig, "resolverUrl" | "resourceRoot">,
  overrides: Partial<VerifierRuntime> = {}
): VerifierRuntime {
  const resolver = overrides.resolver ?? new DidWebsResolver(config.resolverUrl);
  const contexts = overrides.contexts ?? new LocalContextLoader(config.resourceRoot);

  return {
    resolver,
    contexts,
    verifyCredentialJwtOp: overrides.verifyCredentialJwtOp ?? ((token) => verifyCredentialJwtOp(token, resolver)),
    verifyPresentationJwtOp: overrides.verifyPresentationJwtOp ?? (
      (token, options) => verifyPresentationJwtOp(token, resolver, options)
    ),
    verifyDataIntegrityProofOp: overrides.verifyDataIntegrityProofOp ?? (
      (document, method) => promiseToOperation(() => verifyDataIntegrityProof(document, method, contexts))
    ),
    fetchStatusOp: overrides.fetchStatusOp ?? fetchStatus
  };
}

/**
 * Verify one VC-JWT and return the sidecar result contract.
 *
 * `checks` show which verification stages completed successfully:
 * - `jwtEnvelopeValid`: local claim shape checks passed
 * - `signatureValid`: `did-jwt-vc` accepted the JWT envelope and signature
 * - `dataIntegrityProofValid`: the embedded proof verified against the resolved
 *   verification method
 * - `statusActive`: projected credential status did not mark the credential
 *   revoked
 */
export function* verifyVcOp(
  runtime: VerifierRuntime,
  token: string
): Operation<VcVerificationResult> {
  const errors: string[] = [];
  let payload: Record<string, unknown> | null = null;
  const checks: VcChecks = {
    jwtEnvelopeValid: false,
    signatureValid: false,
    dataIntegrityProofValid: false,
    statusActive: false
  };

  try {
    // Stage 1: decode the JWT locally and lock the minimum VC claim semantics.
    const decoded = decodeJwt(token);
    payload = requireVcPayload(decoded.payload);
    validateVcClaims(decoded.payload, payload);
    checks.jwtEnvelopeValid = true;

    // Stage 2: validate the VC-JWT envelope and signature through did-jwt-vc.
    yield* runtime.verifyCredentialJwtOp(token);
    checks.signatureValid = true;

    // Stage 3: verify the embedded proof and projected status explicitly.
    // JWT validation proves the VC-JWT envelope. The embedded proof and status
    // still need explicit checks because they carry Isomer-specific semantics.
    const method = yield* resolveProofVerificationMethodOp(runtime.resolver, decoded, payload);
    checks.dataIntegrityProofValid = yield* runtime.verifyDataIntegrityProofOp(
      payload as Record<string, unknown>,
      method
    );

    const status = yield* runtime.fetchStatusOp(statusUrl(payload));
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

/**
 * Verify one VP-JWT and recursively verify its embedded VC-JWTs.
 *
 * `checks.embeddedCredentialsVerified` counts how many nested credentials
 * completed successfully under the same VC verification pipeline.
 */
export function* verifyVpOp(
  runtime: VerifierRuntime,
  token: string,
  options: { audience?: string; nonce?: string } = {}
): Operation<VpVerificationResult> {
  const errors: string[] = [];
  let payload: Record<string, unknown> | null = null;
  const checks: VpChecks = {
    jwtEnvelopeValid: false,
    signatureValid: false,
    embeddedCredentialsVerified: 0
  };
  const nested: VcVerificationResult[] = [];

  try {
    // Stage 1: decode the JWT locally and lock the minimum VP claim semantics.
    const decoded = decodeJwt(token);
    payload = requireVpPayload(decoded.payload);
    validateVpClaims(decoded.payload, payload, options);
    checks.jwtEnvelopeValid = true;

    // Stage 2: validate the VP-JWT envelope and holder signature.
    yield* runtime.verifyPresentationJwtOp(token, options);
    checks.signatureValid = true;

    // Stage 3: recurse through each embedded VC-JWT.
    const credentials = requireNestedCredentialList(payload);
    for (const credential of credentials) {
      if (typeof credential !== "string") {
        errors.push("only nested VC-JWT strings are supported");
        continue;
      }
      const result = yield* verifyVcOp(runtime, credential);
      nested.push(result);
      if (!result.ok) {
        errors.push(...result.errors.map((item) => `nested credential: ${item}`));
      }
    }
    checks.embeddedCredentialsVerified = nested.filter(isSuccessfulVcVerification).length;
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

/**
 * Enforce the VC-JWT claim relationships Isomer expects before deeper checks.
 */
function validateVcClaims(jwtPayload: Record<string, unknown>, vc: Record<string, unknown>): void {
  const issuer = asString(vc.issuer);
  const id = asString(vc.id);
  const subject = asRecord(vc.credentialSubject);
  const issuerMatches = !issuer || jwtPayload.iss === issuer;
  const idMatches = !id || jwtPayload.jti === id;
  const subjectId = asString(subject?.id);
  const subjectMatches = !subjectId || jwtPayload.sub === subjectId;
  const hasNumericNbf = typeof jwtPayload.nbf === "number";
  const hasNumericIat = typeof jwtPayload.iat === "number";

  if (!issuerMatches) {
    throw new Error("JWT iss does not match vc.issuer");
  }
  if (!idMatches) {
    throw new Error("JWT jti does not match vc.id");
  }
  if (!subjectMatches) {
    throw new Error("JWT sub does not match credentialSubject.id");
  }
  if (!hasNumericNbf || !hasNumericIat) {
    throw new Error("VC-JWT requires numeric iat and nbf");
  }
}

/**
 * Enforce the VP-JWT claim relationships Isomer expects before deeper checks.
 */
function validateVpClaims(
  jwtPayload: Record<string, unknown>,
  vp: Record<string, unknown>,
  options: { audience?: string; nonce?: string }
): void {
  const holder = asString(vp.holder);
  const holderMatches = !holder || jwtPayload.iss === holder;
  const audienceMatches = !options.audience || jwtPayload.aud === options.audience;
  const nonceMatches = !options.nonce || jwtPayload.nonce === options.nonce;
  const hasNumericIat = typeof jwtPayload.iat === "number";

  if (!holderMatches) {
    throw new Error("JWT iss does not match vp.holder");
  }
  if (!audienceMatches) {
    throw new Error("JWT aud does not match expected audience");
  }
  if (!nonceMatches) {
    throw new Error("JWT nonce does not match expected nonce");
  }
  if (!hasNumericIat) {
    throw new Error("VP-JWT requires numeric iat");
  }
}

/**
 * Extract the projected W3C credential status URL from one VC payload.
 */
function statusUrl(vc: Record<string, unknown>): string | undefined {
  const status = vc.credentialStatus;
  return isRecord(status) ? asString(status.id) : undefined;
}

/**
 * Require the `vc` claim and return it as a JSON object.
 */
function requireVcPayload(jwtPayload: Record<string, unknown>): Record<string, unknown> {
  const vc = asRecord(jwtPayload.vc);
  if (!vc) {
    throw new Error("missing vc claim");
  }
  return vc;
}

/**
 * Require the `vp` claim and return it as a JSON object.
 */
function requireVpPayload(jwtPayload: Record<string, unknown>): Record<string, unknown> {
  const vp = asRecord(jwtPayload.vp);
  if (!vp) {
    throw new Error("missing vp claim");
  }
  return vp;
}

/**
 * Require `vp.verifiableCredential` to be a list before nested verification.
 */
function requireNestedCredentialList(vp: Record<string, unknown>): unknown[] {
  if (!Array.isArray(vp.verifiableCredential)) {
    throw new Error("vp.verifiableCredential must be a list");
  }
  return vp.verifiableCredential;
}

/**
 * Resolve the verification method used for the embedded Data Integrity proof.
 *
 * The proof check follows the JWT issuer and `kid` back through resolved
 * `did:webs` state instead of trusting proof material embedded in the VC alone.
 */
function* resolveProofVerificationMethodOp(
  resolver: DidWebsResolver,
  decoded: ReturnType<typeof decodeJwt>,
  vc: Record<string, unknown>
): Operation<Record<string, unknown>> {
  const issuer = asString(decoded.payload.iss) ?? asString(vc.issuer);
  const kid = asString(decoded.header.kid);
  if (!issuer || !kid) {
    throw new Error("VC-JWT requires issuer and kid");
  }
  const didResolution = yield* resolver.resolveOp(issuer);
  const didDocument = didResolution.didDocument as unknown as Record<string, unknown>;
  return findVerificationMethod(didDocument, kid);
}

/**
 * Narrow a generic verification result to a successful VC verification result.
 */
function isSuccessfulVcVerification(result: VerificationResult): result is VcVerificationResult {
  return result.kind === "vc+jwt" && result.ok;
}
