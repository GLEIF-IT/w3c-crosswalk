/**
 * Public config, request, and response contracts for the Node sidecar.
 */
/**
 * Runtime configuration for the HTTP sidecar process.
 */
export interface SidecarConfig {
  host: string;
  port: number;
  resolverUrl: string;
  resourceRoot: string;
  webhookUrl?: string;
  verifierId: string;
  verifierLabel?: string;
}

/**
 * Stage-by-stage verification flags returned for one VC-JWT.
 */
export interface VcChecks {
  /** Local VC claim-shape checks succeeded. */
  jwtEnvelopeValid: boolean;
  /** `did-jwt-vc` accepted the JWT signature and envelope. */
  signatureValid: boolean;
  /** The embedded Data Integrity proof verified successfully. */
  dataIntegrityProofValid: boolean;
  /** Projected credential status did not mark the credential revoked. */
  statusActive: boolean;
}

/**
 * Stage-by-stage verification flags returned for one VP-JWT.
 */
export interface VpChecks {
  /** Local VP claim-shape checks succeeded. */
  jwtEnvelopeValid: boolean;
  /** `did-jwt-vc` accepted the JWT signature and envelope. */
  signatureValid: boolean;
  /** Number of nested VC-JWTs that completed successfully. */
  embeddedCredentialsVerified: number;
}

// Shared result shape used by VC-JWT and VP-JWT verification responses.
interface VerificationResultBase<TKind extends "vc+jwt" | "vp+jwt", TChecks> {
  ok: boolean;
  kind: TKind;
  errors: string[];
  warnings: string[];
  payload: Record<string, unknown> | null;
  checks: TChecks;
}

/**
 * Verification response for one VC-JWT.
 */
export interface VcVerificationResult extends VerificationResultBase<"vc+jwt", VcChecks> {
  nested?: undefined;
}

/**
 * Verification response for one VP-JWT, including nested VC results.
 */
export interface VpVerificationResult extends VerificationResultBase<"vp+jwt", VpChecks> {
  nested: VcVerificationResult[];
}

/**
 * Union of all top-level sidecar verification responses.
 */
export type VerificationResult = VcVerificationResult | VpVerificationResult;

/**
 * JSON request body accepted by the HTTP verify routes.
 */
export interface VerifyRequest {
  token?: unknown;
  audience?: unknown;
  nonce?: unknown;
}

/**
 * Structurally decoded compact JWT parts used by the verifier pipeline.
 */
export interface JwtParts {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: Uint8Array;
  signature: Uint8Array;
}
