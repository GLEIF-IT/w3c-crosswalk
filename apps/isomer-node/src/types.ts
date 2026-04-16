export interface SidecarConfig {
  host: string;
  port: number;
  resolverUrl: string;
  resourceRoot: string;
}

export interface VerificationResult {
  ok: boolean;
  kind: "vc+jwt" | "vp+jwt";
  errors: string[];
  warnings: string[];
  payload: Record<string, unknown> | null;
  checks: Record<string, unknown>;
  nested?: VerificationResult[];
}

export interface VerifyRequest {
  token?: unknown;
  audience?: unknown;
  nonce?: unknown;
}

export interface JwtParts {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signingInput: Uint8Array;
  signature: Uint8Array;
}
