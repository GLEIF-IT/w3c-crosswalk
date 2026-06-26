export type JsonObject = Record<string, unknown>;

export interface Signer {
  kid: string;
  sign(data: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

export interface DecodedJwt {
  header: JsonObject;
  payload: JsonObject;
  signature: Uint8Array;
  signingInput: Uint8Array;
}

export interface W3CIssuanceContext {
  issuanceId: string;
  issuerName: string;
  issuerAid: string;
  holderAid: string;
  sourceCredentialSaid: string;
  schemaSaid: string;
  issuerDid: string;
  holderDid: string;
  statusUrl: string;
  statusBaseUrl?: string;
  profile: string;
  state: string;
  sourceCredential?: JsonObject;
  decodedVc?: JsonObject | null;
  vcJwt?: string | null;
  grantSaid?: string | null;
  error?: string | null;
  [key: string]: unknown;
}

export interface W3CHeldCredential {
  credentialId: string;
  holderName: string;
  holderAid: string;
  holderDid: string;
  issuerAid: string;
  issuerDid: string;
  sourceCredentialSaid: string;
  schemaSaid: string;
  profile: string;
  statusUrl: string;
  vcJwt?: string;
  decodedVc?: JsonObject;
  state: string;
  error?: string | null;
  [key: string]: unknown;
}

export interface W3CPresentationResult {
  presentationId: string;
  holderName: string;
  holderAid: string;
  holderDid: string;
  contactId: string;
  requestDescriptor: JsonObject;
  state: string;
  nonce?: string | null;
  aud?: string | null;
  selectedCredentialId?: string | null;
  vpJwt?: string | null;
  verifierResponse?: unknown;
  error?: string | null;
  [key: string]: unknown;
}
