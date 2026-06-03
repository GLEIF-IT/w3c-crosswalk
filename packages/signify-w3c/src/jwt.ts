import { canonicalizeDidUrl, canonicalizeDidWebs, unixTimestamp } from "./common.js";
import { EDDSA, VC_CONTEXT, VC_JWT_TYP, VP_JWT_TYP } from "./constants.js";
import { addDataIntegrityProof } from "./data-integrity.js";
import { base64UrlDecode, base64UrlEncode, canonicalJsonBytes, cloneJson, utf8Bytes } from "./encoding.js";
import type { DecodedJwt, JsonObject, Signer } from "./types.js";

export async function encodeJwt(payload: JsonObject, { typ, kid, signer }: {
  typ: string;
  kid: string;
  signer: Signer;
}): Promise<string> {
  const header = { alg: EDDSA, kid, typ };
  const encodedHeader = base64UrlEncode(canonicalJsonBytes(header));
  const encodedPayload = base64UrlEncode(canonicalJsonBytes(payload));
  const signingInput = utf8Bytes(`${encodedHeader}.${encodedPayload}`);
  const signature = await signer.sign(signingInput);
  return `${encodedHeader}.${encodedPayload}.${base64UrlEncode(signature)}`;
}

export function decodeJwt(token: string): DecodedJwt {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("JWT must contain exactly three segments");
  }
  const [headerB64, payloadB64, signatureB64] = parts;
  return {
    header: JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64))) as JsonObject,
    payload: JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64))) as JsonObject,
    signature: base64UrlDecode(signatureB64),
    signingInput: utf8Bytes(`${headerB64}.${payloadB64}`)
  };
}

export async function issueVcJwt(
  vc: JsonObject,
  {
    signer,
    verificationMethod,
    proofCreated
  }: {
    signer: Signer;
    verificationMethod?: string;
    proofCreated?: string;
  }
): Promise<{ vcJwt: string; securedVc: JsonObject }> {
  const method = verificationMethod ?? proofMethod(vc);
  const kid = canonicalizeDidUrl(method);
  const securedVc = vc.proof === undefined
    ? await addDataIntegrityProof(vc, { signer, verificationMethod: kid, created: proofCreated })
    : cloneJson(vc);
  const payload = buildVcJwtPayload(securedVc);
  return { vcJwt: await encodeJwt(payload, { typ: VC_JWT_TYP, kid, signer }), securedVc };
}

export function buildVcJwtPayload(vc: JsonObject): JsonObject {
  const subject = recordField(vc, "credentialSubject");
  const issuanceDate = typeof vc.issuanceDate === "string" ? vc.issuanceDate : "";
  return {
    iss: vc.issuer,
    sub: subject.id,
    jti: vc.id,
    iat: unixTimestamp(issuanceDate),
    nbf: unixTimestamp(issuanceDate),
    vc
  };
}

export async function issueVpJwt(
  vcTokens: string[],
  {
    holderDid,
    signer,
    audience,
    nonce,
    presentationId
  }: {
    holderDid: string;
    signer: Signer;
    audience?: string;
    nonce?: string;
    presentationId?: string;
  }
): Promise<{ vpJwt: string; vp: JsonObject }> {
  const canonicalHolderDid = canonicalizeDidWebs(holderDid);
  const vpId = presentationId ?? `urn:uuid:${randomUuid()}`;
  const vp: JsonObject = {
    "@context": [VC_CONTEXT],
    id: vpId,
    type: ["VerifiablePresentation"],
    holder: canonicalHolderDid,
    verifiableCredential: vcTokens
  };
  const payload: JsonObject = {
    iss: canonicalHolderDid,
    jti: vpId,
    iat: Math.floor(Date.now() / 1000),
    vp
  };
  if (audience) {
    payload.aud = audience;
  }
  if (nonce) {
    payload.nonce = nonce;
  }
  const kid = canonicalizeDidUrl(`${canonicalHolderDid}#${signer.kid}`);
  return { vpJwt: await encodeJwt(payload, { typ: VP_JWT_TYP, kid, signer }), vp };
}

function proofMethod(vc: JsonObject): string {
  const proof = recordField(vc, "proof");
  if (typeof proof.verificationMethod !== "string" || proof.verificationMethod.trim().length === 0) {
    throw new Error("VC-JWT issuance requires a verification method");
  }
  return proof.verificationMethod;
}

function recordField(record: JsonObject, field: string): JsonObject {
  const value = record[field];
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as JsonObject
    : {};
}

function randomUuid(): string {
  if (globalThis.crypto?.randomUUID !== undefined) {
    return globalThis.crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  globalThis.crypto?.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map(byte => byte.toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex.slice(6, 8).join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10).join("")}`;
}
