import { action, type Operation } from "effection";
import type { DIDResolutionResult, Resolvable } from "did-resolver";
import { decodeBase58btcMultibase, base64UrlEncode } from "./base58.js";
import { isRecord } from "./jwt.js";

const ED25519_MULTIKEY_PREFIX = Uint8Array.from([0xed, 0x01]);
const DID_JWT_EDDSA_KEY_TYPES = new Set([
  "ED25519SignatureVerification",
  "Ed25519VerificationKey2018",
  "Ed25519VerificationKey2020",
  "JsonWebKey2020",
  "Multikey"
]);

export class DidWebsResolver implements Resolvable {
  readonly #baseUrl: string;
  readonly #cache = new Map<string, DIDResolutionResult>();

  constructor(baseUrl: string) {
    this.#baseUrl = baseUrl.replace(/\/+$/, "");
  }

  async resolve(didUrl: string): Promise<DIDResolutionResult> {
    const did = didUrl.split("#", 1)[0];
    const cached = this.#cache.get(did);
    if (cached) {
      return cached;
    }

    const response = await fetch(`${this.#baseUrl}/${did}`, {
      headers: { Accept: "application/json" }
    });
    const body = await response.json();
    if (!response.ok) {
      throw new Error(`did:webs resolver returned HTTP ${response.status} for ${did}`);
    }
    const didDocument = isRecord(body) && isRecord(body.didDocument) ? body.didDocument : body;
    if (!isRecord(didDocument)) {
      throw new Error(`did:webs resolver response did not contain a DID document for ${did}`);
    }

    normalizeVerificationMethods(didDocument);
    const result: DIDResolutionResult = {
      didDocument: didDocument as DIDResolutionResult["didDocument"],
      didDocumentMetadata: isRecord(body.didDocumentMetadata) ? body.didDocumentMetadata : {},
      didResolutionMetadata: isRecord(body.didResolutionMetadata) ? body.didResolutionMetadata : {}
    };
    this.#cache.set(did, result);
    return result;
  }

  resolveOp(didUrl: string): Operation<DIDResolutionResult> {
    return promiseOp(this.resolve(didUrl));
  }
}

export function findVerificationMethod(
  didDocument: Record<string, unknown>,
  kid: string
): Record<string, unknown> {
  const fragment = kid.includes("#") ? kid.split("#", 2)[1] : kid.replace(/^#/, "");
  const methods = Array.isArray(didDocument.verificationMethod) ? didDocument.verificationMethod : [];
  for (const method of methods) {
    if (!isRecord(method)) {
      continue;
    }
    const id = typeof method.id === "string" ? method.id : "";
    if (id === kid || id === `#${fragment}` || id.endsWith(`#${fragment}`)) {
      return method;
    }
  }
  throw new Error(`verification method ${kid} not found in resolved DID document`);
}

export function publicJwkFromMethod(method: Record<string, unknown>): Record<string, string> {
  if (isRecord(method.publicKeyJwk)) {
    return method.publicKeyJwk as Record<string, string>;
  }

  if (typeof method.publicKeyMultibase === "string") {
    // The Node verifier stack is did-jwt-oriented, so when a resolved method is
    // Multikey-only we synthesize an equivalent Ed25519 OKP JWK view for local
    // consumers rather than patching publicKeyMultibase onto JWK-native methods.
    const raw = decodeBase58btcMultibase(method.publicKeyMultibase);
    if (!startsWith(raw, ED25519_MULTIKEY_PREFIX)) {
      throw new Error("only Ed25519 publicKeyMultibase methods are supported");
    }
    const key = raw.slice(ED25519_MULTIKEY_PREFIX.length);
    return { kty: "OKP", crv: "Ed25519", x: base64UrlEncode(key) };
  }

  throw new Error("resolved verification method did not expose publicKeyJwk or publicKeyMultibase");
}

function normalizeVerificationMethods(didDocument: Record<string, unknown>): void {
  const methods = Array.isArray(didDocument.verificationMethod) ? didDocument.verificationMethod : [];
  for (const method of methods) {
    if (!isRecord(method)) {
      continue;
    }
    // did-jwt expects JWK-shaped verification material, so normalize Multikey
    // methods by synthesizing publicKeyJwk when needed. Unlike the Python path,
    // this sidecar does not patch publicKeyMultibase onto JWK-native methods.
    if (!isRecord(method.publicKeyJwk) && typeof method.publicKeyMultibase === "string") {
      method.publicKeyJwk = publicJwkFromMethod(method);
    }
    if (!DID_JWT_EDDSA_KEY_TYPES.has(typeof method.type === "string" ? method.type : "")) {
      const jwk = isRecord(method.publicKeyJwk) ? method.publicKeyJwk : undefined;
      if (jwk?.kty === "OKP" && jwk?.crv === "Ed25519") {
        method.type = "JsonWebKey2020";
      } else if (typeof method.publicKeyMultibase === "string") {
        method.type = "Multikey";
      }
    }
  }
  normalizeVerificationRelationship(didDocument, "assertionMethod", methods);
  normalizeVerificationRelationship(didDocument, "authentication", methods);
}

function normalizeVerificationRelationship(
  didDocument: Record<string, unknown>,
  relationship: "assertionMethod" | "authentication",
  methods: unknown[]
): void {
  const existing = Array.isArray(didDocument[relationship]) ? didDocument[relationship] : [];
  const normalized = existing
    .map((item) => (typeof item === "string" ? findMethodByReference(methods, item) : item))
    .filter(isRecord);
  didDocument[relationship] = normalized.length > 0 ? normalized : methods.filter(isRecord);
}

function findMethodByReference(methods: unknown[], reference: string): Record<string, unknown> | undefined {
  const fragment = reference.includes("#") ? reference.split("#", 2)[1] : reference.replace(/^#/, "");
  return methods.filter(isRecord).find((method) => {
    const id = typeof method.id === "string" ? method.id : "";
    return id === reference || id === `#${fragment}` || id.endsWith(`#${fragment}`);
  });
}

function startsWith(value: Uint8Array, prefix: Uint8Array): boolean {
  if (value.length < prefix.length) {
    return false;
  }
  return prefix.every((byte, index) => value[index] === byte);
}

export function promiseOp<T>(promise: Promise<T>): Operation<T> {
  return action<T>((resolve, reject) => {
    promise.then(resolve).catch(reject);
    return () => {};
  });
}
