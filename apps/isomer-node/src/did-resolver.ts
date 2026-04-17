/**
 * `did:webs` resolver adaptation for the Node verifier stack.
 *
 * Isomer resolves issuer and presenter key state through the HTTP
 * `did-webs-resolver` service. The Node JWT libraries, however, expect
 * JWK-oriented verification material. This module bridges that mismatch by
 * fetching resolved DID documents, normalizing verification methods, and
 * synthesizing JWK views for Multikey-only Ed25519 methods when required.
 */
import type { DIDResolutionOptions, DIDResolutionResult, Resolvable } from "did-resolver";
import type { Operation } from "effection";
import { decodeBase58btcMultibase, base64UrlEncode } from "./base58.js";
import { promiseToOperation } from "./effection.js";
import { isRecord } from "./jwt.js";

// Multikey Ed25519 public keys begin with the multicodec prefix `0xed01`.
// When the resolver returns only `publicKeyMultibase`, the sidecar uses this
// prefix to recognize Ed25519 material and synthesize an equivalent OKP JWK.
const ED25519_MULTIKEY_PREFIX = Uint8Array.from([0xed, 0x01]);

// did-jwt-oriented consumers only understand a small set of Ed25519 method
// shapes. Normalization lifts resolver output into one of these compatible
// forms before JWT libraries consume the DID document.
const DID_JWT_EDDSA_KEY_TYPES = new Set([
  "ED25519SignatureVerification",
  "Ed25519VerificationKey2018",
  "Ed25519VerificationKey2020",
  "JsonWebKey2020",
  "Multikey"
]);

/**
 * Resolve `did:webs` documents through the Isomer resolver HTTP surface.
 *
 * Results are cached per DID, not per fragment, because all verification
 * methods within one document share the same resolver response.
 */
export class DidWebsResolver implements Resolvable {
  readonly #baseUrl: string;
  readonly #cache = new Map<string, DIDResolutionResult>();

  /**
   * Create a resolver rooted at the `did-webs-resolver` identifiers endpoint.
   */
  constructor(baseUrl: string) {
    this.#baseUrl = baseUrl.replace(/\/+$/, "");
  }

  /**
   * Resolve one DID URL using the `did-resolver` interface contract.
   */
  async resolve(didUrl: string, _options?: DIDResolutionOptions): Promise<DIDResolutionResult> {
    return await this.#resolveDid(didUrl);
  }

  async #resolveDid(didUrl: string, signal?: AbortSignal): Promise<DIDResolutionResult> {
    const did = didUrl.split("#", 1)[0];
    const cached = this.#cache.get(did);
    if (cached) {
      return cached;
    }

    const response = await fetch(`${this.#baseUrl}/${did}`, {
      headers: { Accept: "application/json" },
      signal
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

  /**
   * Resolve one DID URL as an Effection operation with abort support.
   */
  resolveOp(didUrl: string): Operation<DIDResolutionResult> {
    return promiseToOperation((signal) => this.#resolveDid(didUrl, signal));
  }
}

/**
 * Find one verification method in a resolved DID document by `kid`-style
 * reference, fragment, or document-scoped fragment reference.
 */
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
    if (isMatchingMethodReference(id, kid, fragment)) {
      return method;
    }
  }
  throw new Error(`verification method ${kid} not found in resolved DID document`);
}

/**
 * Return a public JWK view for one resolved verification method.
 *
 * If the resolver already exposed `publicKeyJwk`, this function returns it
 * directly. If the method is Multikey-only, it synthesizes an equivalent OKP
 * Ed25519 JWK for local consumers.
 */
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

/**
 * Normalize one verification relationship into embedded method objects.
 *
 * `did-jwt` consumers are easier to satisfy when relationship arrays already
 * contain method objects instead of only string references.
 */
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

/**
 * Find one method object by string reference within a method list.
 */
function findMethodByReference(methods: unknown[], reference: string): Record<string, unknown> | undefined {
  const fragment = reference.includes("#") ? reference.split("#", 2)[1] : reference.replace(/^#/, "");
  return methods.filter(isRecord).find((method) => {
    const id = typeof method.id === "string" ? method.id : "";
    return isMatchingMethodReference(id, reference, fragment);
  });
}

/**
 * Match method references across exact, fragment-only, and document-scoped
 * fragment forms.
 */
function isMatchingMethodReference(id: string, reference: string, fragment: string): boolean {
  const isExactReference = id === reference;
  const isFragmentReference = id === `#${fragment}`;
  const isDocumentScopedReference = id.endsWith(`#${fragment}`);
  return isExactReference || isFragmentReference || isDocumentScopedReference;
}

/**
 * Check whether one byte sequence begins with a multicodec prefix.
 */
function startsWith(value: Uint8Array, prefix: Uint8Array): boolean {
  if (value.length < prefix.length) {
    return false;
  }
  return prefix.every((byte, index) => value[index] === byte);
}
