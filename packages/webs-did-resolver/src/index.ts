import {
  parse,
  type DIDResolutionResult,
  type DIDResolver,
  type JsonWebKey,
  type ResolverRegistry
} from "did-resolver";

/**
 * Multicodec prefix for Ed25519 public keys encoded in Multikey form.
 *
 * `publicJwkFromMethod(...)` uses this prefix to distinguish the one Multikey
 * variant we intentionally support in v1 from other possible multicodec key
 * types that would require different JWK projections.
 */
const ED25519_MULTIKEY_PREFIX = Uint8Array.from([0xed, 0x01]);

/**
 * Verification method types that common JS JWT verifiers already understand for
 * Ed25519 signature verification.
 */
const DID_JWT_EDDSA_KEY_TYPES = new Set([
  "ED25519SignatureVerification",
  "Ed25519VerificationKey2018",
  "Ed25519VerificationKey2020",
  "JsonWebKey2020",
  "Multikey"
]);

/**
 * Narrow error codes used when translating local resolver failures into
 * `did-resolver`-style `didResolutionMetadata.error` values.
 */
type ResolverErrorCode = "invalidDid" | "notFound" | "internalError";

/**
 * Resolver JSON envelope returned by the existing `did-webs-resolver` HTTP
 * service.
 *
 * The service may return either this full DID resolution envelope or the raw
 * DID document directly, so `parseDidWebsResolution(...)` accepts both shapes.
 */
interface ResolverEnvelope {
  didDocument?: unknown;
  didDocumentMetadata?: unknown;
  didResolutionMetadata?: unknown;
}

/**
 * Configuration for the `did:webs` method resolver.
 */
export interface DidWebsResolverOptions {
  /**
   * Base URL of the resolver service, ending at the identifiers collection such
   * as `http://127.0.0.1:7678/1.0/identifiers`.
   */
  resolverUrl: string;
  /**
   * Optional fetch implementation override used primarily by tests or alternate
   * runtimes.
   */
  fetch?: typeof fetch;
  /**
   * Optional additional request headers forwarded to the resolver service.
   */
  headers?: HeadersInit;
}

/**
 * Package-specific error type for resolver URL validation, resolver response
 * validation, and helper-level method lookup / key conversion failures.
 */
export class DidWebsResolverError extends Error {
  /**
   * Narrow resolver error code suitable for mapping into DID resolution
   * metadata.
   */
  readonly code: ResolverErrorCode;
  /**
   * HTTP status when the underlying failure came from a resolver response.
   */
  readonly status?: number;

  /**
   * Create one typed resolver error.
   */
  constructor(message: string, options: { code?: ResolverErrorCode; status?: number } = {}) {
    super(message);
    this.name = "DidWebsResolverError";
    this.code = options.code ?? "invalidDid";
    this.status = options.status;
  }
}

/**
 * Return the `did-resolver` method registry for `did:webs`.
 *
 * Consumers pass this into `new Resolver({ ...getResolver(...) })` so the
 * broader JS DID tooling can resolve `did:webs` identifiers without depending
 * on an app-local adapter.
 */
export function getResolver(options: DidWebsResolverOptions): ResolverRegistry {
  return {
    webs: createDidWebsMethodResolver(options)
  };
}

/**
 * Canonicalize one `did:webs` identifier.
 *
 * The only repair performed here is the local-stack malformed host/port form:
 * `did:webs:<host>:<port>:...` becomes `did:webs:<host>%3A<port>:...`.
 * Existing canonical DIDs and non-`did:webs` values are returned unchanged.
 */
export function canonicalizeDidWebs(did: string): string {
  if (!did.startsWith("did:webs:")) {
    return did;
  }
  if (did.toLowerCase().includes("%3a")) {
    return did;
  }

  const [body, query = ""] = did.split("?", 2);
  const segments = body.slice("did:webs:".length).split(":");
  if (segments.length < 3 || !/^\d+$/.test(segments[1] ?? "")) {
    return did;
  }

  const [domain, port, ...remainder] = segments;
  const normalized = `did:webs:${domain}%3A${port}:${remainder.join(":")}`;
  return query ? `${normalized}?${query}` : normalized;
}

/**
 * Canonicalize the DID portion of one DID URL while preserving its fragment.
 *
 * This keeps resolver-meaningful DID URL structure intact while still repairing
 * the common malformed host/port form in the DID itself.
 */
export function canonicalizeDidWebsDidUrl(value: string): string {
  const [did, fragment = ""] = value.split("#", 2);
  const normalized = canonicalizeDidWebs(did);
  return fragment ? `${normalized}#${fragment}` : normalized;
}

/**
 * Build the resolver-service URL for one `did:webs` DID URL.
 *
 * Fragments are stripped because resolution happens against the DID document,
 * not a document fragment. Query parameters are preserved because DID URL
 * qualifiers such as `?versionId=...` are part of the resolver contract.
 */
export function buildResolutionUrl(resolverUrl: string, didUrl: string): string {
  const parsed = parseCanonicalDidUrl(didUrl);
  return `${resolverUrl.replace(/\/+$/, "")}/${parsed.didUrl}`;
}

/**
 * Validate and normalize one resolver HTTP response into a DID resolution
 * result.
 *
 * This function is intentionally strict because it forms the trust boundary
 * between the package and the external `did-webs-resolver` HTTP service.
 * Callers receive either a usable `DIDResolutionResult` or a typed
 * `DidWebsResolverError`. The returned DID document is also normalized into the
 * narrow compatibility shape that common JS JWT consumers such as `did-jwt-vc`
 * reliably expect.
 */
export function parseDidWebsResolution(
  requestedDidUrl: string,
  body: unknown,
  status: number
): DIDResolutionResult {
  const parsed = parseCanonicalDidUrl(requestedDidUrl);
  if (status >= 400) {
    throw new DidWebsResolverError(
      `resolver returned HTTP ${status} while resolving did:webs DID ${parsed.didUrl}`,
      {
        code: status === 404 ? "notFound" : "invalidDid",
        status
      }
    );
  }

  if (!isRecord(body)) {
    throw new DidWebsResolverError(`resolver response was not a JSON object for ${parsed.didUrl}`);
  }

  const envelope = body as ResolverEnvelope;
  const didDocument = isRecord(envelope.didDocument) ? envelope.didDocument : body;
  if (!isRecord(didDocument) || !Array.isArray(didDocument.verificationMethod)) {
    throw new DidWebsResolverError(
      `resolver response did not contain a usable didDocument for ${parsed.didUrl}`
    );
  }

  const resolvedDid = typeof didDocument.id === "string" ? canonicalizeDidWebs(didDocument.id) : "";
  if (!resolvedDid || resolvedDid !== parsed.did) {
    throw new DidWebsResolverError(
      `resolved didDocument.id did not match requested did:webs DID ${parsed.did}`
    );
  }

  normalizeDidDocumentForCommonJwtConsumers(didDocument);

  return {
    didDocument: didDocument as DIDResolutionResult["didDocument"],
    didDocumentMetadata: isRecord(envelope.didDocumentMetadata) ? envelope.didDocumentMetadata : {},
    didResolutionMetadata: isRecord(envelope.didResolutionMetadata) ? envelope.didResolutionMetadata : {}
  };
}

/**
 * Find the verification method referenced by a JWT `kid`-style value.
 *
 * Matching accepts the three forms maintainers actually encounter across the
 * stack:
 * - the full method id,
 * - a fragment-only reference such as `#key-1`,
 * - a plain fragment suffix such as `key-1`.
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

  throw new DidWebsResolverError(`verification method ${kid} not found in resolved DID document`);
}

/**
 * Return a public JWK view for one resolved verification method.
 *
 * This helper intentionally does not mutate the resolved DID document. If the
 * method already exposes `publicKeyJwk`, it is returned unchanged. If the
 * method is Multikey-only, this helper derives an equivalent Ed25519 OKP JWK
 * view for local JWK-oriented consumers such as the Node crypto APIs.
 */
export function publicJwkFromMethod(method: Record<string, unknown>): JsonWebKey {
  if (isRecord(method.publicKeyJwk)) {
    return method.publicKeyJwk as JsonWebKey;
  }

  if (typeof method.publicKeyMultibase !== "string") {
    throw new DidWebsResolverError(
      "resolved verification method did not expose publicKeyJwk or publicKeyMultibase"
    );
  }

  const raw = decodeBase58btcMultibase(method.publicKeyMultibase);
  if (!startsWith(raw, ED25519_MULTIKEY_PREFIX)) {
    throw new DidWebsResolverError("only Ed25519 publicKeyMultibase methods are supported");
  }

  const key = raw.slice(ED25519_MULTIKEY_PREFIX.length);
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: base64UrlEncode(key)
  };
}

/**
 * Create the `did-resolver` method implementation for `did:webs`.
 *
 * The resolver returns standard `DIDResolutionResult` objects on success and
 * converts transport or validation failures into DID-resolution metadata on
 * failure rather than throwing out through `did-resolver`.
 */
function createDidWebsMethodResolver(options: DidWebsResolverOptions): DIDResolver {
  const fetchFn = options.fetch ?? fetch;

  return async (_did, parsed) => {
    try {
      const resolutionUrl = buildResolutionUrl(options.resolverUrl, parsed.didUrl);
      const response = await fetchFn(resolutionUrl, {
        headers: {
          Accept: "application/json",
          ...options.headers
        }
      });
      const body = await response.json();
      return parseDidWebsResolution(parsed.didUrl, body, response.status);
    } catch (error) {
      const resolverError = normalizeResolverError(error, parsed.didUrl);
      return {
        didDocument: null,
        didDocumentMetadata: {},
        didResolutionMetadata: {
          error: resolverError.code,
          message: resolverError.message,
          ...(typeof resolverError.status === "number" ? { status: resolverError.status } : {})
        }
      };
    }
  };
}

/**
 * Normalize one resolved DID document into the subset of shape common JS JWT
 * verifier stacks reliably consume.
 *
 * This is intentionally narrow. The package does not perform generic app
 * policy work; it only smooths the specific interop seams repeatedly required
 * when live `did:webs` output is fed into `did-jwt` / `did-jwt-vc`.
 */
function normalizeDidDocumentForCommonJwtConsumers(didDocument: Record<string, unknown>): void {
  const methods = Array.isArray(didDocument.verificationMethod) ? didDocument.verificationMethod : [];

  for (const item of methods) {
    if (!isRecord(item)) {
      continue;
    }

    // `did-jwt` is JWK-first. If a resolved method is Multikey-only and we can
    // safely derive an Ed25519 JWK view, make that view explicit. Unsupported
    // Multikey variants are left untouched so unrelated methods do not break
    // whole-document resolution.
    if (!isRecord(item.publicKeyJwk) && typeof item.publicKeyMultibase === "string") {
      try {
        item.publicKeyJwk = publicJwkFromMethod(item);
      } catch {
        // Leave unsupported key material untouched; verification will fail only
        // if a consumer actually selects that method.
      }
    }

    if (DID_JWT_EDDSA_KEY_TYPES.has(typeof item.type === "string" ? item.type : "")) {
      continue;
    }

    const jwk = isRecord(item.publicKeyJwk) ? item.publicKeyJwk : undefined;
    if (jwk?.kty === "OKP" && jwk?.crv === "Ed25519") {
      item.type = "JsonWebKey2020";
    } else if (typeof item.publicKeyMultibase === "string") {
      item.type = "Multikey";
    }
  }

  normalizeVerificationRelationship(didDocument, "assertionMethod", methods);
  normalizeVerificationRelationship(didDocument, "authentication", methods);
}

/**
 * Expand one verification relationship into embedded method objects.
 *
 * Live resolver output often uses string references such as `#key-1`, while JS
 * JWT consumers are easier to satisfy when the relationship arrays already
 * contain the referenced verification method objects.
 */
function normalizeVerificationRelationship(
  didDocument: Record<string, unknown>,
  relationship: "assertionMethod" | "authentication",
  methods: unknown[]
): void {
  const existing = Array.isArray(didDocument[relationship]) ? didDocument[relationship] : [];
  const normalized = existing
    .map((item) => typeof item === "string" ? findMethodByReference(methods, item) : item)
    .filter(isRecord);

  didDocument[relationship] = normalized.length > 0 ? normalized : methods.filter(isRecord);
}

/**
 * Find one verification method object by a string relationship reference.
 */
function findMethodByReference(methods: unknown[], reference: string): Record<string, unknown> | undefined {
  const fragment = reference.includes("#") ? reference.split("#", 2)[1] : reference.replace(/^#/, "");

  return methods.filter(isRecord).find((method) => {
    const id = typeof method.id === "string" ? method.id : "";
    return isMatchingMethodReference(id, reference, fragment);
  });
}

/**
 * Normalize arbitrary thrown values into a typed package error.
 *
 * This keeps error-to-resolution-metadata translation consistent regardless of
 * whether the failure came from fetch, JSON parsing, or local validation.
 */
function normalizeResolverError(error: unknown, didUrl: string): DidWebsResolverError {
  if (error instanceof DidWebsResolverError) {
    return error;
  }

  const message = error instanceof Error ? error.message : String(error);
  return new DidWebsResolverError(
    `did:webs resolution failed for ${stripFragment(canonicalizeDidWebsDidUrl(didUrl))}: ${message}`,
    { code: "internalError" }
  );
}

/**
 * Parse one canonical `did:webs` DID URL after stripping its fragment.
 *
 * This helper centralizes the package's DID URL normalization rules so request
 * building and response validation reason about the same canonical DID.
 */
function parseCanonicalDidUrl(value: string) {
  const normalized = stripFragment(canonicalizeDidWebsDidUrl(value));
  const parsed = parse(normalized);
  if (!parsed || parsed.method !== "webs") {
    throw new DidWebsResolverError(`invalid did:webs DID URL: ${value}`);
  }
  return parsed;
}

/**
 * Remove the fragment component from one DID URL.
 */
function stripFragment(value: string): string {
  return value.split("#", 1)[0] ?? value;
}

/**
 * Narrow an arbitrary JSON value to a plain object record.
 */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Match a DID document verification method against the reference forms this
 * package accepts.
 */
function isMatchingMethodReference(id: string, reference: string, fragment: string): boolean {
  return id === reference || id === `#${fragment}` || id.endsWith(`#${fragment}`);
}

/**
 * Check whether one byte sequence begins with the provided prefix.
 */
function startsWith(value: Uint8Array, prefix: Uint8Array): boolean {
  if (value.length < prefix.length) {
    return false;
  }
  return prefix.every((byte, index) => value[index] === byte);
}

/**
 * Encode raw bytes using unpadded base64url.
 */
function base64UrlEncode(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

/**
 * Decode a base58btc multibase string into raw bytes.
 *
 * This local helper exists to keep the package dependency-light. It is only
 * used for explicit Multikey-to-JWK derivation.
 */
function decodeBase58btcMultibase(value: string): Uint8Array {
  if (!value.startsWith("z")) {
    throw new DidWebsResolverError("multibase value must use base58btc encoding");
  }

  let result = 0n;
  for (const character of value.slice(1)) {
    const index = BASE58_ALPHABET.indexOf(character);
    if (index === -1) {
      throw new DidWebsResolverError("invalid base58btc character");
    }
    result = (result * 58n) + BigInt(index);
  }

  const bytes: number[] = [];
  while (result > 0n) {
    bytes.unshift(Number(result % 256n));
    result /= 256n;
  }

  for (const character of value.slice(1)) {
    if (character !== "1") {
      break;
    }
    bytes.unshift(0);
  }

  return Uint8Array.from(bytes);
}

/**
 * Base58btc alphabet used by Multibase `z...` values.
 */
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
