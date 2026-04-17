/**
 * Embedded Data Integrity proof verification for Isomer VC payloads.
 *
 * The Node sidecar uses `did-jwt-vc` for JWT envelope validation, but that does
 * not prove the embedded `proof` block inside the VC payload is intact. This
 * module performs the explicit `eddsa-rdfc-2022` verification pass using local
 * JSON-LD canonicalization and a resolved verification method from `did:webs`.
 */
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import jsonld from "jsonld";
import { publicJwkFromMethod } from "webs-did-resolver";
import { decodeBase58btcMultibase } from "./base58.js";
import { cloneJson, isRecord } from "./jwt.js";
import type { LocalContextLoader } from "./local-contexts.js";

// The sidecar currently supports only the proof shape emitted by Isomer's
// Python bridge: `DataIntegrityProof` with the `eddsa-rdfc-2022` cryptosuite.
const DATA_INTEGRITY_PROOF = "DataIntegrityProof";
const EDDSA_RDFC_2022 = "eddsa-rdfc-2022";

/**
 * Verify the embedded Data Integrity proof on one VC payload.
 *
 * This checks the expected proof suite, matches the resolved verification
 * method against `proof.verificationMethod`, recreates the suite verify-data,
 * and verifies the detached signature bytes against the resolved public key.
 */
export async function verifyDataIntegrityProof(
  document: Record<string, unknown>,
  method: Record<string, unknown>,
  contexts: LocalContextLoader
): Promise<boolean> {
  const proof = document.proof;
  if (!isRecord(proof)) {
    throw new Error("credential has no Data Integrity proof");
  }
  if (proof.type !== DATA_INTEGRITY_PROOF || proof.cryptosuite !== EDDSA_RDFC_2022) {
    throw new Error("unsupported Data Integrity proof");
  }
  if (typeof proof.proofValue !== "string" || proof.proofValue.length === 0) {
    throw new Error("Data Integrity proof has no proofValue");
  }

  const methodId = typeof method.id === "string" ? method.id : "";
  const proofMethod = typeof proof.verificationMethod === "string" ? proof.verificationMethod : "";
  const fragment = proofMethod.includes("#") ? proofMethod.split("#", 2)[1] : proofMethod;
  if (!verificationMethodMatchesProof(methodId, proofMethod, fragment)) {
    throw new Error("resolved verification method does not match proof verificationMethod");
  }

  const signature = decodeBase58btcMultibase(proof.proofValue);
  const verifyData = await createVerifyData(document, proof, contexts);
  const key = createPublicKey({ key: publicJwkFromMethod(method), format: "jwk" });
  return verifySignature(null, verifyData, key, signature);
}

function verificationMethodMatchesProof(methodId: string, proofMethod: string, fragment: string): boolean {
  if (!methodId || !proofMethod) {
    return true;
  }
  const isExactReference = methodId === proofMethod;
  const isFragmentReference = methodId === `#${fragment}`;
  const isDocumentScopedReference = methodId.endsWith(`#${fragment}`);
  return isExactReference || isFragmentReference || isDocumentScopedReference;
}

/**
 * Recreate the suite-specific verify-data bytes for `eddsa-rdfc-2022`.
 *
 * The proof value itself is removed, the unsecured document and proof config
 * are canonicalized separately, and the final verify-data is the concatenation
 * of the two SHA-256 digests.
 */
export async function createVerifyData(
  document: Record<string, unknown>,
  proof: Record<string, unknown>,
  contexts: LocalContextLoader
): Promise<Uint8Array> {
  const unsecured = cloneJson(document);
  delete unsecured.proof;

  const proofConfig = cloneJson(proof);
  delete proofConfig.proofValue;
  proofConfig["@context"] = unsecured["@context"] ?? [];

  const transformedDocument = await canonicalize(unsecured, contexts);
  const canonicalProofConfig = await canonicalize(proofConfig, contexts);

  return Buffer.concat([
    sha256(Buffer.from(canonicalProofConfig, "utf8")),
    sha256(Buffer.from(transformedDocument, "utf8"))
  ]);
}

/**
 * Canonicalize one JSON-LD document using the pinned local context loader.
 */
async function canonicalize(document: Record<string, unknown>, contexts: LocalContextLoader): Promise<string> {
  const canonize = jsonld.canonize as unknown as (
    input: Record<string, unknown>,
    options: Record<string, unknown>
  ) => Promise<string>;
  return await canonize(document, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
    documentLoader: contexts.loader
  });
}

/**
 * Hash one byte sequence with SHA-256.
 */
function sha256(data: Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}
