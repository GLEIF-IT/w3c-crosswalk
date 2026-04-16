import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import jsonld from "jsonld";
import { decodeBase58btcMultibase } from "./base58.js";
import { cloneJson, isRecord } from "./jwt.js";
import { publicJwkFromMethod } from "./did-resolver.js";
import type { LocalContextLoader } from "./local-contexts.js";

const DATA_INTEGRITY_PROOF = "DataIntegrityProof";
const EDDSA_RDFC_2022 = "eddsa-rdfc-2022";

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
  if (methodId && proofMethod && methodId !== proofMethod && methodId !== `#${fragment}` && !methodId.endsWith(`#${fragment}`)) {
    throw new Error("resolved verification method does not match proof verificationMethod");
  }

  const signature = decodeBase58btcMultibase(proof.proofValue);
  const verifyData = await createVerifyData(document, proof, contexts);
  const key = createPublicKey({ key: publicJwkFromMethod(method), format: "jwk" });
  return verifySignature(null, verifyData, key, signature);
}

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

function sha256(data: Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}
