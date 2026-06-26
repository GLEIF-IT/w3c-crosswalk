import { sha256 } from "@noble/hashes/sha256";
import jsonld from "jsonld";
import {
  ASSERTION_METHOD,
  DATA_INTEGRITY_PROOF,
  EDDSA_RDFC_2022
} from "./constants.js";
import { canonicalizeDidUrl, utcTimestamp } from "./common.js";
import { cloneJson, encodeMultibaseBase58btc } from "./encoding.js";
import { documentLoader } from "./local-contexts.js";
import type { JsonObject, Signer } from "./types.js";

export function createProofConfiguration({
  verificationMethod,
  created,
  proofPurpose = ASSERTION_METHOD
}: {
  verificationMethod: string;
  created?: string;
  proofPurpose?: string;
}): JsonObject {
  return {
    type: DATA_INTEGRITY_PROOF,
    cryptosuite: EDDSA_RDFC_2022,
    created: created ?? utcTimestamp(),
    verificationMethod: canonicalizeDidUrl(verificationMethod),
    proofPurpose
  };
}

export async function createVerifyData(document: JsonObject, proofConfig: JsonObject): Promise<Uint8Array> {
  if (proofConfig.type !== DATA_INTEGRITY_PROOF || proofConfig.cryptosuite !== EDDSA_RDFC_2022) {
    throw new Error("proof configuration must be DataIntegrityProof with eddsa-rdfc-2022");
  }

  const unsecuredDocument = cloneJson(document);
  delete unsecuredDocument.proof;

  const normalizedProofConfig = cloneJson(proofConfig);
  delete normalizedProofConfig.proofValue;
  normalizedProofConfig["@context"] = unsecuredDocument["@context"] ?? [];

  const transformedDocument = await canonicalizeJsonLd(unsecuredDocument);
  const canonicalProofConfig = await canonicalizeJsonLd(normalizedProofConfig);
  const left = sha256(new TextEncoder().encode(canonicalProofConfig));
  const right = sha256(new TextEncoder().encode(transformedDocument));
  return Uint8Array.from([...left, ...right]);
}

export async function generateProof(
  document: JsonObject,
  {
    signer,
    verificationMethod,
    created
  }: {
    signer: Signer;
    verificationMethod: string;
    created?: string;
  }
): Promise<JsonObject> {
  const proof = createProofConfiguration({ verificationMethod, created });
  const signature = await signer.sign(await createVerifyData(document, proof));
  return { ...proof, proofValue: encodeMultibaseBase58btc(signature) };
}

export async function addDataIntegrityProof(
  document: JsonObject,
  {
    signer,
    verificationMethod,
    created
  }: {
    signer: Signer;
    verificationMethod: string;
    created?: string;
  }
): Promise<JsonObject> {
  const secured = cloneJson(document);
  secured.proof = await generateProof(secured, { signer, verificationMethod, created });
  return secured;
}

async function canonicalizeJsonLd(document: JsonObject): Promise<string> {
  const canonize = jsonld.canonize as unknown as (
    input: JsonObject,
    options: Record<string, unknown>
  ) => Promise<string>;
  return await canonize(document, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
    documentLoader
  });
}
