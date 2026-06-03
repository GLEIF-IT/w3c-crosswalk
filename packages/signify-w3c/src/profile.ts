import {
  DATA_INTEGRITY_CONTEXT,
  ISOMER_CONTEXT,
  ISOMER_PROFILE,
  ISOMER_VERSION,
  ISOMER_VRD_SCHEMA_ID,
  LE_SCHEMA,
  STATUS_TYPE,
  SUPPORTED_SCHEMA_TYPES,
  VC_CONTEXT,
  VRD_AUTH_SCHEMA,
  VRD_SCHEMA
} from "./constants.js";
import { canonicalizeDidWebs, requiredRecord, saidUrn } from "./common.js";
import type { JsonObject } from "./types.js";

export function schemaType(acdc: JsonObject): string {
  const schema = acdc.s;
  if (typeof schema !== "string" || !(schema in SUPPORTED_SCHEMA_TYPES)) {
    throw new Error(`unsupported schema SAID: ${String(schema)}`);
  }
  return SUPPORTED_SCHEMA_TYPES[schema as keyof typeof SUPPORTED_SCHEMA_TYPES];
}

export function transposeAcdcToW3cVc(
  acdc: JsonObject,
  {
    issuerDid,
    statusBaseUrl
  }: {
    issuerDid: string;
    statusBaseUrl: string;
  }
): JsonObject {
  const attributes = requiredRecord(acdc.a, "attributes");
  const rules = requiredRecord(acdc.r ?? {}, "rules");
  const credentialType = schemaType(acdc);

  return {
    "@context": [VC_CONTEXT, DATA_INTEGRITY_CONTEXT, ISOMER_CONTEXT],
    type: ["VerifiableCredential", credentialType, "KERIIsomerCredential"],
    id: saidUrn(stringField(acdc, "d")),
    issuer: canonicalizeDidWebs(issuerDid),
    issuanceDate: stringField(attributes, "dt"),
    credentialSubject: buildSubject(acdc),
    credentialSchema: {
      id: ISOMER_VRD_SCHEMA_ID,
      type: "JsonSchemaValidator2018"
    },
    credentialStatus: buildStatusReference(acdc, statusBaseUrl),
    termsOfUse: buildTermsOfUse(rules),
    isomer: buildIsomerMetadata(acdc)
  };
}

export function expectedCredentialType(acdc: JsonObject): string {
  const schema = acdc.s;
  if (schema === VRD_AUTH_SCHEMA) {
    return "VRDAuthorizationCredential";
  }
  if (schema === VRD_SCHEMA) {
    return "VRDCredential";
  }
  throw new Error(`unsupported schema SAID: ${String(schema)}`);
}

function buildSubject(acdc: JsonObject): JsonObject {
  const attributes = requiredRecord(acdc.a, "attributes");
  const edges = requiredRecord(acdc.e ?? {}, "edges");
  const legalEntityEdge = recordField(edges, "le");
  const credentialType = schemaType(acdc);
  const subject: JsonObject = {
    id: stringField(attributes, "DID"),
    AID: stringField(attributes, "AID"),
    legalName: stringField(attributes, "LegalName"),
    address: parseAddress(stringField(attributes, "HeadquartersAddress")),
    legalEntityCredential: {
      id: saidUrn(stringField(legalEntityEdge, "n")),
      type: "LegalEntityvLEICredential",
      schema: stringField(legalEntityEdge, "s") || LE_SCHEMA
    }
  };
  if (credentialType === "VRDAuthorizationCredential") {
    subject.authorizedQviAid = stringField(attributes, "i");
  }
  return subject;
}

function buildIsomerMetadata(acdc: JsonObject): JsonObject {
  const attributes = requiredRecord(acdc.a, "attributes");
  const edges = requiredRecord(acdc.e ?? {}, "edges");
  const legalEntityEdge = recordField(edges, "le");
  const metadata: JsonObject = {
    profile: ISOMER_PROFILE,
    version: ISOMER_VERSION,
    sourceCredentialSaid: stringField(acdc, "d"),
    sourceSchemaSaid: stringField(acdc, "s"),
    sourceIssuerAid: stringField(acdc, "i"),
    sourceRegistry: stringField(acdc, "ri"),
    sourceCredentialType: schemaType(acdc),
    sourceLegalEntityCredentialSaid: stringField(legalEntityEdge, "n"),
    sourceLegalEntityCredentialSchema: stringField(legalEntityEdge, "s") || LE_SCHEMA
  };
  if (schemaType(acdc) === "VRDAuthorizationCredential") {
    metadata.sourceAuthorizedQviAid = stringField(attributes, "i");
  }
  return metadata;
}

function buildStatusReference(acdc: JsonObject, statusBaseUrl: string): JsonObject {
  return {
    id: statusUrl(statusBaseUrl, stringField(acdc, "d")),
    type: STATUS_TYPE,
    statusPurpose: "revocation",
    statusRegistryId: stringField(acdc, "ri")
  };
}

export function statusUrl(statusBaseUrl: string, credentialSaid: string): string {
  return `${statusBaseUrl.replace(/\/+$/g, "")}/status/${credentialSaid}`;
}

function buildTermsOfUse(rules: JsonObject): JsonObject[] {
  return [
    { type: "vLEIUsageDisclaimer", text: stringField(recordField(rules, "usageDisclaimer"), "l") },
    { type: "vLEIIssuanceDisclaimer", text: stringField(recordField(rules, "issuanceDisclaimer"), "l") },
    { type: "vLEIPrivacyDisclaimer", text: stringField(recordField(rules, "privacyDisclaimer"), "l") }
  ];
}

function parseAddress(addressString: string): JsonObject {
  const parts = addressString.split(",").map(part => part.trim());
  const address: JsonObject = {
    type: "PostalAddress",
    streetAddress: "",
    addressLocality: "",
    addressCountry: ""
  };
  if (parts.length >= 1) {
    address.streetAddress = parts[0] ?? "";
  }
  if (parts.length >= 2 && parts[1]) {
    address.streetAddress = address.streetAddress ? `${address.streetAddress}, ${parts[1]}` : parts[1];
  }
  if (parts.length >= 3) {
    address.addressLocality = parts[2] ?? "";
  }
  if (parts.length >= 4) {
    const regionPostal = (parts[3] ?? "").split(/\s+/).filter(Boolean);
    if (regionPostal[0]) {
      address.addressRegion = regionPostal[0];
    }
    if (regionPostal[1]) {
      address.postalCode = regionPostal[1];
    }
  }
  if (parts.length >= 5) {
    address.addressCountry = parts[4] ?? "";
  }
  return address;
}

function stringField(record: JsonObject, field: string): string {
  const value = record[field];
  return typeof value === "string" ? value : "";
}

function recordField(record: JsonObject, field: string): JsonObject {
  const value = record[field];
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as JsonObject
    : {};
}
