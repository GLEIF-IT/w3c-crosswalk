import { DATA_INTEGRITY_CONTEXT, ISOMER_CONTEXT, VC_CONTEXT } from "./constants.js";
import type { JsonObject } from "./types.js";

export const VC_V1_CONTEXT = {
  "@context": {
    "@version": 1.1,
    "id": "@id",
    "type": "@type",
    "cred": "https://www.w3.org/2018/credentials#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "VerifiableCredential": "cred:VerifiableCredential",
    "VerifiablePresentation": "cred:VerifiablePresentation",
    "credentialSubject": { "@id": "cred:credentialSubject" },
    "credentialSchema": { "@id": "cred:credentialSchema" },
    "credentialStatus": { "@id": "cred:credentialStatus" },
    "termsOfUse": { "@id": "cred:termsOfUse" },
    "issuer": { "@id": "cred:issuer", "@type": "@id" },
    "holder": { "@id": "cred:holder", "@type": "@id" },
    "issuanceDate": { "@id": "cred:issuanceDate", "@type": "xsd:dateTime" },
    "expirationDate": { "@id": "cred:expirationDate", "@type": "xsd:dateTime" },
    "verifiableCredential": { "@id": "cred:verifiableCredential" }
  }
} satisfies JsonObject;

export const SECURITY_DATA_INTEGRITY_V2_CONTEXT = {
  "@context": {
    "@version": 1.1,
    "sec": "https://w3id.org/security#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "DataIntegrityProof": "sec:DataIntegrityProof",
    "assertionMethod": "sec:assertionMethod",
    "created": { "@id": "http://purl.org/dc/terms/created", "@type": "xsd:dateTime" },
    "cryptosuite": { "@id": "sec:cryptosuite", "@type": "xsd:string" },
    "proof": { "@id": "sec:proof" },
    "proofPurpose": { "@id": "sec:proofPurpose", "@type": "@vocab" },
    "proofValue": { "@id": "sec:proofValue", "@type": "sec:multibase" },
    "verificationMethod": { "@id": "sec:verificationMethod", "@type": "@id" }
  }
} satisfies JsonObject;

export const ISOMER_V1_CONTEXT = {
  "@context": {
    "@version": 1.1,
    "iso": "https://www.gleif.org/isomer/v1#",
    "schemaorg": "https://schema.org/",
    "vlei": "https://www.gleif.org/vlei/v1#",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "KERIIsomerCredential": "iso:KERIIsomerCredential",
    "QualifiedvLEIIssuerCredential": "vlei:QualifiedvLEIIssuerCredential",
    "VRDAuthorizationCredential": "vlei:VRDAuthorizationCredential",
    "VRDCredential": "vlei:VRDCredential",
    "LegalEntityvLEICredential": "vlei:LegalEntityvLEICredential",
    "KERICredentialStatus": "iso:KERICredentialStatus",
    "PostalAddress": "schemaorg:PostalAddress",
    "JsonSchemaValidator2018": "https://www.w3.org/2018/credentials#JsonSchemaValidator2018",
    "AID": { "@id": "vlei:AID", "@type": "xsd:string" },
    "address": { "@id": "schemaorg:address" },
    "addressCountry": { "@id": "schemaorg:addressCountry", "@type": "xsd:string" },
    "addressLocality": { "@id": "schemaorg:addressLocality", "@type": "xsd:string" },
    "addressRegion": { "@id": "schemaorg:addressRegion", "@type": "xsd:string" },
    "authorizedQviAid": { "@id": "iso:authorizedQviAid", "@type": "xsd:string" },
    "isomer": {
      "@id": "iso:metadata",
      "@context": {
        "profile": { "@id": "iso:profile", "@type": "xsd:string" },
        "sourceAuthorizedQviAid": { "@id": "iso:sourceAuthorizedQviAid", "@type": "xsd:string" },
        "sourceCredentialSaid": { "@id": "iso:sourceCredentialSaid", "@type": "xsd:string" },
        "sourceCredentialType": { "@id": "iso:sourceCredentialType", "@type": "xsd:string" },
        "sourceIssuerAid": { "@id": "iso:sourceIssuerAid", "@type": "xsd:string" },
        "sourceLegalEntityCredentialSaid": { "@id": "iso:sourceLegalEntityCredentialSaid", "@type": "xsd:string" },
        "sourceLegalEntityCredentialSchema": { "@id": "iso:sourceLegalEntityCredentialSchema", "@type": "xsd:string" },
        "sourceRegistry": { "@id": "iso:sourceRegistry", "@type": "xsd:string" },
        "sourceSchemaSaid": { "@id": "iso:sourceSchemaSaid", "@type": "xsd:string" },
        "version": { "@id": "iso:version", "@type": "xsd:string" }
      }
    },
    "legalEntityCredential": {
      "@id": "vlei:legalEntityCredential",
      "@context": {
        "schema": { "@id": "vlei:credentialSchema", "@type": "xsd:string" }
      }
    },
    "legalName": { "@id": "schemaorg:legalName", "@type": "xsd:string" },
    "postalCode": { "@id": "schemaorg:postalCode", "@type": "xsd:string" },
    "revocation": "iso:revocation",
    "schema": { "@id": "vlei:credentialSchema", "@type": "xsd:string" },
    "statusPurpose": { "@id": "iso:statusPurpose", "@type": "@vocab" },
    "statusRegistryId": { "@id": "iso:statusRegistryId", "@type": "xsd:string" },
    "streetAddress": { "@id": "schemaorg:streetAddress", "@type": "xsd:string" },
    "text": { "@id": "schemaorg:text", "@type": "xsd:string" },
    "vLEIIssuanceDisclaimer": "vlei:IssuanceDisclaimer",
    "vLEIPrivacyDisclaimer": "vlei:PrivacyDisclaimer",
    "vLEIUsageDisclaimer": "vlei:UsageDisclaimer"
  }
} satisfies JsonObject;

const CONTEXTS = new Map<string, JsonObject>([
  [VC_CONTEXT, VC_V1_CONTEXT],
  [DATA_INTEGRITY_CONTEXT, SECURITY_DATA_INTEGRITY_V2_CONTEXT],
  [ISOMER_CONTEXT, ISOMER_V1_CONTEXT]
]);

export function documentLoader(url: string): { contextUrl: null; documentUrl: string; document: JsonObject } {
  const document = CONTEXTS.get(url);
  if (document === undefined) {
    throw new Error(`no local JSON-LD context registered for ${url}`);
  }
  return { contextUrl: null, documentUrl: url, document };
}
