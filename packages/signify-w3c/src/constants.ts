export const VC_CONTEXT = "https://www.w3.org/2018/credentials/v1";
export const DATA_INTEGRITY_CONTEXT = "https://w3id.org/security/data-integrity/v2";
export const ISOMER_CONTEXT = "https://www.gleif.org/contexts/isomer-v1.jsonld";
export const ISOMER_VRD_SCHEMA_ID = "https://www.gleif.org/schemas/isomer/v1/vrd-credential.json";

export const VC_JWT_TYP = "JWT";
export const VP_JWT_TYP = "JWT";
export const EDDSA = "EdDSA";

export const EDDSA_RDFC_2022 = "eddsa-rdfc-2022";
export const DATA_INTEGRITY_PROOF = "DataIntegrityProof";
export const ASSERTION_METHOD = "assertionMethod";

export const ISOMER_PROFILE = "gleif-vrd-isomer";
export const ISOMER_VERSION = "0.1.0";
export const DEFAULT_KERIA_W3C_PROFILE = "gleif-vrd-isomer-v1";

export const QVI_SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
export const VRD_AUTH_SCHEMA = "EFiYsVADHXcn1BZirDRH301Rm12301povihg5UMIYkfc";
export const VRD_SCHEMA = "EAyv2DLocYxJlPrWAfYBuHWDpjCStdQBzNLg0-3qQ-KP";
export const LE_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY";

export const STATUS_TYPE = "KERICredentialStatus";

export const W3C_GRANT_ROUTE = "/w3c/vc/grant";

export const SUPPORTED_SCHEMA_TYPES = {
  [QVI_SCHEMA]: "QualifiedvLEIIssuerCredential",
  [VRD_AUTH_SCHEMA]: "VRDAuthorizationCredential",
  [VRD_SCHEMA]: "VRDCredential"
} as const;
