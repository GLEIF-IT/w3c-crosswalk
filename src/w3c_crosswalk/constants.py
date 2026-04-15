"""Protocol and profile constants for the crosswalk package.

The values here are intentionally centralized because they define wire-level
behavior, schema identification, and default service expectations used by both
runtime code and tests.
"""

# W3C envelope constants used when issuing or verifying VC-JWT and VP-JWT
# artifacts.
VC_CONTEXT = "https://www.w3.org/ns/credentials/v2"
VC_JWT_TYP = "vc+jwt"
VP_JWT_TYP = "vp+jwt"
EDDSA = "EdDSA"

# Crosswalk profile identity used in generated W3C credential metadata.
CROSSWALK_PROFILE = "gleif-vrd-crosswalk"
CROSSWALK_VERSION = "0.1.0"

# Canonical schema SAIDs for the credential chain currently supported by the
# Python crosswalk implementation.
QVI_SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
VRD_AUTH_SCHEMA = "EFiYsVADHXcn1BZirDRH301Rm12301povihg5UMIYkfc"
VRD_SCHEMA = "EAyv2DLocYxJlPrWAfYBuHWDpjCStdQBzNLg0-3qQ-KP"
LE_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"

# Mapping from ACDC schema SAID to the W3C credential type emitted by the
# crosswalk projection.
SUPPORTED_SCHEMA_TYPES = {
    QVI_SCHEMA: "QualifiedvLEIIssuerCredential",
    VRD_AUTH_SCHEMA: "VRDAuthorizationCredential",
    VRD_SCHEMA: "VRDCredential",
}

# Default status and resolver configuration used by the local demo stack.
STATUS_TYPE = "KERICredentialRegistryStatus"
RESOLVER_DEFAULT = "http://127.0.0.1:7678/1.0/identifiers"

# Internal-first HTTP route defaults for the local crosswalk services.
HEALTH_ROUTE = "/healthz"
STATUS_ROUTE_PREFIX = "/status"
OPERATIONS_ROUTE_PREFIX = "/operations"
VERIFY_VC_ROUTE = "/verify/vc"
VERIFY_VP_ROUTE = "/verify/vp"
VERIFY_PAIR_ROUTE = "/verify/pair"

# Long-running verifier operation type names.
VERIFY_VC_OPERATION = "verify-vc"
VERIFY_VP_OPERATION = "verify-vp"
VERIFY_PAIR_OPERATION = "verify-pair"
