"""Stable constants for the live isomer integration harness."""

# Canonical schema SAIDs exercised by the single-sig live workflow.
QVI_SCHEMA_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
LE_SCHEMA_SAID = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"
VRD_AUTH_SCHEMA_SAID = "EFiYsVADHXcn1BZirDRH301Rm12301povihg5UMIYkfc"
VRD_SCHEMA_SAID = "EAyv2DLocYxJlPrWAfYBuHWDpjCStdQBzNLg0-3qQ-KP"

# Mapping from local aliases to the schema OOBI SAIDs served by the vLEI helper
# service.
SCHEMA_OOBI_SAIDS = {
    "qvi": QVI_SCHEMA_SAID,
    "legal-entity": LE_SCHEMA_SAID,
    "vrd-auth": VRD_AUTH_SCHEMA_SAID,
    "vrd": VRD_SCHEMA_SAID,
}

# Fixed witness identifiers expected by the local witness-demo topology.
WITNESS_AIDS = [
    "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha",
    "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM",
    "BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX",
]

# Canonical witness aliases used in configs, URLs, and logs.
WITNESS_NAMES = ("wan", "wil", "wes")
