# signify-w3c

Edge-owned W3C artifact helpers for Signify wallets.

This package assembles and signs the W3C artifacts used by the Isomer VRD
workflow:

- projected W3C VC documents from source ACDC payloads;
- `eddsa-rdfc-2022` Data Integrity proofs;
- compact VC-JWT envelopes;
- compact VP-JWT envelopes;
- KERIA route helpers for submitting edge-built VC-JWT and VP-JWT artifacts.

KERIA validates and forwards these artifacts. It does not stage signing inputs
or assemble VC-JWT/VP-JWT token material.
