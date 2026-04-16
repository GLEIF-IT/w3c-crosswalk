# Isomer W3C/OpenID Interop Notes

This directory holds developer-facing interop artifacts for the current Isomer
profile. They are not a full OpenID4VCI/OpenID4VP server implementation.

The current target is VCDM 1.1 `jwt_vc_json-ld`:

- the VC-JWT payload uses `iss`, `sub`, `jti`, `iat`, `nbf`, and `vc`
- the embedded `vc` is JSON-LD with a KERI-backed `DataIntegrityProof`
- the VP-JWT payload uses `iss`, `jti`, `iat`, optional `aud`/`nonce`, and `vp`
- status is dereferenceable through Isomer and backed by KERI TEL state

Use the JSON files here as fixtures when wiring OpenID metadata, wallet
configuration, or an external W3C verifier harness.
