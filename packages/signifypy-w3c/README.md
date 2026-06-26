# signifypy-w3c

Python edge-owned W3C VC-JWT and VP-JWT artifact helpers for SignifyPy
wallets.

This package mirrors the TypeScript `signify-w3c` package. It keeps W3C
projection, JWT/Data Integrity signing, and KERIA W3C workflow orchestration in
`w3c-crosswalk`, while `signifypy` remains a core Signify/KERI/ACDC client.

## Model

- Issuer edges build and sign VC-JWTs.
- Holder edges build and sign VP-JWTs.
- KERIA validates edge-provided artifacts, records workflow state, and forwards
  grants or verifier submissions.
- No staged W3C signing-request automator is used.

## Public API

```python
from signifypy_w3c import (
    W3CKeriaClient,
    issue_w3c_credential,
    present_w3c_credential,
    signer_for_identifier,
)
```
