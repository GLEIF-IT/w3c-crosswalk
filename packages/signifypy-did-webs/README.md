# signifypy-did-webs

Blocking did:webs setup helpers for SignifyPy wallets.

This package owns DID/webs state detection and setup orchestration. SignifyPy
stays a thin KERIA client; Python wallet apps call this package before W3C
issuance or presentation workflows that require published did:webs assets.

```python
from signifypy_did_webs import ensure_didwebs_setup

setup = ensure_didwebs_setup(client, "issuer")
```
