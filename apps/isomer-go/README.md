# isomer-go

Minimal Go verifier sidecar for external W3C acceptance.

This app verifies the same VC-JWT and VP-JWT artifacts as `apps/isomer-node`,
but uses the local sibling `../vc-go` clone as the independent Go W3C stack.
The module uses:

```go
replace github.com/trustbloc/vc-go => ../../../vc-go
```

Setup and check:

```bash
make external-go-check
```

Run manually:

```bash
cd apps/isomer-go
go run ./cmd/isomer-go \
  --host 127.0.0.1 \
  --port 8788 \
  --resolver-url http://127.0.0.1:7678/1.0/identifiers \
  --resource-root ../..
```

API:

- `GET /healthz`
- `POST /verify/vc` with `{ "token": "<vc-jwt>" }`
- `POST /verify/vp` with `{ "token": "<vp-jwt>", "audience"?: "...", "nonce"?: "..." }`

This sidecar deliberately omits Isomer pair verification. TEL state and
ACDC/W3C equivalence remain Python Isomer verifier responsibilities.

VP-JWT verification is intentionally split: the sidecar validates the VP JOSE
signature and JWT claims directly, parses the VP with `vc-go/verifiable`, and
then verifies each nested VC-JWT through the same VC path. VP JSON-LD checks are
disabled in this pass because the current local `vc-go` stack is not the source
of truth for Isomer's VP Data Integrity model.
