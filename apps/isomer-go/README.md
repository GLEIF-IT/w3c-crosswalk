# isomer-go

Minimal Go verifier sidecar for external W3C acceptance.

This app verifies the same VC-JWT and VP-JWT artifacts as `apps/isomer-node`,
but uses the local sibling `../vc-go` clone as the independent Go W3C stack.
The Go sidecar depends on:

- `vc-go` for VC/VP parsing and Data Integrity verification
- `did-go` for DID document parsing
- the HTTP `did-webs-resolver` service for latest-key DID resolution

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

Optional successful VC/VP webhook settings:

- `--webhook-url` / `ISOMER_WEBHOOK_URL`
- `--verifier-id` / `ISOMER_VERIFIER_ID`, default `isomer-go`
- `--verifier-label` / `ISOMER_VERIFIER_LABEL`

The sidecar emits the webhook only for successful top-level `vc+jwt` or
`vp+jwt` verification. Raw JWTs are not included in the event body.

This sidecar deliberately omits Isomer pair verification. TEL state and
ACDC/W3C equivalence remain Python Isomer verifier responsibilities.

VP-JWT verification is intentionally split: the sidecar validates the VP JOSE
signature and JWT claims directly, parses the VP with `vc-go/verifiable`, and
then verifies each nested VC-JWT through the same VC path. VP JSON-LD checks
remain disabled in this pass because the current local `vc-go` stack is not yet
the source of truth for Isomer's VP Data Integrity model.
