# isomer-go

Minimal Go verifier sidecar for external W3C acceptance.

This app verifies the same VC-JWT and VP-JWT artifacts as `apps/isomer-node`,
using a pinned non-local `vc-go` module replacement as the independent Go W3C
stack.

For shared verifier semantics, see `../../docs/verifier-contract.md`.

## Scope

Owns:

- VC/VP parsing through `vc-go`
- JOSE EdDSA signature verification against `did:webs` key state
- embedded VC `DataIntegrityProof` verification
- projected status fetch/check
- optional dashboard webhook emission

Does not own:

- Isomer ACDC/W3C pair verification
- TEL-aware verification
- issuer, holder, or wallet workflow
- Python verifier behavior

## Dependency

The module uses a pinned non-local replacement:

```go
replace github.com/trustbloc/vc-go => github.com/kentbull/vc-go v0.0.0-20260129140819-c99b4c46239e
```

Default commands must not require a sibling `vc-go` checkout.

## Setup

```bash
make external-go-check
```

## Manual Run

```bash
cd apps/isomer-go
go run ./cmd/isomer-go \
  --host 127.0.0.1 \
  --port 8790 \
  --resolver-url http://127.0.0.1:7678/1.0/identifiers \
  --resource-root ../..
```

Optional webhook settings:

- `--webhook-url` / `ISOMER_WEBHOOK_URL`
- `--verifier-id` / `ISOMER_VERIFIER_ID`, default `isomer-go`
- `--verifier-label` / `ISOMER_VERIFIER_LABEL`

## API

- `GET /healthz`
- `POST /verify/vc` with `{ "token": "<vc-jwt>" }`
- `POST /verify/vp` with
  `{ "token": "<vp-jwt>", "audience"?: "...", "nonce"?: "..." }`

VP JSON-LD checks remain the active gap tracked in
`../../plans/isomer-go-vp-vc-go-jsonld-fix.md`.
