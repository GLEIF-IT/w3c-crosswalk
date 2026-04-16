# isomer-node

Minimal TypeScript verifier sidecar for external W3C acceptance.

This app verifies Isomer VCDM 1.1 VC-JWT and VP-JWT artifacts without importing
the Python verifier. It uses the local sibling `../did-jwt-vc` clone for the
JWT VC/VP envelope, strict local JSON-LD contexts from `src/vc_isomer`, and
did:webs/status HTTP endpoints from the live Isomer stack.

Setup:

```bash
make external-node-sync
make external-node-check
```

Run manually:

```bash
npm --prefix apps/isomer-node run serve -- \
  --host 127.0.0.1 \
  --port 8787 \
  --resolver-url http://127.0.0.1:7678/1.0/identifiers \
  --resource-root "$PWD"
```

API:

- `GET /healthz`
- `POST /verify/vc` with `{ "token": "<vc-jwt>" }`
- `POST /verify/vp` with `{ "token": "<vp-jwt>", "audience"?: "...", "nonce"?: "..." }`

The response shape mirrors Isomer verifier results: `ok`, `kind`, `errors`,
`warnings`, `checks`, `payload`, and optional `nested`.
