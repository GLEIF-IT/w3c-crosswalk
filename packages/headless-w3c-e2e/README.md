# headless-w3c-e2e

Python-first executable harness for the holder-centered W3C VRD flow.

The package wraps SignifyPy/KERIA-style clients with in-memory wallet actors,
drives issuer issuance, holder import/admit, presentation transactions, and
verifier checks, then emits manifests that TypeScript, React, and local-stack
work can compare against.

Verifier acceptance is live-service only. The harness expects Python, Node, and
Go verifier base URLs, builds runtime presentation descriptors for KERIA, lets
KERIA submit the holder VP-JWT, then polls the verifier service operation that
KERIA created. CLI-style stdin commands, verifier test doubles, direct verifier
library calls, and fixture-only verifier responses are not acceptance evidence.

Signing remains an edge operation. KERIA may stage exact signing inputs and
verify submitted signatures, but wallet automation signs only policy-approved
requests with the holder or issuer edge key material.

It is not a production wallet SDK.

See `../../docs/live-service-headless-e2e.md` for the full runbook.

## CLI Shape

Typical attach-mode run:

```bash
python -m headless_w3c_e2e.cli \
  --w3c-stack attach \
  --manifest .tmp/local-stack/w3c-vrd-chain-manifest.json \
  --manifest-out .tmp/local-stack/headless-w3c-live-manifest.json
```

Supported stack modes:

- `attach`: consume already-running live services.
- `process`: start real local service processes, then seed.
- `docker`: start the portable compose stack, then seed.

The harness requires Python, Node, and Go verifier URLs. Docker mode uses host
URLs for harness polling and container DNS submission URLs for KERIA.

## Evidence

The output manifest records issuance, holder import/admit, presentation
transactions, verifier operation evidence, negative cases, and dashboard
webhook evidence when configured. Raw JWTs are redacted unless
`--unsafe-raw-tokens` is set for local debugging.
