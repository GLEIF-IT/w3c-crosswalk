# Isomer Verifier Containers

These images package the three W3C verifier implementations behind the same
local HTTP contract plus the dashboard webhook target:

- `GET /healthz`
- `POST /verify/vc` with `{ "token": "<vc-jwt>" }`
- `GET /` on `isomer-dashboard` for the activity stream
- `POST /webhooks/presentations` on `isomer-dashboard` for successful VP events

Node and Go also keep `POST /verify/vp`. Python uses the existing Isomer
long-running operation API behind `/verify/vc`, so a successful submission
returns a 2xx operation document and the final result is available under
`/operations/{name}`.

## Build

BuildKit named contexts pull in the local sibling repositories needed by each
implementation:

```sh
make docker-verifiers-build
```

The expected workspace layout is:

```text
kentbull/
  w3c-crosswalk/
  keripy/
  did-jwt-vc/
  vc-go/
```

## Run

Start all three against a local did:webs resolver:

```sh
ISOMER_RESOLVER_URL=http://host.docker.internal:7678/1.0/identifiers \
docker compose -f docker/compose.verifiers.yml up
```

Default host ports:

- Python: `http://127.0.0.1:8788`
- Node: `http://127.0.0.1:8789`
- Go: `http://127.0.0.1:8790`
- Dashboard: `http://127.0.0.1:8791`

The compose file wires all three verifiers to:

```text
http://isomer-dashboard:8791/webhooks/presentations
```

Only successful top-level VP-JWT verification emits dashboard events.

Run one image directly:

```sh
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -e ISOMER_RESOLVER_URL=http://host.docker.internal:7678/1.0/identifiers \
  -p 8788:8788 \
  w3c-crosswalk/isomer-node:local
```

## KERIA Config Example

KERIA can expose these verifier choices through `GET /w3c/verifiers`:

```json
{
  "w3c_projection": {
    "enabled": true,
    "session_ttl_seconds": 600,
    "verifiers": [
      {
        "id": "isomer-python-local",
        "label": "Isomer Python",
        "kind": "isomer-python-vc-jwt",
        "verifyUrl": "http://127.0.0.1:8788/verify/vc"
      },
      {
        "id": "isomer-node-local",
        "label": "Isomer Node",
        "kind": "isomer-node-vc-jwt",
        "verifyUrl": "http://127.0.0.1:8789/verify/vc"
      },
      {
        "id": "isomer-go-local",
        "label": "Isomer Go",
        "kind": "isomer-go-vc-jwt",
        "verifyUrl": "http://127.0.0.1:8790/verify/vc"
      }
    ]
  }
}
```

## Build A Real VRD Projection Input

The Phase 4 projection flow needs a real vLEI chain, ending with an LE-held VRD
credential that can be projected to VC-JWT. With witnesses, KERIA, and a vLEI
schema/OOBI server running, generate that chain from SignifyPy:

```sh
cd ../signifypy
venv/bin/python scripts/setup_vrd_projection_chain.py \
  --schema-base-url http://127.0.0.1:7723 \
  --output .tmp/w3c-vrd-chain-manifest.json
```

The script prints the LE wallet alias and passcode to stderr so the LE account
can be opened in `signify-react-ts`. The manifest includes the projection tuple
KERIA acceptance tests need:

```json
{
  "projection": {
    "identifierName": "w3c-vrd-qvi-...",
    "credentialSaid": "..."
  }
}
```

Use the QVI identifier from the manifest for the W3C projection request because
the final VRD credential is issued by the QVI AID. Use the LE passcode for
manual wallet login because the LE is the credential holder.

## Checks

```sh
make docker-verifiers-smoke
make docker-verifiers-test
```
