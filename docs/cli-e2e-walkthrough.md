# CLI End-to-End Walkthrough

This is the manual runbook for the Isomer CLI boundary:

- project TEL-backed credential status
- issue a W3C VC-JWT twin from accepted local KERI credential state
- verify the VC-JWT and ACDC/VC pair through the verifier service
- observe revocation failure after status reprojection
- optionally send the same artifacts to Node and Go sidecars

The live pytest flow still owns the full KERI issuance chain. This walkthrough
starts at the Isomer boundary after you have a source ACDC and a live KERI
habitat signer.

## 0. Bootstrap KERI/ACDC State

From the repo root:

```bash
UV_CACHE_DIR=$PWD/.uv-cache uv sync

RESET=1 \
START_WITNESS_DEMO=1 \
START_VLEI_SERVER=1 \
DWS_ARTIFACT_HOSTPORT=127.0.0.1:7677 \
./scripts/demo/bootstrap-vrd-acdc-kli.sh

source .tmp/kli-vrd-acdc/out/env.sh
```

The bootstrap exports:

- `SOURCE_ACDC`: the generated VRD ACDC JSON
- `VRD_SAID`: the generated VRD ACDC SAID used by isomer commands
- `SIGNER_NAME`, `SIGNER_ALIAS`, `SIGNER_PASSCODE`: the live QVI signer
- `QVI_REGISTRY`: the QVI registry name used when revoking the VRD ACDC
- `ISSUER_DID`: the QVI `did:webs` DID to use as the W3C issuer
- `DWS_ARTIFACT_DIR`: static did:webs files generated from the QVI KERI state

Start the static `did:webs` artifact host and resolver in another terminal:

```bash
./scripts/demo/serve-didwebs-static.sh .tmp/kli-vrd-acdc/out/env.sh
```

Keep that terminal running through verification.

## 1. Set Isomer Environment

```bash
export ROOT="$PWD"
export STATUS_PORT=8787
export VERIFIER_PORT=8788
export DASHBOARD_PORT=8791
export STATUS_BASE="http://127.0.0.1:${STATUS_PORT}"
export VERIFIER_BASE="http://127.0.0.1:${VERIFIER_PORT}"
export DASHBOARD_BASE="http://127.0.0.1:${DASHBOARD_PORT}"
export WEBHOOK_URL="${DASHBOARD_BASE}/webhooks/presentations"
export RESOLVER_BASE="http://127.0.0.1:7678/1.0/identifiers"
export STATUS_STORE="$ROOT/.tmp/status-store.json"
export OP_ROOT="$ROOT/.tmp/verifier-ops"
export OUT_DIR="$ROOT/.tmp/cli-e2e"
mkdir -p "$OUT_DIR"
```

If you skipped the bootstrap, set the exported signer, DID, source ACDC, and
registry values yourself. The issuer DID must resolve to the key controlled by
the opened habitat signer.

## 2. Start Services

Status service:

```bash
isomer status serve \
  --host 127.0.0.1 \
  --port "$STATUS_PORT" \
  --store "$STATUS_STORE" \
  --base-url "$STATUS_BASE"
```

Verifier service:

```bash
isomer verifier serve \
  --host 127.0.0.1 \
  --port "$VERIFIER_PORT" \
  --resolver "$RESOLVER_BASE" \
  --operation-root "$OP_ROOT" \
  --webhook-url "$WEBHOOK_URL" \
  --verifier-id isomer-python
```

Dashboard:

```bash
npm --prefix apps/isomer-dashboard install
ISOMER_DASHBOARD_HOST=127.0.0.1 \
ISOMER_DASHBOARD_PORT="$DASHBOARD_PORT" \
npm --prefix apps/isomer-dashboard run serve
```

Health checks:

```bash
curl -fsS "$STATUS_BASE/healthz"
curl -fsS "$VERIFIER_BASE/healthz"
curl -fsS "$DASHBOARD_BASE/healthz"
```

## 3. Project Status

```bash
isomer status project \
  --name "$SIGNER_NAME" \
  --registry "$QVI_REGISTRY" \
  --credential "$SOURCE_ACDC" \
  --status-base-url "$STATUS_BASE" \
  --store "$STATUS_STORE"
```

The command publishes a W3C-facing status projection. TEL remains
authoritative.

## 4. Issue VC-JWT

```bash
isomer vc issue \
  --name "$SIGNER_NAME" \
  --alias "$SIGNER_ALIAS" \
  --passcode "$SIGNER_PASSCODE" \
  --credential "$SOURCE_ACDC" \
  --issuer-did "$ISSUER_DID" \
  --status-base-url "$STATUS_BASE" \
  --out "$OUT_DIR/vrd-vc.json" \
  --token-out "$OUT_DIR/vrd-vc.jwt"
```

Useful inspection:

```bash
jq '.issuer, .id, .credentialSubject.id, .credentialStatus' "$OUT_DIR/vrd-vc.json"
```

## 5. Verify

VC-JWT:

```bash
isomer vc verify \
  --server "$VERIFIER_BASE" \
  --token "$(cat "$OUT_DIR/vrd-vc.jwt")"
```

ACDC/W3C pair:

```bash
isomer vc verify-pair \
  --server "$VERIFIER_BASE" \
  --token "$(cat "$OUT_DIR/vrd-vc.jwt")" \
  --credential "$SOURCE_ACDC"
```

Successful commands exit `0`. Failures exit non-zero and print a compact error.
Detailed operation state belongs in the service and integration harness, not in
normal CLI output.

## 6. Revoke And Reproject

Revoke the source credential through KERIpy, then reproject status:

```bash
kli vc revoke \
  --name "$SIGNER_NAME" \
  --alias "$SIGNER_ALIAS" \
  --passcode "$SIGNER_PASSCODE" \
  --registry-name "$QVI_REGISTRY" \
  --said "$VRD_SAID"

isomer status project \
  --name "$SIGNER_NAME" \
  --registry "$QVI_REGISTRY" \
  --credential "$SOURCE_ACDC" \
  --status-base-url "$STATUS_BASE" \
  --store "$STATUS_STORE"
```

The same `isomer vc verify` command should now fail because the projected
status is inactive.

## 7. Optional VP Flow

Issue a VP-JWT from the VC-JWT:

```bash
isomer vp issue \
  --name "$SIGNER_NAME" \
  --alias "$SIGNER_ALIAS" \
  --passcode "$SIGNER_PASSCODE" \
  --holder-did "$ISSUER_DID" \
  --credential-token "$OUT_DIR/vrd-vc.jwt" \
  --out "$OUT_DIR/vrd-vp.json" \
  --token-out "$OUT_DIR/vrd-vp.jwt"
```

Verify:

```bash
isomer vp verify \
  --server "$VERIFIER_BASE" \
  --token "$(cat "$OUT_DIR/vrd-vp.jwt")"
```

## 8. External Verifier Acceptance

Node:

```bash
make external-node-sync
make external-node-check
```

Go:

```bash
make external-go-check
```

Live e2e through both sidecars:

```bash
ISOMER_EXTERNAL_VERIFIERS=node,go \
./.venv/bin/python -m pytest \
  tests/integration/test_single_sig_vrd_isomer.py \
  -q --tb=short
```

## Full Live Test

Use this when debugging the complete KERI issuance chain:

```bash
PYTHONUNBUFFERED=1 \
UV_CACHE_DIR=$PWD/.uv-cache \
./.venv/bin/python -m pytest -s -vv \
  -o log_cli=true \
  --log-cli-level=INFO \
  tests/integration/test_single_sig_vrd_isomer.py
```
