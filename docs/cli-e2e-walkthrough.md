# CLI End-to-End Walkthrough

This guide gives a CLI-only walkthrough of the isomer-specific
interoperability flow:

- project local TEL-backed credential status
- issue a W3C VC-JWT twin from accepted local KERI credential state
- verify the VC-JWT and ACDC/VC pair through the verifier service
- observe success and revocation failure through exit codes and short errors

Verdict: this is the closest manual CLI walkthrough to the live end-to-end test,
but it is not a full replacement for that test. The live pytest flow still owns
the complete KERI issuance chain:

- GEDA inception
- delegated QVI inception
- LE inception
- registry inception
- issue -> grant -> mailbox sync -> admit

This CLI guide starts at the isomer boundary: you already have a source ACDC
and a live KERI habitat signer that matches a resolvable `did:webs` DID.

For the live stack and maintainer mental model behind this flow, see
[`integration-maintainer-guide.md`](integration-maintainer-guide.md).

## Current Mental Model

The CLI is intentionally thin. It is not trying to be a generic KERI wallet, a
full vLEI issuance orchestrator, or an operation-inspection console. Think of it
as an isomer boundary tool:

1. `isomer status project` reads the accepted source ACDC and TEL state from
   local KERIpy state, then writes the W3C-facing status projection.
2. `isomer vc issue` reads that same accepted source credential by SAID and
   signs a VC-JWT twin with a live KERI habitat signer.
3. `isomer vc verify`, `isomer vp verify`, and `isomer vc verify-pair` submit verification work to the verifier
   service, waits for completion, and returns pass/fail.
4. Revocation starts with `kli vc revoke`. W3C revocation is only a projection
   after local KERI TEL state says the source credential is revoked.

Verifier operations still exist inside the service because verification may need
network I/O, DID resolution, and status dereferencing. They are an internal
service mechanism, not the primary user interface. The CLI does not print
terminal operation documents. On success, verify commands print one compact
identifier summary and exit `0`; on failure they exit non-zero and print one
basic error message to `stderr`.

That simplicity is deliberate. If you need detailed operation payloads or
cross-service timing behavior, use the live pytest harness and the service code,
not this walkthrough.

## What You Need

- a synced local environment:

```bash
UV_CACHE_DIR=$PWD/.uv-cache uv sync
```

- a live KERI habitat signer you can open from the CLI
- a `did:webs` DID for that signer that resolves through a running resolver
- a source ACDC credential SAID accepted in local KERIpy state

For the normal local walkthrough, generate those prerequisites with the KLI
bootstrap script in this repo before starting the CLI workflow below.
The script is located at:
- `./scripts/demo/bootstrap-vrd-acdc-kli.sh`
- See the README.md at `./scripts/demo/README.md` for full bootstrap instructions.

The canonical fixture ACDC is still available when you only need a static sample:

```bash
ls fixtures/vrd-acdc.json
```

## Important Boundary

Keep in mind that the `fixtures/vrd-acdc.json` is only an example credential input. 
It is not enough by itself to make verification succeed. The  issuer DID still has 
to resolve through a live `did:webs` resolver, and the signer you open must actually
control the keys behind that DID.

If you do not already have:

- a live signer keystore
- a matching `did:webs` DID
- a working resolver endpoint

then this walkthrough will not complete successfully.

## Prerequisites: Bootstrap KERI/ACDC State

Run this prerequisite setup before starting the CLI e2e workflow in step 1. The
bootstrap script drives the KERI side with KERIpy `kli` commands:

- GEDA inception
- delegated QVI inception
- LE inception
- GEDA, QVI, and LE registry inception
- QVI, LE, VRD Auth, and VRD issue -> grant -> mailbox sync -> admit
- export of the final VRD ACDC JSON for inspection and debugging

The script assumes a compatible witness stack and a vLEI schema helper are
already running. For this repo, the easiest path is to run it from the repo root
and let the bootstrap start the same local witness helper used by the
integration harness plus `vLEI-server`:

```bash
RESET=1 \
START_WITNESS_DEMO=1 \
START_VLEI_SERVER=1 \
DWS_ARTIFACT_HOSTPORT=127.0.0.1:7677 \
./scripts/demo/bootstrap-vrd-acdc-kli.sh
```

`RESET=1` clears only the script output directory under `.tmp`; it does not
delete your normal KERIpy keystores. By default, the script uses the same KERI
home as normal KLI usage: `~/.keri` on macOS and `/usr/local/var/keri` on Linux.
Only set `KERI_HOME` if you intentionally want to override `HOME` for an
isolated run.

Then source the generated environment before starting the CLI workflow:

```bash
source .tmp/kli-vrd-acdc/out/env.sh
```

That exports the signer, issuer DID, registry, and source credential values consumed by
the commands below:

- `SOURCE_ACDC`: the generated VRD ACDC JSON
- `VRD_SAID`: the generated VRD ACDC SAID used by isomer commands
- `SIGNER_NAME`, `SIGNER_ALIAS`, `SIGNER_PASSCODE`: the live QVI signer
- `QVI_REGISTRY`: the QVI registry name used when revoking the VRD ACDC
- `ISSUER_DID`: the QVI `did:webs` DID to use as the W3C issuer
- `DWS_ARTIFACT_DIR`: static did:webs files generated from the QVI KERI state

Finally, start the did:webs static artifact host and resolver in a separate
terminal and keep it running while you work through the verifier steps:

```bash
./scripts/demo/serve-didwebs-static.sh .tmp/kli-vrd-acdc/out/env.sh
```

That script serves `DWS_ARTIFACT_DIR` on port `7677` and runs the did:webs
resolver on port `7678`, matching the default `ISSUER_DID` and `RESOLVER_BASE`
values in this walkthrough. Once the bootstrap env is sourced and the did:webs
services are running, continue with step 1.

## 1. Set Environment Variables

From the repo root:

```bash
export ROOT="$PWD"
export STATUS_PORT=8787
export VERIFIER_PORT=8788
export STATUS_BASE="http://127.0.0.1:${STATUS_PORT}"
export VERIFIER_BASE="http://127.0.0.1:${VERIFIER_PORT}"
export RESOLVER_BASE="http://127.0.0.1:7678/1.0/identifiers"
export STATUS_STORE="$ROOT/.tmp/status-store.json"
export OP_ROOT="$ROOT/.tmp/verifier-ops"
export OUT_DIR="$ROOT/.tmp/cli-e2e"
mkdir -p "$OUT_DIR"
```

If you did not run the bootstrap script, set these for your live signer and
source credential manually:

```bash
export SIGNER_NAME="qvi"
export SIGNER_ALIAS="qvi"
export SIGNER_PASSCODE='your-22-char-bran-here'
export ISSUER_DID='did:webs:127.0.0.1%3A7677:dws:YOUR_AID_HERE'
export SOURCE_ACDC="$ROOT/fixtures/vrd-acdc.json"
export VRD_SAID='your-source-acdc-said-here'
export QVI_REGISTRY='qvi-registry'
```

Use your real values. `ISSUER_DID` must resolve to the same Ed25519 key that the
opened habitat signer uses, and `VRD_SAID` must already exist in the opened
KERIpy credential/TEL state.

## 2. Start The Local Isomer Services


### Credential Status Service

Source the same env vars from the "Set Environment Variables section" first.

Start the status service in one terminal:

```bash
isomer status serve \
  --host 127.0.0.1 \
  --port "$STATUS_PORT" \
  --store "$STATUS_STORE" \
  --base-url "$STATUS_BASE"
# Alternative syntax:
#   ./.venv/bin/python -m vc_isomer.cli status serve ...
```

### W3C Verifier Service

Source the same env vars from the "Set Environment Variables section" first.

Start the verifier service in a second terminal:

```bash
isomer verifier serve \
  --host 127.0.0.1 \
  --port "$VERIFIER_PORT" \
  --resolver "$RESOLVER_BASE" \
  --operation-root "$OP_ROOT"
# Alternative syntax:
#   ./.venv/bin/python -m vc_isomer.cli verifier serve ...
```

### Health checks

Source the same env vars from the "Set Environment Variables section" first.

Health checks:

```bash
curl -fsS "${STATUS_BASE}/healthz"
curl -fsS "${VERIFIER_BASE}/healthz"
```

The default verifier command runs the API and worker together in one process.
There is also a `verifier worker serve` command for split deployments, but the
single-process `verifier serve` shape is the right default for this PoC and for
this walkthrough.

## 3. Project Status From TEL State

Make sure to source the appropriate generated environment context with:

```bash
source .tmp/kli-vrd-acdc/out/env.sh
```


Project the accepted VRD TEL state into the local status store:

```bash
SIGNER_PASS="$SIGNER_PASSCODE" \
isomer status project \
  --said "$VRD_SAID" \
  --issuer-did "$ISSUER_DID" \
  --store "$STATUS_STORE" \
  --base-url "$STATUS_BASE" \
  --name "$SIGNER_NAME" \
  --alias "$SIGNER_ALIAS" \
  --passcode-env SIGNER_PASS \
  --output "$OUT_DIR/status.json"
# Alternative syntax:
#   ./.venv/bin/python -m vc_isomer.cli status project ...
```

Inspect the projected status resource:

```bash
cat "$OUT_DIR/status.json"
```

Mental model: the KERI TEL is authoritative. This command only publishes a
W3C-facing projection of whatever local KERIpy has already accepted. The verifier
later follows the `credentialStatus.id` URL in the VC-JWT and expects this local
status service to answer.

## 4. Issue The VC-JWT Twin

Issue a W3C VC-JWT from the accepted source credential using your live habitat
signer:

```bash
SIGNER_PASS="$SIGNER_PASSCODE" \
isomer vc issue \
  --said "$VRD_SAID" \
  --issuer-did "$ISSUER_DID" \
  --status-base-url "$STATUS_BASE" \
  --store "$STATUS_STORE" \
  --name "$SIGNER_NAME" \
  --alias "$SIGNER_ALIAS" \
  --passcode-env SIGNER_PASS \
  --output "$OUT_DIR/vc.json"
# Alternative syntax:
#   ./.venv/bin/python -m vc_isomer.cli vc issue ...
```

The command writes both the full JSON artifact and a sibling raw VC-JWT token
file, then prints both paths:

```text
vc: .tmp/cli-e2e/vc.json
jwt: .tmp/cli-e2e/vc.token
```

The real point of this step is:

- the VC-JWT is signed by your live habitat signer
- `credentialStatus.id` points at your local status service
- the payload still carries isomer provenance back to the source ACDC

## 5. Run Verifier Checks

Submit and wait for plain VC verification:

```bash
isomer vc verify \
  --token "$OUT_DIR/vc.token" \
  --server "$VERIFIER_BASE" \
  --timeout 45 \
  --poll 0.25
# Alternative syntax:
#   ./.venv/bin/python -m vc_isomer.cli vc verify ...
```

Submit and wait for isomer pair verification:

```bash
SIGNER_PASS="$SIGNER_PASSCODE" \
isomer vc verify-pair \
  --said "$VRD_SAID" \
  --token "$OUT_DIR/vc.token" \
  --server "$VERIFIER_BASE" \
  --name "$SIGNER_NAME" \
  --alias "$SIGNER_ALIAS" \
  --passcode-env SIGNER_PASS \
  --timeout 45 \
  --poll 0.25
# Alternative syntax:
#   ./.venv/bin/python -m vc_isomer.cli vc verify-pair ...
```

These commands do not run verification inline inside the CLI process. They submit
work to the verifier service, wait for the operation to finish, and use the
process exit code for pass/fail. A successful command prints one compact
identifier summary, for example:

```text
verified vc+jwt:
type=VRDCredential
id=urn:said:E...
issuer=did:webs:...
```

or:

```text
verified isomer pair:
type=VRDCredential
source=E...
vc=urn:said:E...
```

A failed command prints one compact error message to `stderr`, for example:

```text
verification failed: credential is revoked
```

The verifier checks are:

- issuer DID resolution through the configured `did:webs` resolver
- JWT signature verification against the resolved verification method
- projected credential-status lookup
- isomer equivalence between the VC-JWT and source ACDC cloned from local
  KERIpy state for `vc verify-pair`

## 6. Revoke The Source ACDC And Reproject Status

Revoke the source ACDC in its issuer TEL with KERIpy first:

```bash
kli vc revoke \
  --name "$SIGNER_NAME" \
  --alias "$SIGNER_ALIAS" \
  --passcode "$SIGNER_PASSCODE" \
  --registry-name "$QVI_REGISTRY" \
  --said "$VRD_SAID"
```

Then project the accepted TEL state again:

```bash
SIGNER_PASS="$SIGNER_PASSCODE" \
isomer status project \
  --said "$VRD_SAID" \
  --issuer-did "$ISSUER_DID" \
  --store "$STATUS_STORE" \
  --base-url "$STATUS_BASE" \
  --name "$SIGNER_NAME" \
  --alias "$SIGNER_ALIAS" \
  --passcode-env SIGNER_PASS \
  --output "$OUT_DIR/revoked-status.json"
# Alternative syntax:
#   ./.venv/bin/python -m vc_isomer.cli status project ...
```

Inspect the projected status resource:

```bash
cat "$OUT_DIR/revoked-status.json"
```

You should see:

```json
{
  "status": "rev",
  "statusSaid": "E...",
  "statusSequence": 1,
  "revoked": true,
  "credSaid": "E..."
}
```

With the status service still running, dereference the same status URL that the
verifier will use:

```bash
curl -fsS "${STATUS_BASE}/status/${VRD_SAID}"
```

That response should also show `revoked: true`. If it does not, stop here: the
verifier will not observe revocation until the status service and `STATUS_STORE`
point at the same file you just updated.

Now re-run VC verification:

```bash
isomer vc verify \
  --token "$OUT_DIR/vc.token" \
  --server "$VERIFIER_BASE" \
  --timeout 45 \
  --poll 0.25
# Alternative syntax:
#   ./.venv/bin/python -m vc_isomer.cli vc verify ...
```

The expected outcome is:

- the verifier command exits non-zero
- the command prints a short verifier error to `stderr`, such as
  `verification failed: credential ${VRD_SAID} is revoked`
- the status-related verifier check fails because the credential is inactive or
  revoked

That failure is healthy. It proves the verifier is consulting the projected
status service rather than blindly trusting the JWT signature.

If you want to repeat the happy-path verification afterward, issue a fresh source
credential or rerun the bootstrap. Reprojecting cannot make a revoked TEL active
again, and that is the point: W3C status is downstream of KERI TEL state.

## 7. Optional VP Walkthrough

If you also want to issue and verify a VP-JWT:

```bash
SIGNER_PASS="$SIGNER_PASSCODE" \
isomer vp issue \
  --vc-token "$OUT_DIR/vc.token" \
  --holder-did "$ISSUER_DID" \
  --name "$SIGNER_NAME" \
  --alias "$SIGNER_ALIAS" \
  --passcode-env SIGNER_PASS \
  --output "$OUT_DIR/vp.json"
# Alternative syntax:
#   ./.venv/bin/python -m vc_isomer.cli vp issue ...
```

Extract the VP token:

```bash
python - <<'PY'
import json
from pathlib import Path
payload = json.loads(Path(".tmp/cli-e2e/vp.json").read_text())
Path(".tmp/cli-e2e/vp.token").write_text(payload["token"], encoding="utf-8")
print(payload["kind"])
PY
```

Verify it:

```bash
isomer vp verify \
  --token "$OUT_DIR/vp.token" \
  --server "$VERIFIER_BASE" \
  --timeout 45 \
  --poll 0.25
# Alternative syntax:
#   ./.venv/bin/python -m vc_isomer.cli vp verify ...
```

Successful VP verification prints:

```text
verified vp+jwt:
holder=did:webs:...
embeddedCredentials=1
```

## What This Walkthrough Proves

- the nested `isomer` CLI is wired correctly
- the local status service hosts W3C-facing status resources
- VC issuance uses a live KERI habitat signer
- verify commands expose a simple pass/fail interface
- verifier operations remain internal service machinery
- verification consults both `did:webs` resolution and status projection

## What It Does Not Prove

- the full GEDA -> QVI -> LE -> VRD issuance chain
- grant/admit mailbox timing
- delegated inception behavior
- witness orchestration

That is still the job of:

```bash
PYTHONUNBUFFERED=1 \
UV_CACHE_DIR=$PWD/.uv-cache \
./.venv/bin/python -m pytest -s -vv \
  -o log_cli=true \
  --log-cli-level=INFO \
  tests/integration/test_single_sig_vrd_isomer.py
```
