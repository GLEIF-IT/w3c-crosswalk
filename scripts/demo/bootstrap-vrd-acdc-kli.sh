#!/usr/bin/env bash
set -euo pipefail

# Bootstrap the KERI/ACDC side of the crosswalk demo using KERIpy KLI commands.
#
# This script intentionally stops at the crosswalk boundary:
# - GEDA, delegated QVI, and LE identifiers exist.
# - GEDA/QVI/LE registries exist.
# - QVI, LE, VRD Auth, and VRD credentials have been issued, granted, mailbox
#   synced, and admitted.
# - The final VRD ACDC is exported as JSON for `crosswalk issue vc`.
#
# By default this uses KERIpy's normal KLI home resolution. On macOS that means
# ~/.keri; on Linux that means /usr/local/var/keri. Set KERI_HOME only when you
# explicitly want a non-default HOME for an isolated/manual run.
#
# Set START_WITNESS_DEMO=1 and/or START_VLEI_SERVER=1 when you want this script
# to start the bootstrap-only helper services itself.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KLI="${KLI:-$ROOT/.venv/bin/kli}"
PYTHON_BIN="${PYTHON_BIN:-$ROOT/.venv/bin/python}"

WORK_DIR="${WORK_DIR:-$ROOT/.tmp/kli-vrd-acdc}"
CONFIG_ROOT="$WORK_DIR/config"
TMP_DIR="$WORK_DIR/tmp"
OUT_DIR="$WORK_DIR/out"
LOG_DIR="$WORK_DIR/logs"

HOST="${HOST:-127.0.0.1}"
WITNESS_AID="${WITNESS_AID:-BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha}"
WITNESS_OOBI_WAN="${WITNESS_OOBI_WAN:-http://127.0.0.1:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller?name=Wan&tag=witness}"
WITNESS_OOBI_WIL="${WITNESS_OOBI_WIL:-http://127.0.0.1:5643/oobi/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM/controller?name=Wil&tag=witness}"
WITNESS_OOBI_WES="${WITNESS_OOBI_WES:-http://127.0.0.1:5644/oobi/BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX/controller?name=Wes&tag=witness}"

VLEI_SCHEMA_BASE="${VLEI_SCHEMA_BASE:-http://127.0.0.1:7723}"
DWS_ARTIFACT_HOSTPORT="${DWS_ARTIFACT_HOSTPORT:-127.0.0.1:7677}"
DWS_DID_PATH="${DWS_DID_PATH:-dws}"
DWS_BIN="${DWS_BIN:-$ROOT/.venv/bin/dws}"
DWS_ARTIFACT_DIR="${DWS_ARTIFACT_DIR:-$OUT_DIR/did-webs-static}"
DWS_ARTIFACT_OUTPUT_DIR="$DWS_ARTIFACT_DIR/${DWS_DID_PATH//:/\/}"

START_WITNESS_DEMO="${START_WITNESS_DEMO:-0}"
START_VLEI_SERVER="${START_VLEI_SERVER:-0}"
STOP_BOOTSTRAP_SERVICES="${STOP_BOOTSTRAP_SERVICES:-1}"
VLEI_SERVER_BIN="${VLEI_SERVER_BIN:-$ROOT/.venv/bin/vLEI-server}"

GEDA_NAME="${GEDA_NAME:-crosswalk-geda}"
GEDA_ALIAS="${GEDA_ALIAS:-geda}"
GEDA_SALT="${GEDA_SALT:-0AA2-S2YS4KqvlSzO7faIEpH}"
GEDA_PASSCODE="${GEDA_PASSCODE:-18b2c88fd050851c45c67}"

QVI_NAME="${QVI_NAME:-crosswalk-qvi}"
QVI_ALIAS="${QVI_ALIAS:-qvi}"
QVI_PROXY_ALIAS="${QVI_PROXY_ALIAS:-proxy}"
QVI_SALT="${QVI_SALT:-0ACgCmChLaw_qsLycbqBoxDK}"
QVI_PASSCODE="${QVI_PASSCODE:-e6b3402845de8185abe94}"

LE_NAME="${LE_NAME:-crosswalk-legal-entity}"
LE_ALIAS="${LE_ALIAS:-legal-entity}"
LE_SALT="${LE_SALT:-0AB90ainJghoJa8BzFmGiEWa}"
LE_PASSCODE="${LE_PASSCODE:-tcc6Yj4JM8MfTDs1IiidP}"

QVI_SCHEMA="${QVI_SCHEMA:-EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao}"
LE_SCHEMA="${LE_SCHEMA:-ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY}"
VRD_AUTH_SCHEMA="${VRD_AUTH_SCHEMA:-EFiYsVADHXcn1BZirDRH301Rm12301povihg5UMIYkfc}"
VRD_SCHEMA="${VRD_SCHEMA:-EAyv2DLocYxJlPrWAfYBuHWDpjCStdQBzNLg0-3qQ-KP}"

QVI_REGISTRY="${QVI_REGISTRY:-qvi-registry}"
GEDA_REGISTRY="${GEDA_REGISTRY:-geda-registry}"
LE_REGISTRY="${LE_REGISTRY:-le-registry}"

LEGAL_NAME="${LEGAL_NAME:-Example Legal Entity LLC}"
LEGAL_ADDRESS="${LEGAL_ADDRESS:-1 Market St, San Francisco, CA, US}"
LEI="${LEI:-254900OPPU84GM83MG36}"

if [[ "${RESET:-0}" == "1" ]]; then
  rm -rf "$WORK_DIR"
fi

mkdir -p "$CONFIG_ROOT/keri/cf" "$TMP_DIR" "$OUT_DIR"
mkdir -p "$LOG_DIR" "$DWS_ARTIFACT_OUTPUT_DIR"

if [[ ! -x "$KLI" ]]; then
  echo "KLI not found or not executable: $KLI" >&2
  exit 1
fi

if [[ ! -x "$DWS_BIN" ]]; then
  echo "dws CLI not found or not executable: $DWS_BIN" >&2
  exit 1
fi

kli() {
  if [[ -n "${KERI_HOME:-}" ]]; then
    HOME="$KERI_HOME" "$KLI" "$@"
  else
    "$KLI" "$@"
  fi
}

dws() {
  if [[ -n "${KERI_HOME:-}" ]]; then
    HOME="$KERI_HOME" "$DWS_BIN" "$@"
  else
    "$DWS_BIN" "$@"
  fi
}

say() {
  printf '\n==> %s\n' "$*" >&2
}

SERVICE_PIDS=()

cleanup_services() {
  if [[ "$STOP_BOOTSTRAP_SERVICES" != "1" ]]; then
    return
  fi
  for pid in "${SERVICE_PIDS[@]:-}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
}

trap cleanup_services EXIT

wait_for_port() {
  local port="$1" label="$2"
  python - "$port" "$label" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
label = sys.argv[2]
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        try:
            sock.connect(("127.0.0.1", port))
            raise SystemExit(0)
        except OSError:
            time.sleep(0.25)
raise SystemExit(f"timed out waiting for {label} on 127.0.0.1:{port}")
PY
}

start_bootstrap_services() {
  if [[ "$START_WITNESS_DEMO" == "1" ]]; then
    say "starting local witness helper"
    "$PYTHON_BIN" -u "$ROOT/tests/integration/_services/witness_server.py" \
      --config-dir "$CONFIG_ROOT" \
      --wan-port 5642 \
      --wil-port 5643 \
      --wes-port 5644 > "$LOG_DIR/witness-demo.log" 2>&1 &
    SERVICE_PIDS+=("$!")
    wait_for_port 5642 "witness helper wan"
    wait_for_port 5643 "witness helper wil"
    wait_for_port 5644 "witness helper wes"
  fi

  if [[ "$START_VLEI_SERVER" == "1" ]]; then
    say "starting vLEI-server"
    "$VLEI_SERVER_BIN" \
      --schema-dir "$ROOT/tests/integration/_assets/vlei/schema/acdc" \
      --cred-dir "$ROOT/tests/integration/_assets/vlei/samples/acdc" \
      --oobi-dir "$ROOT/tests/integration/_assets/vlei/samples/oobis" \
      --http 7723 > "$LOG_DIR/vlei-server.log" 2>&1 &
    SERVICE_PIDS+=("$!")
    wait_for_port 7723 "vLEI-server"
  fi
}

write_common_config() {
  mkdir -p "$CONFIG_ROOT/keri/cf/main"
  python - "$ROOT/tests/integration/_assets/keri/cf/main" "$CONFIG_ROOT/keri/cf/main" <<'PY'
import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
target = Path(sys.argv[2])
ports = {"wan": 5642, "wil": 5643, "wes": 5644}
for name, port in ports.items():
    body = json.loads((source / f"{name}.json").read_text(encoding="utf-8"))
    body[name]["curls"] = [
        curl if not curl.startswith("http://") else f"http://127.0.0.1:{port}/"
        for curl in body[name]["curls"]
    ]
    (target / f"{name}.json").write_text(json.dumps(body), encoding="utf-8")
PY

  cat > "$CONFIG_ROOT/keri/cf/common-habery-config.json" <<JSON
{
  "dt": "2026-03-31T00:00:00+00:00",
  "iurls": [
    "$WITNESS_OOBI_WAN",
    "$WITNESS_OOBI_WIL",
    "$WITNESS_OOBI_WES"
  ],
  "durls": [
    "$VLEI_SCHEMA_BASE/oobi/$QVI_SCHEMA",
    "$VLEI_SCHEMA_BASE/oobi/$LE_SCHEMA",
    "$VLEI_SCHEMA_BASE/oobi/$VRD_AUTH_SCHEMA",
    "$VLEI_SCHEMA_BASE/oobi/$VRD_SCHEMA"
  ]
}
JSON
}

init_actor() {
  local name="$1" salt="$2" passcode="$3"
  if [[ -n "${KERI_HOME:-}" && -d "$KERI_HOME/.keri/ks/$name" ]]; then
    say "keystore exists for $name"
    return
  fi

  say "kli init $name"
  kli init \
    --name "$name" \
    --salt "$salt" \
    --passcode "$passcode" \
    --config-dir "$CONFIG_ROOT" \
    --config-file common-habery-config
}

incept_single_sig() {
  local name="$1" alias="$2" passcode="$3"
  say "kli incept $alias"
  kli incept \
    --name "$name" \
    --alias "$alias" \
    --passcode "$passcode" \
    --transferable \
    --wits "$WITNESS_AID" \
    --toad 1 \
    --icount 1 \
    --isith 1 \
    --ncount 1 \
    --nsith 1
}

aid_for() {
  local name="$1" alias="$2" passcode="$3"
  kli aid --name "$name" --alias "$alias" --passcode "$passcode" | tail -n 1 | tr -d '[:space:]'
}

witness_oobi_for() {
  local name="$1" alias="$2" passcode="$3"
  kli oobi generate --name "$name" --alias "$alias" --passcode "$passcode" --role witness \
    | grep -Eo 'https?://[^[:space:]]+' \
    | tail -n 1
}

resolve_oobi() {
  local name="$1" passcode="$2" alias="$3" oobi="$4"
  say "resolve $alias into $name"
  kli oobi resolve --name "$name" --passcode "$passcode" --oobi-alias "$alias" --oobi "$oobi"
}

resolve_pairwise_oobis() {
  local geda_oobi="$1" qvi_oobi="$2" le_oobi="$3"
  resolve_oobi "$GEDA_NAME" "$GEDA_PASSCODE" "$QVI_ALIAS" "$qvi_oobi"
  resolve_oobi "$GEDA_NAME" "$GEDA_PASSCODE" "$LE_ALIAS" "$le_oobi"
  resolve_oobi "$QVI_NAME" "$QVI_PASSCODE" "$GEDA_ALIAS" "$geda_oobi"
  resolve_oobi "$QVI_NAME" "$QVI_PASSCODE" "$LE_ALIAS" "$le_oobi"
  resolve_oobi "$LE_NAME" "$LE_PASSCODE" "$GEDA_ALIAS" "$geda_oobi"
  resolve_oobi "$LE_NAME" "$LE_PASSCODE" "$QVI_ALIAS" "$qvi_oobi"
}

incept_delegated_qvi() {
  local geda_aid="$1"

  say "kli incept delegated $QVI_ALIAS"
  kli incept \
    --name "$QVI_NAME" \
    --alias "$QVI_ALIAS" \
    --passcode "$QVI_PASSCODE" \
    --proxy "$QVI_PROXY_ALIAS" \
    --delpre "$geda_aid" \
    --transferable \
    --wits "$WITNESS_AID" \
    --toad 1 \
    --icount 1 \
    --isith 1 \
    --ncount 1 \
    --nsith 1 &
  local delegate_pid=$!

  say "kli delegate confirm $GEDA_ALIAS -> $QVI_ALIAS"
  kli delegate confirm \
    --name "$GEDA_NAME" \
    --alias "$GEDA_ALIAS" \
    --passcode "$GEDA_PASSCODE" \
    --interact \
    --auto

  wait "$delegate_pid"
  kli query --name "$QVI_NAME" --alias "$QVI_ALIAS" --passcode "$QVI_PASSCODE" --prefix "$geda_aid"
}

new_nonce() {
  kli nonce | tail -n 1 | tr -d '[:space:]'
}

create_registry() {
  local name="$1" alias="$2" passcode="$3" registry="$4" usage="$5"
  say "kli vc registry incept $registry"
  kli vc registry incept \
    --name "$name" \
    --alias "$alias" \
    --passcode "$passcode" \
    --registry-name "$registry" \
    --nonce "$(new_nonce)" \
    --usage "$usage"
}

saidify_file() {
  local path="$1"
  kli saidify --file "$path" --label d >/dev/null
}

render_json_template() {
  local template="$1" output="$2" key="$3" value="$4"
  python - "$template" "$output" "$key" "$value" <<'PY'
from pathlib import Path
import sys

template, output, key, value = sys.argv[1:]
text = Path(template).read_text(encoding="utf-8").replace(key, value)
Path(output).write_text(text, encoding="utf-8")
PY
  saidify_file "$output"
}

write_json() {
  local output="$1"
  shift
  python - "$output" "$@" <<'PY'
import json
import sys
from pathlib import Path

output = Path(sys.argv[1])
pairs = sys.argv[2:]
body = {pairs[i]: pairs[i + 1] for i in range(0, len(pairs), 2)}
output.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
PY
}

now_iso() {
  python - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).isoformat(timespec="microseconds"))
PY
}

credential_said() {
  local name="$1" alias="$2" passcode="$3" schema="$4" direction="$5"
  local args=(vc list --name "$name" --alias "$alias" --passcode "$passcode" --schema "$schema" --said)
  if [[ "$direction" == "issued" ]]; then
    args+=(--issued)
  fi
  kli "${args[@]}" | grep -E '^[A-Za-z0-9_-]{44}$' | tail -n 1
}

issue_credential() {
  local name="$1" alias="$2" passcode="$3" registry="$4" schema="$5" recipient="$6" data="$7" rules="$8" edges="${9:-}"
  local time
  time="$(now_iso)"

  say "kli vc create schema=$schema issuer=$alias"
  if [[ -n "$edges" ]]; then
    kli vc create \
      --name "$name" \
      --alias "$alias" \
      --passcode "$passcode" \
      --registry-name "$registry" \
      --schema "$schema" \
      --recipient "$recipient" \
      --data "@$data" \
      --rules "@$rules" \
      --edges "@$edges" \
      --time "$time" >&2
  else
    kli vc create \
      --name "$name" \
      --alias "$alias" \
      --passcode "$passcode" \
      --registry-name "$registry" \
      --schema "$schema" \
      --recipient "$recipient" \
      --data "@$data" \
      --rules "@$rules" \
      --time "$time" >&2
  fi

  credential_said "$name" "$alias" "$passcode" "$schema" issued
}

grant_credential() {
  local name="$1" alias="$2" passcode="$3" recipient="$4" said="$5"
  local output grant_said
  say "kli ipex grant $said"
  output="$(kli ipex grant \
    --name "$name" \
    --alias "$alias" \
    --passcode "$passcode" \
    --recipient "$recipient" \
    --said "$said" \
    --message "" \
    --time "$(now_iso)")"
  printf '%s\n' "$output"
  grant_said="$(printf '%s\n' "$output" | awk '/Sending message / { print $3 }' | tail -n 1)"
  if [[ -z "$grant_said" ]]; then
    echo "Unable to parse grant exchange SAID from kli ipex grant output" >&2
    exit 1
  fi
  printf '%s\n' "$grant_said"
}

wait_for_grant_exchange() {
  local name="$1" alias="$2" passcode="$3" grant_said="$4"
  local grants

  say "poll IPEX grant exchange $grant_said"
  for attempt in $(seq 1 30); do
    grants="$(kli ipex list \
      --name "$name" \
      --alias "$alias" \
      --passcode "$passcode" \
      --type grant \
      --poll \
      --said 2>/dev/null || true)"
    if printf '%s\n' "$grants" | grep -Fxq "$grant_said"; then
      return
    fi
    printf 'grant exchange not ready yet for %s, retry %s/30\n' "$grant_said" "$attempt" >&2
    sleep 2
  done

  echo "Unable to find grant exchange $grant_said in $alias IPEX notifications" >&2
  return 1
}

admit_grant() {
  local name="$1" alias="$2" passcode="$3" grant_said="$4" schema="$5"
  local output

  say "mailbox sync and kli ipex admit $grant_said"
  wait_for_grant_exchange "$name" "$alias" "$passcode" "$grant_said"
  for attempt in $(seq 1 12); do
    if output="$(kli ipex admit \
      --name "$name" \
      --alias "$alias" \
      --passcode "$passcode" \
      --said "$grant_said" \
      --message "" \
      --time "$(now_iso)" 2>&1)"; then
      printf '%s\n' "$output"
      credential_said "$name" "$alias" "$passcode" "$schema" received
      return
    fi
    printf 'admit not ready yet for %s, retry %s/12\n' "$grant_said" "$attempt" >&2
    sleep 2
  done

  echo "Unable to admit grant $grant_said" >&2
  return 1
}

export_credential() {
  local name="$1" alias="$2" passcode="$3" said="$4" json_output="$5" cesr_output="$6"
  say "kli vc export $said"
  kli vc export --name "$name" --alias "$alias" --passcode "$passcode" --said "$said" > "$cesr_output"
  python - "$cesr_output" "$json_output" <<'PY'
import json
import sys
from pathlib import Path

cesr = Path(sys.argv[1])
output = Path(sys.argv[2])
stream = cesr.read_text(encoding="utf-8")
credential, _ = json.JSONDecoder().raw_decode(stream)
output.write_text(json.dumps(credential, indent=2) + "\n", encoding="utf-8")
PY
}

did_webs_for() {
  local aid="$1"
  local encoded_hostport="${DWS_ARTIFACT_HOSTPORT/:/%3A}"
  printf 'did:webs:%s:%s:%s\n' "$encoded_hostport" "$DWS_DID_PATH" "$aid"
}

write_common_config
start_bootstrap_services

say "runtime"
printf 'WORK_DIR=%s\nKERI_HOME=%s\nOUT_DIR=%s\n' "$WORK_DIR" "${KERI_HOME:-<KERIpy default>}" "$OUT_DIR"

init_actor "$GEDA_NAME" "$GEDA_SALT" "$GEDA_PASSCODE"
init_actor "$QVI_NAME" "$QVI_SALT" "$QVI_PASSCODE"
init_actor "$LE_NAME" "$LE_SALT" "$LE_PASSCODE"

incept_single_sig "$GEDA_NAME" "$GEDA_ALIAS" "$GEDA_PASSCODE"
GEDA_AID="$(aid_for "$GEDA_NAME" "$GEDA_ALIAS" "$GEDA_PASSCODE")"

GEDA_OOBI="$(witness_oobi_for "$GEDA_NAME" "$GEDA_ALIAS" "$GEDA_PASSCODE")"
resolve_oobi "$QVI_NAME" "$QVI_PASSCODE" "$GEDA_ALIAS" "$GEDA_OOBI"

incept_single_sig "$QVI_NAME" "$QVI_PROXY_ALIAS" "$QVI_PASSCODE"
incept_delegated_qvi "$GEDA_AID"
QVI_AID="$(aid_for "$QVI_NAME" "$QVI_ALIAS" "$QVI_PASSCODE")"

incept_single_sig "$LE_NAME" "$LE_ALIAS" "$LE_PASSCODE"
LE_AID="$(aid_for "$LE_NAME" "$LE_ALIAS" "$LE_PASSCODE")"

QVI_OOBI="$(witness_oobi_for "$QVI_NAME" "$QVI_ALIAS" "$QVI_PASSCODE")"
LE_OOBI="$(witness_oobi_for "$LE_NAME" "$LE_ALIAS" "$LE_PASSCODE")"
resolve_pairwise_oobis "$GEDA_OOBI" "$QVI_OOBI" "$LE_OOBI"

create_registry "$GEDA_NAME" "$GEDA_ALIAS" "$GEDA_PASSCODE" "$GEDA_REGISTRY" "QVI Credential Registry for GEDA"
create_registry "$QVI_NAME" "$QVI_ALIAS" "$QVI_PASSCODE" "$QVI_REGISTRY" "LE and VRD Credential Registry for QVI"
create_registry "$LE_NAME" "$LE_ALIAS" "$LE_PASSCODE" "$LE_REGISTRY" "VRD Authorization Registry for LE"

QVI_RULES="$TMP_DIR/qvi-rules.json"
VRD_AUTH_RULES="$TMP_DIR/vrd-auth-rules.json"
VRD_RULES="$TMP_DIR/vrd-rules.json"
cp "$ROOT/tests/integration/assets/qvi-rules.json" "$QVI_RULES"
cp "$ROOT/tests/integration/assets/vrd-auth-rules.json" "$VRD_AUTH_RULES"
cp "$ROOT/tests/integration/assets/vrd-rules.json" "$VRD_RULES"
saidify_file "$QVI_RULES"
saidify_file "$VRD_AUTH_RULES"
saidify_file "$VRD_RULES"

QVI_DATA="$TMP_DIR/qvi-data.json"
write_json "$QVI_DATA" LEI "$LEI"
QVI_CREDENTIAL_SAID="$(issue_credential "$GEDA_NAME" "$GEDA_ALIAS" "$GEDA_PASSCODE" "$GEDA_REGISTRY" "$QVI_SCHEMA" "$QVI_AID" "$QVI_DATA" "$QVI_RULES")"
QVI_GRANT_SAID="$(grant_credential "$GEDA_NAME" "$GEDA_ALIAS" "$GEDA_PASSCODE" "$QVI_AID" "$QVI_CREDENTIAL_SAID" | tail -n 1)"
QVI_ADMITTED_SAID="$(admit_grant "$QVI_NAME" "$QVI_ALIAS" "$QVI_PASSCODE" "$QVI_GRANT_SAID" "$QVI_SCHEMA" | tail -n 1)"

LE_DATA="$TMP_DIR/le-data.json"
LE_EDGE="$TMP_DIR/le-edge.json"
write_json "$LE_DATA" LEI "$LEI"
render_json_template "$ROOT/tests/integration/assets/le-edge-template.json" "$LE_EDGE" "__QVI_CREDENTIAL_SAID__" "$QVI_CREDENTIAL_SAID"
LE_CREDENTIAL_SAID="$(issue_credential "$QVI_NAME" "$QVI_ALIAS" "$QVI_PASSCODE" "$QVI_REGISTRY" "$LE_SCHEMA" "$LE_AID" "$LE_DATA" "$QVI_RULES" "$LE_EDGE")"
LE_GRANT_SAID="$(grant_credential "$QVI_NAME" "$QVI_ALIAS" "$QVI_PASSCODE" "$LE_AID" "$LE_CREDENTIAL_SAID" | tail -n 1)"
LE_ADMITTED_SAID="$(admit_grant "$LE_NAME" "$LE_ALIAS" "$LE_PASSCODE" "$LE_GRANT_SAID" "$LE_SCHEMA" | tail -n 1)"

LE_DID="$(did_webs_for "$LE_AID")"
QVI_DID="$(did_webs_for "$QVI_AID")"

VRD_AUTH_DATA="$TMP_DIR/vrd-auth-data.json"
VRD_AUTH_EDGE="$TMP_DIR/vrd-auth-edge.json"
write_json "$VRD_AUTH_DATA" \
  i "$QVI_AID" \
  AID "$LE_AID" \
  DID "$LE_DID" \
  HeadquartersAddress "$LEGAL_ADDRESS" \
  LegalName "$LEGAL_NAME"
render_json_template "$ROOT/tests/integration/assets/vrd-auth-edge-template.json" "$VRD_AUTH_EDGE" "__LE_CREDENTIAL_SAID__" "$LE_CREDENTIAL_SAID"
VRD_AUTH_SAID="$(issue_credential "$LE_NAME" "$LE_ALIAS" "$LE_PASSCODE" "$LE_REGISTRY" "$VRD_AUTH_SCHEMA" "$QVI_AID" "$VRD_AUTH_DATA" "$VRD_AUTH_RULES" "$VRD_AUTH_EDGE")"
VRD_AUTH_GRANT_SAID="$(grant_credential "$LE_NAME" "$LE_ALIAS" "$LE_PASSCODE" "$QVI_AID" "$VRD_AUTH_SAID" | tail -n 1)"
VRD_AUTH_ADMITTED_SAID="$(admit_grant "$QVI_NAME" "$QVI_ALIAS" "$QVI_PASSCODE" "$VRD_AUTH_GRANT_SAID" "$VRD_AUTH_SCHEMA" | tail -n 1)"

VRD_DATA="$TMP_DIR/vrd-data.json"
VRD_EDGE="$TMP_DIR/vrd-edge.json"
write_json "$VRD_DATA" \
  i "$LE_AID" \
  AID "$LE_AID" \
  DID "$QVI_DID" \
  HeadquartersAddress "$LEGAL_ADDRESS" \
  LegalName "$LEGAL_NAME"
render_json_template "$ROOT/tests/integration/assets/vrd-edge-template.json" "$VRD_EDGE" "__LE_CREDENTIAL_SAID__" "$LE_CREDENTIAL_SAID"
VRD_SAID="$(issue_credential "$QVI_NAME" "$QVI_ALIAS" "$QVI_PASSCODE" "$QVI_REGISTRY" "$VRD_SCHEMA" "$LE_AID" "$VRD_DATA" "$VRD_RULES" "$VRD_EDGE")"
VRD_GRANT_SAID="$(grant_credential "$QVI_NAME" "$QVI_ALIAS" "$QVI_PASSCODE" "$LE_AID" "$VRD_SAID" | tail -n 1)"
VRD_ADMITTED_SAID="$(admit_grant "$LE_NAME" "$LE_ALIAS" "$LE_PASSCODE" "$VRD_GRANT_SAID" "$VRD_SCHEMA" | tail -n 1)"

export_credential "$LE_NAME" "$LE_ALIAS" "$LE_PASSCODE" "$VRD_SAID" "$OUT_DIR/vrd-acdc.json" "$OUT_DIR/vrd-acdc.cesr"
export_credential "$QVI_NAME" "$QVI_ALIAS" "$QVI_PASSCODE" "$VRD_AUTH_SAID" "$OUT_DIR/vrd-auth-acdc.json" "$OUT_DIR/vrd-auth-acdc.cesr"

say "generating did:webs static artifacts"
dws did webs generate \
  --name "$QVI_NAME" \
  --passcode "$QVI_PASSCODE" \
  --output-dir "$DWS_ARTIFACT_OUTPUT_DIR" \
  --did "$QVI_DID"

cat > "$OUT_DIR/env.sh" <<EOF
export SIGNER_NAME="$QVI_NAME"
export SIGNER_ALIAS="$QVI_ALIAS"
export SIGNER_PASSCODE="$QVI_PASSCODE"
export ISSUER_DID="$QVI_DID"
export SOURCE_ACDC="$OUT_DIR/vrd-acdc.json"
export VRD_AUTH_ACDC="$OUT_DIR/vrd-auth-acdc.json"
export DWS_ARTIFACT_DIR="$DWS_ARTIFACT_DIR"
export GEDA_REGISTRY="$GEDA_REGISTRY"
export QVI_REGISTRY="$QVI_REGISTRY"
export LE_REGISTRY="$LE_REGISTRY"
export VRD_SAID="$VRD_SAID"
export VRD_AUTH_SAID="$VRD_AUTH_SAID"
export QVI_AID="$QVI_AID"
export LE_AID="$LE_AID"
export GEDA_AID="$GEDA_AID"
EOF

if [[ -n "${KERI_HOME:-}" ]]; then
  printf 'export HOME="%s"\n' "$KERI_HOME" >> "$OUT_DIR/env.sh"
fi

cat > "$OUT_DIR/summary.json" <<EOF
{
  "gedaAid": "$GEDA_AID",
  "qviAid": "$QVI_AID",
  "leAid": "$LE_AID",
  "issuerDid": "$QVI_DID",
  "gedaRegistry": "$GEDA_REGISTRY",
  "qviRegistry": "$QVI_REGISTRY",
  "leRegistry": "$LE_REGISTRY",
  "qviCredentialSaid": "$QVI_CREDENTIAL_SAID",
  "qviAdmittedSaid": "$QVI_ADMITTED_SAID",
  "leCredentialSaid": "$LE_CREDENTIAL_SAID",
  "leAdmittedSaid": "$LE_ADMITTED_SAID",
  "vrdAuthSaid": "$VRD_AUTH_SAID",
  "vrdAuthAdmittedSaid": "$VRD_AUTH_ADMITTED_SAID",
  "vrdSaid": "$VRD_SAID",
  "vrdAdmittedSaid": "$VRD_ADMITTED_SAID",
  "sourceAcdc": "$OUT_DIR/vrd-acdc.json",
  "didWebsArtifacts": "$DWS_ARTIFACT_DIR",
  "env": "$OUT_DIR/env.sh"
}
EOF

say "bootstrap complete"
cat "$OUT_DIR/summary.json"
printf '\nNext:\n  source "%s"\n  use "$VRD_SAID" and "$ISSUER_DID" in docs/cli-e2e-walkthrough.md\n' "$OUT_DIR/env.sh"
