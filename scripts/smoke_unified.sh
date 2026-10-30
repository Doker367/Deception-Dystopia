#!/usr/bin/env bash
# Unified Dystopia + T-Pot + Elasticsearch/Kibana contract smoke.
#
# Default (offline): standard-library fixtures, mapping/filter/dedupe/secret
# checks and in-process fakes. No services, containers, VMs or network access.
#
# Lab (opt-in): validates the fail-closed gate and then runs the end-to-end
# module. It refuses to run unless the operator explicitly marks disposable
# lab destinations. It never opens SSH, sends exploits or guesses passwords.
#
# This script installs nothing and changes no firewall, network or service.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONDONTWRITEBYTECODE=1

usage() {
  cat <<'EOF'
Usage: scripts/smoke_unified.sh [--offline] [--lab [--full]]

  --offline (default)  Run contract tests with fixtures and in-process fakes.
  --lab                Run the opt-in lab scenario in preflight mode.
  --full               Lab mode plus the post-SSH event/index/Kibana/restart flow.
  --help               Show this message.

Lab mode requires:
  DYSTOPIA_LAB_CONFIRM=DISPOSABLE-LAB-ONLY
  DYSTOPIA_LAB_MARKER=/path/to/marker   (purpose=dystopia-disposable-lab,
                                         authorization_id=<exercise id>)
  DYSTOPIA_LAB_TARGETS=10.20.30.40,...  (explicit RFC1918/loopback allowlist)
  DYSTOPIA_LAB_SCENARIO=/path/scenario.json
  owner-only token files referenced by the scenario (no inline credentials)

Full mode additionally requires the operator to perform an authorized benign
SSH login and set DYSTOPIA_LAB_SSH_PERFORMED to the scenario's performed_token.
The harness itself never opens SSH.
EOF
}

MODE="offline"
FULL="0"
for argument in "$@"; do
  case "$argument" in
    --offline) MODE="offline" ;;
    --lab) MODE="lab" ;;
    --full) MODE="lab"; FULL="1" ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $argument" >&2; usage >&2; exit 2 ;;
  esac
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required (no installation is attempted)" >&2
  exit 2
fi

if [[ "$MODE" == "offline" ]]; then
  echo "== unified contract smoke (offline; no services, no network) =="
  # Defensive: an inherited lab configuration must never enable network tests
  # in offline mode.
  exec env \
    -u DYSTOPIA_LAB_E2E -u DYSTOPIA_LAB_CONFIRM -u DYSTOPIA_LAB_MARKER \
    -u DYSTOPIA_LAB_TARGETS -u DYSTOPIA_LAB_SCENARIO -u DYSTOPIA_LAB_SSH_PERFORMED \
    python3 -m unittest discover -s tests/integration_unified -p 'test_*.py' -v
fi

echo "== unified lab smoke (opt-in; disposable lab only) =="

if [[ "${DYSTOPIA_LAB_CONFIRM:-}" != "DISPOSABLE-LAB-ONLY" ]]; then
  echo "refusing: DYSTOPIA_LAB_CONFIRM must be exactly DISPOSABLE-LAB-ONLY" >&2
  exit 2
fi
for required in DYSTOPIA_LAB_MARKER DYSTOPIA_LAB_TARGETS DYSTOPIA_LAB_SCENARIO; do
  if [[ -z "${!required:-}" ]]; then
    echo "refusing: $required is required in lab mode" >&2
    exit 2
  fi
done
if [[ ! -f "$DYSTOPIA_LAB_MARKER" ]]; then
  echo "refusing: marker file does not exist: $DYSTOPIA_LAB_MARKER" >&2
  exit 2
fi
if [[ ! -f "$DYSTOPIA_LAB_SCENARIO" ]]; then
  echo "refusing: scenario file does not exist: $DYSTOPIA_LAB_SCENARIO" >&2
  exit 2
fi

if [[ "$FULL" == "1" ]]; then
  export DYSTOPIA_LAB_E2E="full"
else
  export DYSTOPIA_LAB_E2E="${DYSTOPIA_LAB_E2E:-preflight}"
fi
if [[ "$DYSTOPIA_LAB_E2E" != "preflight" && "$DYSTOPIA_LAB_E2E" != "full" ]]; then
  echo "refusing: DYSTOPIA_LAB_E2E must be preflight or full" >&2
  exit 2
fi

# Validate markers, authorization id, target allowlist, URL schemes and token
# file permissions BEFORE any test can open a connection. The summary prints no
# tokens, only the exercise id and allowed hosts.
python3 - <<'PY'
import os
import sys

sys.path.insert(0, os.path.join(os.getcwd(), "tests", "integration_unified"))
from lab_gate import LabGate, LabGateError  # noqa: E402

try:
    gate = LabGate.from_environ(os.environ)
except LabGateError as exc:
    print(f"refusing: {exc}", file=sys.stderr)
    raise SystemExit(2)
if gate is None:
    print("refusing: lab mode is not enabled", file=sys.stderr)
    raise SystemExit(2)
summary = gate.summary()
print(
    "gate ok: mode={mode} authorization_id={authorization_id} "
    "targets={targets} device={device_id} index={index_pattern}".format(**summary)
)
PY

if [[ "$DYSTOPIA_LAB_E2E" == "full" && -z "${DYSTOPIA_LAB_SSH_PERFORMED:-}" ]]; then
  echo "note: full flow will skip until the operator confirms the benign SSH login" >&2
fi

exec python3 -m unittest discover -s tests/integration_unified -p 'test_lab_e2e_optin.py' -v
