#!/usr/bin/env bash
# Build an offline wheel bundle accepted by runtime/install.py::verify_bundle.
#
# Usage: scripts/build_offline_bundle.sh <requirements.lock> [output-dir]
#
# The lock must contain only exact pins with SHA-256 hashes for every artifact.
# Only prebuilt wheels for CPython 3.12 / Linux amd64 are downloaded; sdists are
# rejected, nothing is built, and the command fails closed on any mismatch.
# The output directory receives requirements.lock, the wheels and hashes.json.
set -euo pipefail

usage() {
    echo "usage: $0 <requirements.lock> [output-dir]" >&2
    echo "  target: CPython 3.12 / Linux amd64 (manylinux_2_28)" >&2
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || [ -z "${1:-}" ]; then
    usage
    exit 2
fi

LOCK=$1
OUT=${2:-build/offline-bundle}
PYTHON=${PYTHON:-python3}
PLATFORM=manylinux_2_28_x86_64
PY_VERSION=3.12

if [ ! -f "$LOCK" ] || [ ! -r "$LOCK" ]; then
    echo "error: lock file not found or unreadable: $LOCK" >&2
    exit 1
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "error: PYTHON interpreter not found: $PYTHON" >&2
    exit 1
fi

# Validate the lock with the same syntax runtime/install.py enforces. This runs
# before any network or filesystem output so a malformed lock costs nothing.
LOCK="$LOCK" "$PYTHON" - <<'PY'
import os
import re
import sys

path = os.environ["LOCK"]
pattern = re.compile(
    r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.+!-]+"
    r"(?:\s+--hash=sha256:[a-f0-9]{64})+"
)
text = open(path, encoding="utf-8").read()
lines = text.replace("\\\n", " ").splitlines()
pins = []
for raw in lines:
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if not pattern.fullmatch(line):
        sys.exit(f"error: lock line is not an exact pin with SHA-256 hashes: {line[:80]}")
    pins.append(line)
if not pins:
    sys.exit("error: lock contains no pinned requirements")
print(f"lock validated: {len(pins)} pinned requirements")
PY

mkdir -p "$OUT"
if [ -n "$(find "$OUT" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    echo "error: output directory must be empty: $OUT" >&2
    exit 1
fi

cp "$LOCK" "$OUT/requirements.lock"

# --no-deps keeps resolution out of the download step: the lock is the closure.
# --require-hashes rejects any artifact whose SHA-256 is not in the lock.
# --only-binary=:all: prevents sdists; nothing is compiled or built.
"$PYTHON" -m pip download \
    --no-deps \
    --require-hashes \
    --only-binary=:all: \
    --no-cache-dir \
    --disable-pip-version-check \
    --python-version "$PY_VERSION" \
    --implementation cp \
    --abi cp312 \
    --platform manylinux_2_28_x86_64 \
    --platform manylinux_2_17_x86_64 \
    --platform manylinux2014_x86_64 \
    -r "$OUT/requirements.lock" \
    -d "$OUT"

# Verify the downloaded set is exactly one wheel per pinned requirement, then
# write the manifest consumed by runtime/install.py. Any extra file (sdist,
# metadata, stray wheel) or missing wheel aborts the bundle.
OUT="$OUT" "$PYTHON" - <<'PY'
import hashlib
import json
import os
import re
import sys
from pathlib import Path

out = Path(os.environ["OUT"])
lock = (out / "requirements.lock").read_text(encoding="utf-8")
lines = lock.replace("\\\n", " ").splitlines()
names = []
for raw in lines:
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    names.append(re.split(r"==", line, maxsplit=1)[0].split("[", 1)[0])

def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()

expected = {normalize(name) for name in names}
wheels = sorted(p for p in out.iterdir() if p.suffix == ".whl")
unexpected = sorted(
    p.name for p in out.iterdir()
    if p.name not in {"requirements.lock", "hashes.json"} and p.suffix != ".whl"
)
if unexpected:
    sys.exit(f"error: non-wheel artifacts are not allowed: {', '.join(unexpected)}")
if len(wheels) != len(expected):
    sys.exit(f"error: expected {len(expected)} wheels, found {len(wheels)}")

found = {}
for wheel in wheels:
    dist = normalize(wheel.name.split("-", 1)[0])
    found.setdefault(dist, []).append(wheel.name)
missing = sorted(expected - set(found))
extra = sorted(set(found) - expected)
duplicates = {k: v for k, v in found.items() if len(v) != 1}
if missing:
    sys.exit(f"error: missing wheel for: {', '.join(missing)}")
if extra:
    sys.exit(f"error: wheel not present in lock: {', '.join(extra)}")
if duplicates:
    sys.exit(f"error: multiple wheels for one requirement: {duplicates}")

manifest = {}

def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

manifest["requirements.lock"] = digest(out / "requirements.lock")
for wheel in wheels:
    manifest[wheel.name] = digest(wheel)

tmp = out / ".hashes.json.tmp"
tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
tmp.replace(out / "hashes.json")
print(f"bundle complete: {len(wheels)} wheels, manifest covers all artifacts")
PY

echo "offline bundle ready: $OUT"
