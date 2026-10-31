#!/usr/bin/env python3
"""Generate a deterministic CycloneDX JSON SBOM from an offline wheel bundle.

Usage: python3 scripts/generate_sbom.py <bundle-dir> <output.json> [name]

Every component is read from the wheel's own dist-info/METADATA. Hashes are
recomputed from the downloaded wheel and must match the bundle manifest.
License data is only copied from METADATA (License-Expression, License or the
license classifiers); missing data is recorded as NOASSERTION, never guessed.
"""
import hashlib
import json
import re
import sys
import uuid
import zipfile
from pathlib import Path


def sha256(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def metadata(wheel):
    with zipfile.ZipFile(wheel) as archive:
        names = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise SystemExit(f"error: expected one METADATA file in {wheel.name}")
        text = archive.read(names[0]).decode("utf-8", "replace")
    fields = {}
    classifiers = []
    for line in text.splitlines():
        if not line:
            break
        if line.startswith((" ", "\t")) or ":" not in line:
            continue
        key, value = line.split(":", 1)
        value = value.strip()
        if key == "Classifier":
            classifiers.append(value)
        else:
            fields.setdefault(key, value)
    license_value = fields.get("License-Expression") or fields.get("License")
    license_source = "License-Expression" if fields.get("License-Expression") else "License"
    if not license_value or license_value.upper() in {"UNKNOWN", "NONE"}:
        for classifier in classifiers:
            if classifier.startswith("License ::"):
                license_value = re.sub(r"^License\s*::\s*(OSI Approved\s*::\s*)?", "", classifier)
                license_source = "Classifier"
                break
    if not license_value or license_value.upper() in {"UNKNOWN", "NONE"}:
        license_value = "NOASSERTION"
        license_source = "missing"
    return fields.get("Name"), fields.get("Version"), license_value, license_source


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def main(argv):
    if len(argv) not in (3, 4):
        raise SystemExit("usage: generate_sbom.py <bundle-dir> <output.json> [name]")
    bundle = Path(argv[1])
    output = Path(argv[2])
    name = argv[3] if len(argv) == 4 else "dystopia-offline-bundle"
    manifest = json.loads((bundle / "hashes.json").read_text(encoding="utf-8"))
    wheels = sorted(bundle.glob("*.whl"))
    if not wheels:
        raise SystemExit("error: bundle has no wheels")

    components = []
    digest_stream = hashlib.sha256()
    for wheel in wheels:
        digest = sha256(wheel)
        if manifest.get(wheel.name) != digest:
            raise SystemExit(f"error: manifest mismatch for {wheel.name}")
        digest_stream.update(f"{wheel.name}:{digest}\n".encode())
        dist, version, license_value, license_source = metadata(wheel)
        if not dist or not version:
            raise SystemExit(f"error: incomplete METADATA in {wheel.name}")
        normalized = normalize(dist)
        purl = f"pkg:pypi/{normalized}@{version}"
        components.append({
            "type": "library",
            "bom-ref": f"{purl}?file_name={wheel.name}#sha256={digest}",
            "name": dist,
            "version": version,
            "purl": purl,
            "hashes": [{"alg": "SHA-256", "content": digest}],
            "licenses": [{"license": {"name": license_value}}],
            "properties": [
                {"name": "dystopia:wheel", "value": wheel.name},
                {"name": "dystopia:license-source", "value": license_source},
                {"name": "dystopia:target-platform", "value": "linux/amd64, CPython 3.12, manylinux_2_28"},
            ],
        })

    serial = uuid.uuid5(uuid.NAMESPACE_URL, digest_stream.hexdigest())
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "tools": {"components": [{
                "type": "application",
                "name": "dystopia-generate-sbom",
                "version": "1",
            }]},
            "component": {
                "type": "application",
                "name": name,
                "version": "1",
            },
        },
        "components": components,
    }
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {output}: {len(components)} components")


if __name__ == "__main__":
    main(sys.argv)
