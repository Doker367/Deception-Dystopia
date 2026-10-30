"""Mapping compatibility checks used by the artifact tests.

Elasticsearch is permissive in some places (numeric strings are coerced to
keywords) and strict in others (an object cannot be indexed as a keyword, and
an undeclared field under ``dynamic: strict`` rejects the document). This model
reproduces the distinctions that matter for the contract without starting a
cluster.
"""
from __future__ import annotations

from ipaddress import ip_address
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_GLOBS = (
    "config/elasticsearch/templates/*.json",
    "config/elasticsearch/**/*template*.json",
    "deploy/elasticsearch/**/*.json",
    "deploy/elastic/**/*template*.json",
    "runtime/elastic/**/*template*.json",
    "integration/elastic/**/*template*.json",
)


def template_paths():
    found = set()
    for pattern in TEMPLATE_GLOBS:
        found.update(ROOT.glob(pattern))
    return sorted(path for path in found if path.is_file())


def load_template(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def mapping_root(container):
    """Return the mappings object, including its ``dynamic`` setting."""
    current = container
    for _ in range(4):
        if not isinstance(current, dict):
            break
        if "mappings" in current and isinstance(current["mappings"], dict):
            current = current["mappings"]
            continue
        if "template" in current and isinstance(current["template"], dict):
            current = current["template"]
            continue
        if "properties" in current and isinstance(current["properties"], dict):
            return current
        break
    raise ValueError("template has no mappings/properties object")


def index_patterns(container):
    patterns = container.get("index_patterns")
    if patterns is None and isinstance(container.get("template"), dict):
        patterns = container["template"].get("index_patterns")
    return list(patterns or [])


_SCALARS = (str, int, float, bool)


def _scalar_ok(kind, value):
    if kind in {"keyword", "text", "constant_keyword", "wildcard"}:
        return isinstance(value, _SCALARS)
    if kind == "ip":
        if not isinstance(value, str):
            return False
        try:
            ip_address(value)
            return True
        except ValueError:
            return False
    if kind == "date":
        return isinstance(value, (str, int, float)) and not isinstance(value, bool)
    if kind in {"long", "integer", "short", "byte"}:
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return True
        return isinstance(value, str) and re.fullmatch(r"-?\d+", value) is not None
    if kind in {"float", "double", "half_float", "scaled_float"}:
        if isinstance(value, bool):
            return False
        if isinstance(value, (int, float)):
            return True
        return isinstance(value, str) and re.fullmatch(r"-?\d+(?:\.\d+)?", value) is not None
    if kind == "boolean":
        return isinstance(value, bool) or (
            isinstance(value, str) and value.lower() in {"true", "false"}
        )
    if kind == "geo_point":
        return isinstance(value, (str, list)) or (
            isinstance(value, dict) and "lat" in value and "lon" in value
        )
    return True


def _walk(value, node, path, errors, warnings):
    if isinstance(value, dict):
        kind = (node or {}).get("type")
        if kind not in (None, "object", "nested"):
            errors.append(f"{path}: object cannot be indexed as {kind}")
            return
        properties = (node or {}).get("properties")
        for key, nested in value.items():
            child_path = f"{path}.{key}" if path else key
            child = (properties or {}).get(key)
            if child is None:
                policy = (node or {}).get("dynamic")
                if policy == "strict":
                    errors.append(f"{child_path}: undeclared field under dynamic=strict")
                elif policy is False:
                    warnings.append(
                        f"{child_path}: stored in _source but not indexed (dynamic=false)"
                    )
                continue
            _walk(nested, child, child_path, errors, warnings)
        return
    if isinstance(value, list):
        kind = (node or {}).get("type")
        if kind not in (None, "object", "nested"):
            for item in value:
                if not _scalar_ok(kind, item):
                    errors.append(f"{path}: {kind} array contains an incompatible value")
                    break
            return
        for item in value:
            _walk(item, node, path, errors, warnings)
        return
    if node is None:
        return
    kind = node.get("type")
    if kind and kind not in {"object", "nested"} and not _scalar_ok(kind, value):
        errors.append(f"{path}: value is incompatible with mapping type {kind}")


def check_document(document, root):
    errors, warnings = [], []
    _walk(document, root, "", errors, warnings)
    return errors, warnings


def declared_paths(root, prefix=""):
    paths = set()
    for key, definition in (root.get("properties") or {}).items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(definition, dict) and "properties" in definition:
            paths.update(declared_paths(definition, path))
        else:
            paths.add(path)
    return paths
