#!/usr/bin/env python3
"""Passive analysis of files captured by Cowrie.

This utility only reads Cowrie's JSONL log and the files Cowrie stored under
``var/lib/cowrie/downloads``.  It never executes a sample, never follows a
symlink out of the downloads directory, and never talks to the network.

It computes SHA-256/MD5/size and a small magic-byte classification, optionally
asks ``file``, ClamAV (``--clamav``) or YARA (``--yara-rules``) for a second
opinion, and compares the observed hash with the hash Cowrie logged.

Example (on the Docker host, with the local cell data root)::

    python3 scripts/analyze_cowrie_samples.py \
      --log /var/lib/dystopia/honeypots/cowrie/var/log/cowrie/cowrie.json \
      --downloads /var/lib/dystopia/honeypots/cowrie/var/lib/cowrie/downloads \
      --output /tmp/cowrie-samples.json

The report deliberately contains only metadata and bounded tool output; it is
not a sandbox and must not be used to detonate malware.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any


def load_download_events(log_path: Path) -> list[dict[str, Any]]:
    """Return ``cowrie.session.file_download`` records from a JSONL log."""
    events: list[dict[str, Any]] = []
    with log_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_number, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if not isinstance(record, dict):
                continue
            if record.get("eventid") != "cowrie.session.file_download":
                continue
            record.setdefault("_line", line_number)
            events.append(record)
    return events


def safe_sample_path(downloads_root: Path, outfile: object) -> Path | None:
    """Resolve a logged outfile without allowing traversal/symlink escape.

    Cowrie normally stores the sample under a SHA-256 filename in the downloads
    directory.  Logs can contain relative or container-absolute paths, so only
    the basename is trusted and it is joined to the configured host directory.
    """
    if not isinstance(outfile, str) or not outfile:
        return None
    name = Path(outfile).name
    if not name or name in {".", ".."}:
        return None
    root = downloads_root.resolve(strict=False)
    candidate = (root / name).resolve(strict=False)
    try:
        if candidate.parent != root:
            return None
    except OSError:
        return None
    return candidate


def _magic_kind(head: bytes) -> str:
    if not head:
        return "empty"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"#!"):
        return "script"
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    if head.startswith(b"%PDF"):
        return "pdf"
    printable = sum(32 <= byte < 127 or byte in b"\r\n\t" for byte in head)
    if b"\x00" not in head and printable / len(head) >= 0.9:
        return "text"
    return "binary"


def _run(argv: list[str], timeout: int) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
            check=False,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "error": str(exc)}
    return {
        "available": True,
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip()[:4096],
        "stderr": proc.stderr.strip()[:1024],
    }


def inspect_sample(
    downloads_root: Path,
    event: dict[str, Any],
    *,
    yara_rules: Path | None = None,
    run_clamav: bool = False,
) -> dict[str, Any]:
    """Inspect one downloaded file without executing it."""
    outfile = event.get("outfile") or event.get("filename")
    path = safe_sample_path(downloads_root, outfile)
    result: dict[str, Any] = {
        "line": event.get("_line"),
        "session": event.get("session"),
        "src_ip": event.get("src_ip"),
        "url": event.get("url"),
        "outfile": outfile,
    }
    if path is None:
        result.update({"status": "unsafe_path", "error": "outfile escapes downloads root"})
        return result
    result["path"] = str(path)
    if not path.is_file() or path.is_symlink():
        result.update({"status": "missing"})
        return result

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    size = 0
    head = b""
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            if len(head) < 32:
                head += chunk[: 32 - len(head)]
            sha256.update(chunk)
            md5.update(chunk)
            size += len(chunk)

    result.update(
        {
            "status": "ok",
            "size": size,
            "sha256": sha256.hexdigest(),
            "md5": md5.hexdigest(),
            "magic": _magic_kind(head),
        }
    )
    logged_hash = event.get("shasum") or event.get("sha256_hash")
    if isinstance(logged_hash, str) and len(logged_hash) == 64:
        result["hash_matches_event"] = logged_hash.lower() == result["sha256"]

    file_bin = shutil.which("file")
    if file_bin:
        file_result = _run([file_bin, "--brief", "--mime-type", str(path)], 5)
        if file_result.get("available"):
            result["file_mime"] = file_result.get("stdout", "")

    if yara_rules is not None:
        yara_bin = shutil.which("yara")
        if yara_bin:
            yara_result = _run([yara_bin, "-s", str(yara_rules), str(path)], 30)
            yara_result["matches"] = [
                line for line in yara_result.get("stdout", "").splitlines() if line
            ]
            result["yara"] = yara_result
        else:
            result["yara"] = {"available": False, "error": "yara not installed"}

    if run_clamav:
        clam_bin = shutil.which("clamscan")
        if clam_bin:
            clam_result = _run(
                [clam_bin, "--no-summary", "--infected", str(path)], 60
            )
            if clam_result.get("available"):
                rc = clam_result.get("returncode")
                clam_result["status"] = (
                    "infected" if rc == 1 else "clean" if rc == 0 else "error"
                )
            result["clamav"] = clam_result
        else:
            result["clamav"] = {"available": False, "error": "clamscan not installed"}

    return result


def build_report(
    log_path: Path,
    downloads_root: Path,
    *,
    yara_rules: Path | None = None,
    run_clamav: bool = False,
) -> dict[str, Any]:
    events = load_download_events(log_path)
    samples = [
        inspect_sample(
            downloads_root,
            event,
            yara_rules=yara_rules,
            run_clamav=run_clamav,
        )
        for event in events
    ]
    return {
        "log": str(log_path),
        "downloads": str(downloads_root),
        "download_events": len(events),
        "samples": samples,
    }


def _default_downloads(log_path: Path) -> Path:
    # <cell>/var/log/cowrie/cowrie.json -> <cell>/var/lib/cowrie/downloads
    return log_path.parent.parent.parent / "lib" / "cowrie" / "downloads"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--log",
        type=Path,
        default=Path(
            os.environ.get(
                "DYSTOPIA_COWRIE_LOG",
                "/var/lib/dystopia/honeypots/cowrie/var/log/cowrie/cowrie.json",
            )
        ),
    )
    parser.add_argument(
        "--downloads",
        type=Path,
        default=None,
        help="Cowrie downloads directory (default: derived from --log)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="write JSON here instead of stdout",
    )
    parser.add_argument("--yara-rules", type=Path, default=None)
    parser.add_argument(
        "--clamav",
        action="store_true",
        help="run clamscan if it is installed (signature scan, no execution)",
    )
    args = parser.parse_args(argv)

    log_path = args.log.expanduser()
    if not log_path.is_file():
        print(f"analyze_cowrie_samples: log not found: {log_path}", file=sys.stderr)
        return 2
    downloads = (
        args.downloads.expanduser()
        if args.downloads is not None
        else _default_downloads(log_path)
    )
    yara_rules = args.yara_rules.expanduser() if args.yara_rules else None
    report = build_report(
        log_path,
        downloads,
        yara_rules=yara_rules,
        run_clamav=args.clamav,
    )
    payload = json.dumps(report, indent=2, sort_keys=True)
    if args.output is None:
        print(payload)
    else:
        args.output.expanduser().write_text(payload + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
