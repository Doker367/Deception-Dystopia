#!/usr/bin/env python3
"""Local-only first administrator bootstrap. No environment passwords or reset."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

if __name__ == "__main__":
    from runtime.cli import main
    raise SystemExit(main(["bootstrap-admin", *sys.argv[1:]]))
