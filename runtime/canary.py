"""Defensive honeytoken metadata shared by the sensor and control plane.

The canary is a *tripwire*, not a tracker: it is a plausible file inside the
Cowrie fake filesystem.  When an attacker reads it, Cowrie logs the command;
normalization marks the event and the alerting path raises a high-signal
``canary_access`` alert.  Nothing is sent to the attacker and no external
callback is performed.

Keep this module dependency-free so it can be imported by the isolated
collector and by the control plane.  The Cowrie image build reads the same
constants from ``docker/deception/cowrie/patch_process.py``; the test suite
asserts both copies stay in sync.
"""

from __future__ import annotations

CANARY_ID = "finance-2026"
CANARY_PATH = "/srv/files/finance/2026-q4.csv"
CANARY_TOKEN = "DYSTOPIA-CANARY-FINANCE-2026-7F3C9A2E"
CANARY_CONTENT = (
    "period,account,amount,currency,reference\n"
    "2026-Q4,ACME-041,184250.00,USD,INV-2026-1041\n"
    "2026-Q4,ACME-042,98210.50,USD,INV-2026-1042\n"
    "2026-Q4,NORTHWIND-017,55120.00,USD,DYSTOPIA-CANARY-FINANCE-2026-7F3C9A2E\n"
    "2026-Q4,CONTOSO-003,120400.75,USD,INV-2026-1044\n"
)
CANARY_MARKERS = (CANARY_TOKEN, CANARY_PATH, "2026-q4.csv")


def match(value: object) -> str | None:
    """Return the canary id when a command/reference touches the tripwire."""
    if not isinstance(value, str) or not value:
        return None
    haystack = value.casefold()
    for marker in CANARY_MARKERS:
        if marker.casefold() in haystack:
            return CANARY_ID
    return None
