"""Test-session fixtures.

Provides a SYNTHETIC, test-only JWT secret so the suite can run without a
provisioned deployment secret. This value is never read by the application at
runtime: app.core.security only reads NETPULSE_JWT_SECRET from the process
environment, which in production comes from /etc/dystopia/control.env.

It is intentionally NOT the retired development default, and it is long enough
(>32 bytes) to satisfy the fail-closed length check.
"""
import os
import secrets
import sys
from pathlib import Path

SYNTHETIC_TEST_SECRET = "dystopia-pytest-synthetic-secret-not-for-deployment-0123456789"

os.environ.setdefault("NETPULSE_JWT_SECRET", SYNTHETIC_TEST_SECRET)
# Keep host-coupled collectors and exposure paths off during tests.
os.environ.setdefault("NETPULSE_ENV", "development")

# RT-09: the raw-reference HMAC key is never committed. Tests generate an
# ephemeral per-session key, exactly like a deployment provisions one in a
# private file. Nothing here is a production secret.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.services.deception.integrations import ecs  # noqa: E402

ecs.configure_reference_key(secrets.token_bytes(32))
