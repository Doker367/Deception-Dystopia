"""Test-session fixtures.

Provides a SYNTHETIC, test-only JWT secret so the suite can run without a
provisioned deployment secret. This value is never read by the application at
runtime: app.core.security only reads NETPULSE_JWT_SECRET from the process
environment, which in production comes from /etc/dystopia/control.env.

It is intentionally NOT the retired development default, and it is long enough
(>32 bytes) to satisfy the fail-closed length check.
"""
import os

SYNTHETIC_TEST_SECRET = "dystopia-pytest-synthetic-secret-not-for-deployment-0123456789"

os.environ.setdefault("NETPULSE_JWT_SECRET", SYNTHETIC_TEST_SECRET)
# Keep host-coupled collectors and exposure paths off during tests.
os.environ.setdefault("NETPULSE_ENV", "development")
