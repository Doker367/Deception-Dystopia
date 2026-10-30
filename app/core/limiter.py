"""Shared limiter keyed by the direct socket peer only.

Untrusted forwarding headers must never bypass the login attempt budget.
A trusted reverse proxy would need a separately verified identity boundary.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request


def client_key(request: Request) -> str:
    """Use the direct peer, never caller-supplied proxy headers."""
    return get_remote_address(request)


limiter = Limiter(
    key_func=client_key,
    default_limits=["100/minute"],  # 100 requests per minute per client
)
