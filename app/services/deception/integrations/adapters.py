"""Registry of external honeypot adapters.

Each adapter maps a native log record to the common ECS/Dystopia contract in
``ecs.build_event``. Adapters are deliberately pure: metadata (Dystopia
topology, GeoIP) is injected, and an absent/honeypot-unknown device is kept.
"""

from typing import Any, Callable, Optional

from . import (
    cowrie_svc,
    dionaea_svc,
    endlessh_svc,
    heralding_svc,
    opencanary_svc,
    redishoneypot_svc,
)

Adapter = Callable[..., Optional[dict]]

# Canonical sensor names and the aliases found in deployment/config files.
ADAPTERS: dict[str, Adapter] = {
    "cowrie": cowrie_svc.normalize,
    "opencanary": opencanary_svc.normalize,
    "dionaea": dionaea_svc.normalize,
    "heralding": heralding_svc.normalize,
    "redishoneypot": redishoneypot_svc.normalize,
    "redis-honeypot": redishoneypot_svc.normalize,
    "endlessh": endlessh_svc.normalize,
}

PRODUCTS = {
    "cowrie": cowrie_svc.PRODUCT,
    "opencanary": opencanary_svc.PRODUCT,
    "dionaea": dionaea_svc.PRODUCT,
    "heralding": heralding_svc.PRODUCT,
    "redishoneypot": redishoneypot_svc.PRODUCT,
    "redis-honeypot": redishoneypot_svc.PRODUCT,
    "endlessh": endlessh_svc.PRODUCT,
}


def supported() -> list[str]:
    return sorted(ADAPTERS)


def normalize(sensor: str, raw: Any, **kwargs: Any) -> Optional[dict]:
    """Normalize one record from a named sensor.

    Raises:
        ValueError: unknown sensor name (configuration error, not a log error).
    """
    adapter = ADAPTERS.get(str(sensor).strip().lower())
    if adapter is None:
        raise ValueError("unknown honeypot adapter")
    return adapter(raw, **kwargs)
