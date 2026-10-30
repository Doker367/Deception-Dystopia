"""Legacy engine disabled: listeners must run in a validated sensor cell."""


def is_running() -> bool:
    return False


async def start() -> dict:
    return {"status": "blocked", "started": 0, "reason":
            "Legacy listeners share administrative settings; use isolated sensor adapters after validation"}


async def stop() -> dict:
    return {"status": "stopped", "stopped": 0}


def status() -> dict:
    return {"enabled": False, "running": False, "listeners": [], "count": 0,
            "state": "blocked", "reason": "sensor isolation and adapter migration required"}
