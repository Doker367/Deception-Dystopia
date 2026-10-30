"""Legacy in-control tailer retired; migrate logs to the independent sensor."""


def is_running():
    return False


def start():
    return {"status": "blocked", "reason": "use runtime.sensor; no central DB in sensors"}


def stop():
    return {"status": "stopped"}


def status():
    return {"running": False, "state": "blocked", "sources": []}
