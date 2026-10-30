"""Read-only legacy registry. QEMU execution from the API is prohibited.

Lifecycle now belongs to runtime.isolation; activation remains fail-closed.
No PID signals, disk creation/deletion, consoles or default networking here.
"""
import json
from app.core.settings import VMS_REGISTRY

_REASON = "Legacy VM lifecycle disabled; use the local isolation helper (activation requires verification)"


def is_enabled() -> bool:
    return False


def qemu_available() -> dict:
    return {"managed_by": "libvirt-helper", "activation": "blocked"}


def list_vms() -> list[dict]:
    if not VMS_REGISTRY.exists():
        return []
    data = json.loads(VMS_REGISTRY.read_text(encoding="utf-8"))
    return [{**vm, "running": None, "status": "unverified_legacy", "vnc": None}
            for vm in data.get("vms", [])]


def get_vm(vm_id):
    return next((vm for vm in list_vms() if vm["id"] == vm_id), None)


def list_isos():
    return []


def start_vm(vm_id):
    return {"success": False, "error": _REASON}


def stop_vm(vm_id):
    return {"success": False, "error": _REASON}


def create_vm(*args, **kwargs):
    raise RuntimeError(_REASON)


def save_iso(*args, **kwargs):
    raise RuntimeError(_REASON)


def delete_vm(*args, **kwargs):
    raise RuntimeError(_REASON)
