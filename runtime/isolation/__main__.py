"""Local-only fixed-operation helper. No socket or API privilege escalation path."""
import argparse
import json
from pathlib import Path

from .backend import LocalCellBackend
from .containers import ContainerCellPolicy, container_manifest, container_nft_rules
from .policy import CellPolicy
from .render import domain_xml, nft_rules


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("operation", choices=("plan", "plan-container", "apply", "quarantine",
                                        "emergency", "stop", "verify", "activate"))
    p.add_argument("--cell", type=int)
    p.add_argument("--policy", type=Path)
    p.add_argument("--confirm")
    args = p.parse_args()
    if args.operation in ("plan", "plan-container"):
        if not args.policy or args.cell is not None:
            p.error("plan requires only an explicit policy file")
        from .backend import _unique_object
        with args.policy.open("rb") as stream:
            raw = stream.read(16385)
        if len(raw) > 16384:
            p.error("policy exceeds 16 KiB")
        document = json.loads(raw, object_pairs_hook=_unique_object)
        if args.operation == "plan":
            policy = CellPolicy.from_mapping(document)
            print(json.dumps({"state": "configurado", "containment_verified": False,
                              "domain_xml": domain_xml(policy), "nft": nft_rules(policy)},
                             indent=2))
        else:
            policy = ContainerCellPolicy.from_mapping(document)
            print(json.dumps({
                "state": "configurado",
                "containment_verified": False,
                "activation_allowed": False,
                "deployment_errors": policy.deployment_errors(),
                "manifest": container_manifest(policy),
                "nft": container_nft_rules(policy),
            }, indent=2))
        return 0
    if args.policy is not None or args.cell is None:
        p.error("privileged operations accept only a cell number, never a caller policy path")
    if args.confirm != f"CELL-{args.cell}-{args.operation.upper()}":
        p.error("explicit per-cell operation confirmation required")
    backend = LocalCellBackend(args.cell)
    operations = {"apply": backend.apply, "quarantine": backend.quarantine,
                  "emergency": backend.emergency, "stop": backend.stop,
                  "verify": backend.verify, "activate": backend.activate}
    operations[args.operation]()
    print(json.dumps({"state": backend.state.value, "detail": backend.detail,
                      "containment_verified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
