#!/usr/bin/env python3
"""CLI del RAG local: indexar, buscar y etiquetar sin pasar por la API.

Uso:
    export NETPULSE_RAG_ENABLED=true
    python3 scripts/rag_cli.py status
    python3 scripts/rag_cli.py index --scope all
    python3 scripts/rag_cli.py search "fuerza bruta SSH" --ip 203.0.113.9
    python3 scripts/rag_cli.py ask "¿Qué hizo 203.0.113.9?" --ip 203.0.113.9
    python3 scripts/rag_cli.py triage "Clasificá el caso de 203.0.113.9" --ip 203.0.113.9
    python3 scripts/rag_cli.py feedback --predicted suspicious --label true_positive \
        --question "caso 203.0.113.9"
    python3 scripts/rag_cli.py metrics

La configuración se toma del entorno (el proyecto no carga .env solo).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.ai.rag import service  # noqa: E402
from app.services.ai.rag.errors import RagError  # noqa: E402


def _print(payload: object) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def main() -> int:
    parser = argparse.ArgumentParser(description="Memoria RAG local de Dystopia")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="estado del índice y de los modelos")

    index = sub.add_parser("index", help="indexar fuentes locales")
    index.add_argument("--scope", default="all",
                       choices=["all", "events", "notes", "knowledge"])
    index.add_argument("--force", action="store_true", help="reindexar aunque no cambie")

    search = sub.add_parser("search", help="búsqueda híbrida")
    search.add_argument("query")
    search.add_argument("--ip", default=None)
    search.add_argument("--k", type=int, default=None)
    search.add_argument("--kind", action="append", choices=["event", "note", "knowledge"])

    ask = sub.add_parser("ask", help="respuesta fundamentada con citas")
    ask.add_argument("question")
    ask.add_argument("--ip", default=None)
    ask.add_argument("--k", type=int, default=None)
    ask.add_argument("--kind", action="append", choices=["event", "note", "knowledge"])

    triage = sub.add_parser("triage", help="veredicto estructurado")
    triage.add_argument("question")
    triage.add_argument("--ip", default=None)
    triage.add_argument("--k", type=int, default=None)

    feedback = sub.add_parser("feedback", help="etiquetar un caso (TP/FP)")
    feedback.add_argument("--question", required=True)
    feedback.add_argument("--predicted", required=True,
                          choices=["malicious", "suspicious", "benign", "unknown"])
    feedback.add_argument("--label", required=True,
                          choices=["true_positive", "false_positive"])
    feedback.add_argument("--ip", default="")
    feedback.add_argument("--analyst", default="cli")
    feedback.add_argument("--notes", default="")

    sub.add_parser("metrics", help="precisión y recall de casos etiquetados")

    args = parser.parse_args()
    try:
        if args.command == "status":
            _print(service.status())
        elif args.command == "index":
            _print(service.index(scope=args.scope, force=args.force))
        elif args.command == "search":
            _print(service.search(args.query, k=args.k, kinds=args.kind, src_ip=args.ip))
        elif args.command == "ask":
            _print(service.ask(args.question, k=args.k, kinds=args.kind, src_ip=args.ip))
        elif args.command == "triage":
            _print(service.ask(args.question, k=args.k, src_ip=args.ip, mode="triage"))
        elif args.command == "feedback":
            _print(service.feedback(
                question=args.question, predicted=args.predicted, label=args.label,
                analyst=args.analyst, src_ip=args.ip, notes=args.notes,
            ))
        elif args.command == "metrics":
            _print(service.metrics())
    except RagError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
