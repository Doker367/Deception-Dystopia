#!/usr/bin/env python3
"""Monitor proactivo de la IA: evalúa eventos nuevos y lanza notificaciones.

Uso puntual (systemd timer o cron):
    python3 scripts/ai_monitor.py --once

Bucle continuo:
    python3 scripts/ai_monitor.py --loop --interval 300

Requiere el entorno del servicio (NETPULSE_RAG_ENABLED=true y los modelos
locales). No bloquea ni modifica nada: solo crea hallazgos y notifica.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core import settings  # noqa: E402
from app.services.ai.rag import service  # noqa: E402
from app.services.ai.rag.errors import RagError  # noqa: E402


def run(args: argparse.Namespace) -> int:
    if not settings.RAG_MONITOR_ENABLED and not args.force:
        print(json.dumps({
            "skipped": True,
            "reason": "NETPULSE_AI_MONITOR_ENABLED=false (use --force para una pasada manual)",
        }, ensure_ascii=False))
        return 0
    try:
        result = service.scan(
            window_min=args.window,
            min_events=args.min_events,
            notify=not args.no_notify,
        )
    except RagError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor proactivo de la IA")
    parser.add_argument("--once", action="store_true", help="una pasada (por defecto)")
    parser.add_argument("--loop", action="store_true", help="bucle continuo")
    parser.add_argument("--interval", type=int, default=300, help="segundos entre pasadas")
    parser.add_argument("--window", type=int, default=None, help="ventana de análisis en minutos")
    parser.add_argument("--min-events", type=int, default=None, help="umbral de eventos")
    parser.add_argument("--no-notify", action="store_true", help="no enviar notificaciones")
    parser.add_argument("--force", action="store_true", help="ignorar NETPULSE_AI_MONITOR_ENABLED")
    args = parser.parse_args()

    if args.loop:
        while True:
            try:
                run(args)
            except KeyboardInterrupt:
                return 0
            except Exception as exc:  # noqa: BLE001
                print(f"error inesperado: {exc}", file=sys.stderr)
            time.sleep(max(30, args.interval))
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
