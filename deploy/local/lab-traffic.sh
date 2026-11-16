#!/usr/bin/env bash
# Tráfico de laboratorio continuo: dispara attack-demo.sh cada N segundos para
# que el flujo en vivo del panel tenga datos reales (estímulos benignos por los
# puertos publicados, no eventos sintéticos). Es tráfico local: no exponer
# estos puertos fuera de 127.0.0.1.
#
# Uso: ./lab-traffic.sh [intervalo-segundos]   (Ctrl+C para parar)
set -u

INTERVAL="${1:-45}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "Tráfico de laboratorio cada ${INTERVAL}s (Ctrl+C para parar)"
while true; do
  "$HERE/attack-demo.sh" >/dev/null 2>&1 || true
  sleep "$INTERVAL"
done
