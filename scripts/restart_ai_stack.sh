#!/usr/bin/env bash
# Reinicia el control y el monitor de IA del laboratorio Docker con el
# código y la web actuales. Requiere Docker (se re-ejecuta con sudo si hace
# falta) y los modelos locales escuchando en 172.17.0.1:8081/8091.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/deploy/local"

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker no está instalado" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  if [ "$(id -u)" -ne 0 ]; then
    echo "Se necesita Docker; solicitando sudo…"
    exec sudo -- "$0" "$@"
  fi
  echo "error: el daemon de Docker no responde" >&2
  exit 1
fi

COMPOSE=(
  docker compose
  --env-file .env
  -f docker-compose.yml
  -f docker-compose.remote.yml
  -f docker-compose.ai.yml
)

echo "== comprobando modelos locales =="
for port in 8081 8091; do
  if ! curl -fsS --max-time 3 "http://172.17.0.1:${port}/health" >/dev/null; then
    echo "error: no responde 172.17.0.1:${port}; arranca dystopia-ai-embed/llm" >&2
    exit 1
  fi
done
echo "modelos OK"

echo "== reconstruyendo y reiniciando control + ai-monitor =="
"${COMPOSE[@]}" up -d --build --wait control ai-monitor

echo "== estado =="
"${COMPOSE[@]}" ps control ai-monitor

echo
echo "Web: http://127.0.0.1:8082/#ai"
echo "Logs: docker compose --env-file .env -f docker-compose.yml -f docker-compose.remote.yml -f docker-compose.ai.yml logs -f ai-monitor"
