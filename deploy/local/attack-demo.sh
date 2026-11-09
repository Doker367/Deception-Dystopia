#!/usr/bin/env bash
# Estímulos benignos, uno por puerto publicado. No son exploits: solo
# conexiones que deben dejar una línea nativa en el log del honeypot.
set -u

HOST="${HOST:-127.0.0.1}"

probe_ssh() {
  printf 'SSH-2.0-dystopia-lab\r\n' | nc -w 4 "$HOST" "$1" >/dev/null 2>&1 || true
}

probe_line() {
  printf '%s\r\n' "$2" | nc -w 4 "$HOST" "$1" >/dev/null 2>&1 || true
}

echo "[1/8] Cowrie SSH      :$HOST:12222"
probe_ssh 12222
echo "[2/8] Cowrie Telnet   :$HOST:12223"
probe_line 12223 "lab"
echo "[3/8] OpenCanary SSH  :$HOST:13022"
probe_ssh 13022
echo "[4/8] OpenCanary HTTP :$HOST:13080"
curl --max-time 5 -sS "http://$HOST:13080/index.html" -o /dev/null || true
echo "[5/8] Dionaea FTP     :$HOST:14021"
printf 'USER lab\r\nPASS demo-not-a-real-password\r\nQUIT\r\n' \
  | nc -w 5 "$HOST" 14021 >/dev/null 2>&1 || true
echo "[6/8] Heralding FTP   :$HOST:15021"
printf 'USER lab\r\nPASS demo-not-a-real-password\r\nQUIT\r\n' \
  | nc -w 5 "$HOST" 15021 >/dev/null 2>&1 || true
echo "[7/8] Redis           :$HOST:16379"
printf '*1\r\n$4\r\nPING\r\n' | nc -w 4 "$HOST" 16379 >/dev/null 2>&1 || true
echo "[8/8] Endlessh        :$HOST:17222"
probe_ssh 17222

echo "Listo. Espera ~12 s (poll de 10 s) y consulta /api/analytics/events."
