#!/bin/sh
# NetPulse — entrypoint de dispositivo del fabric (Fase 4).
#
# No arranca servicios todavía: mantiene el contenedor vivo para que el
# Device Runtime pueda mover el veth a su netns y configurar la interfaz.
# La Fase 5 sustituirá este bucle por el arranque de honeypots.
set -eu

trap 'exit 0' TERM INT

while :; do
    sleep 3600 &
    wait "$!"
done
