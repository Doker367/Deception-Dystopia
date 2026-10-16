# Despliegue

Servidor Linux dedicado. Crear entorno sin descargar durante validación, instalar dependencias desde artefactos aprobados, crear `.env` local y mantener servicios opt-in. Laya se despliega localmente con `docker-compose.ai.yml` o un `laya-serve` equivalente; la aplicación conserva fallback cuando no está disponible. No usar `privileged` ni `network_mode: host`.

## Operación aislada

La API de control y la red señuelo usan interfaces/VLAN distintas. Mantenga listeners en loopback o red aislada; documente puertos antes de habilitarlos. Packet mode requiere revisión especial; QEMU/VNC nunca debe enlazar gestión ni Internet. Cowrie/OpenCanary permanecen en red interna. Use únicamente topología y datos sintéticos. Dystopia arranca y opera sin NOC; la integración futura es opt-in.
