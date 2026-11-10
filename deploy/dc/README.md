# Handoff de red para el CPD

Esta carpeta contiene la matriz legible por máquina para el ingeniero de redes:

- `ports.csv`: puertos publicados y de gestión.
- `flows.csv`: flujos propuestos; los valores entre `<...>` son placeholders.

Los documentos de contexto son:

- [`docs/NETWORK-MATRIX.md`](../../docs/NETWORK-MATRIX.md)
- [`docs/CELL-INVENTORY.md`](../../docs/CELL-INVENTORY.md)
- [`docs/RUNBOOK-DC-CUTOVER.md`](../../docs/RUNBOOK-DC-CUTOVER.md)

Reglas que no deben relajarse:

1. El panel `8082` nunca se publica en Internet ni en la VLAN de sensores.
2. El ingress debe preservar la IP pública del atacante; nada de SNAT.
3. Los sensores no inician tráfico hacia gestión, backup, SIEM, Internet ni
   otras celdas.
4. IPv6, si se habilita, replica la misma política.
5. No se declara contención sin evidencia Linux firmada y el gate aprobado.

No incluir IPs reales, JWT, claves ni capturas de tráfico en este repositorio.
