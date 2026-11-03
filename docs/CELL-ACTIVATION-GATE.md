# Contrato offline del gate de activación de celdas

**Versión:** `dystopia.cell-verification/v1`

**Estado:** bloqueado por defecto. Este comando no activa celdas.

`runtime.cell_gate.evaluate_cell_gate()` recibe una `CellPolicy` o
`ContainerCellPolicy` ya validada, el ID esperado mediante `CellGateContext` y,
opcionalmente, un directorio de evidencias. Produce un resultado determinista con
`activation_allowed`, `containment_verified`, `blocking_reasons`,
`required_artifacts` y `detail`. La CLI equivalente es:

```text
python -m runtime.cli cells gate --cell N --policy PATH [--artifacts DIR]
```

El gate solo lee la política y los artefactos; no ejecuta `nft`, Docker, KVM,
libvirt, systemd ni comandos del sistema. Tampoco importa ni conecta el despliegue
Compose. Un resultado bloqueado devuelve código de salida `2` y JSON en stdout.

## Qué valida

- El tipo de política validada, coincidencia de celda y workload, y el SHA-256 de
  la representación JSON canónica de esa política.
- El manifiesto `cell-N.attestation.json`, con esquema exacto v1, identidad de
  Ubuntu 24.04/kernel/boot y registros para los ocho artefactos requeridos.
- Que cada archivo de evidencia sea regular, acotado, único, coincida con su SHA-256
  declarado y tenga resultado `pass`.
- Una firma Ed25519 sobre el manifiesto, hecha por una clave pública confiable
  fijada en el propio gate. No se acepta una clave incluida en el paquete.
- Para políticas de contenedor, que exista un digest de imagen revisado (`image` no
  puede ser `null`).

Los archivos de una carpeta de evidencias son referenciados por nombre de archivo
(sin subdirectorios) por el manifiesto. Cada registro tiene exactamente `file`,
`sha256` y `result`. El manifiesto incluye `schema`, `cell`, `workload`,
`policy_sha256`, `verification`, `platform`, `verifier_key_id`, `artifacts` y
`signature`. La firma cubre todos los campos salvo `signature`; los archivos se
ligan al manifiesto mediante sus hashes.

El trust store v1 (`TRUSTED_VERIFIER_KEYS`) empieza intencionalmente vacío. Por
tanto, **este commit siempre bloquea**, incluso ante informes bien formados. Solo
una revisión separada del verificador Linux, la custodia de su clave y la fijación
de la clave pública podrían permitir que una evidencia futura pase el contrato.
No se incluye una clave privada, un generador de evidencia ni un camino para
saltarse esa revisión. `apply_succeeded=True` no altera la decisión: la aceptación
de una transacción no es prueba independiente ni puede omitir el gate.

## Qué no valida ni hace

- No observa el kernel, no descubre topología, no ejecuta pruebas de paquetes ni
  comprueba que la evidencia siga vigente en el host que consumiría la celda.
- No instala ni evalúa reglas nftables, no arranca/paraliza workload, y no otorga
  autorización operativa. Es un verificador de contrato de evidencia, no una
  frontera de seguridad ni un activador.
- No convierte tests unitarios, mocks, configuración declarativa o manifiestos en
  evidencia Linux. `mock`, `self-check`, `internal=true`, campos desconocidos y
  firmas no confiables no pueden aprobar.

## Evidencia Linux mínima del contrato v1

El verificador independiente debe producir, ligar al hash de política, firmar y
entregar estos artefactos. Deben incluir observaciones y resultados reproducibles,
no solo una configuración deseada:

1. `host_identity`: Ubuntu 24.04, kernel y boot ID observados.
2. `network_topology`: bridge/puertos/interfaces reales, exclusividad de la celda,
   ausencia de rutas, NAT, interfaces adicionales y bypasses relevantes.
3. `nft_policy`: reglas **cargadas en kernel**, orden/hooks y contadores observados,
   además de su correspondencia con la política exacta.
4. `connectivity_matrix`: pruebas permitidas y denegadas, con capturas externas al
   workload que prueben entrega y ausencia de entrega.
5. `resource_limits`: límites cgroup v2 efectivos y pruebas de presión/denegación.
6. `storage_quota`: cuota efectiva de datos y logs, rotación y prueba de agotamiento
   controlado.
7. `workload_boundary`: identidad y configuración efectiva de KVM/QEMU o runtime
   de contenedor, dispositivos/interfaces, privilegios y separación del host.
8. `activation_barrier`: arranque condicionado a verificación, NIC/link inicialmente
   cerrado, ausencia de autostart y comportamiento fail-closed ante fallos/reboot.

El verificador debe estar fuera del proceso que aplica la política y no debe firmar
resultados derivados únicamente de declaraciones del propio workload. La clave
pública solo se fija tras revisar código, aislamiento, custodia y procedimiento de
revocación del firmante.

## Por qué estas señales no prueban contención

- `internal=true` describe una opción de red de Docker. No demuestra el estado real
  del kernel, ausencia de otras rutas/interfaces, límites de recursos efectivos ni
  que el runtime no tenga una configuración adicional.
- `nft --check` valida que una transacción se puede analizar/aplicar. No prueba que
  se aplicó, que la tabla observada sea la esperada, el orden efectivo de hooks,
  aislamiento frente a otras reglas, ni el resultado de tráfico real permitido y
  denegado.
- Un `apply` exitoso indica, como máximo, aceptación de una transacción. No cambia
  `containment_verified` ni elimina ningún bloqueo del gate.
- Un archivo que diga `verification: mock`, `verification: self-check` o
  `internal: true` es una afirmación autocontenida; sin firmante confiable y hashes
  de evidencia no acredita observaciones independientes.

## Checklist para una futura verificación en Ubuntu 24.04

Este checklist es un plan de laboratorio; **no se ejecutó en este cambio**. Usar
una VM desechable, sin red externa/LAN, secretos, sockets compartidos ni workload
de producción. Mantener la activación bloqueada durante la toma de evidencias.

- [ ] Revisar y aprobar política exacta, exclusividad de la celda e inventario; fijar
      digest de imagen cuando aplique. Calcular el hash canónico esperado.
- [ ] Confirmar identidad del host Ubuntu 24.04, kernel, boot y que el host/lab está
      aislado; registrar herramientas y versiones del verificador.
- [ ] Inspeccionar topología real, namespaces, bridge, puertos y rutas; buscar
      interfaces extra, NAT, forwarding y caminos de bypass.
- [ ] Inspeccionar reglas cargadas, hooks, prioridades, contadores y conntrack en el
      kernel. Capturar tráfico desde un punto independiente al workload.
- [ ] Ejecutar matriz positiva/negativa IPv4 e IPv6: servicio autorizado; origen,
      puerto y dirección inversa nuevos no autorizados; host, gestión, Internet,
      metadata, otras celdas, spoofing, fragmentos, VLAN, ARP/ND/RA/DHCP y multicast.
- [ ] Verificar cgroup v2 efectivo (memoria, CPU, PIDs) y probar límites; verificar
      cuotas de disco/logs, rotación y fallo controlado por agotamiento.
- [ ] Inspeccionar los límites efectivos de KVM/QEMU o del runtime de contenedor,
      privilegios, namespaces, dispositivos, mounts y ausencia de socket del runtime.
- [ ] Probar enlace cerrado y barrera de arranque, parada/cuarentena, caída del
      verificador, reinicio y persistencia; comprobar que cualquier incertidumbre
      conserva el bloqueo.
- [ ] Guardar artefactos brutos, generar manifiesto v1 ligado a celda y hash de
      política, revisar resultados y firmar con una clave de verificador protegida.
- [ ] Revisar el paquete fuera del workload. Fijar la clave pública confiable en un
      cambio separado y revisado; ejecutar el gate offline y conservar JSON, hashes,
      capturas, aprobación y decisión operativa.
- [ ] No usar este gate como comando de arranque: una aprobación futura solo sería
      un prerrequisito para un camino de activación separado, revisado y autorizado.

## Ejemplo de salida actual

```json
{
  "activation_allowed": false,
  "blocking_reasons": [
    "no Linux verification artifacts were supplied",
    "no independently reviewed Linux verifier key is pinned (v1 fail-closed)"
  ],
  "containment_verified": false,
  "detail": "activation blocked; independent Linux containment evidence is incomplete",
  "required_artifacts": [
    "host_identity",
    "network_topology",
    "nft_policy",
    "connectivity_matrix",
    "resource_limits",
    "storage_quota",
    "workload_boundary",
    "activation_barrier"
  ]
}
```
