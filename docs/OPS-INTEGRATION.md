# Integración operativa offline (`ops status` / `ops verify`)

**Versión:** `dystopia.ops/v1`

**Estado:** solo lectura. El comando no activa ninguna celda, no arranca
servicios y no modifica el host.

`runtime/ops.py` es la costura entre contratos que ya existían:

| plano | contrato reutilizado |
|-------|----------------------|
| control | tabla fija de artefactos de `runtime/backup.py` |
| backup | `runtime.backup.runtime_state()` y sus huecos declarados |
| runtime | instantáneas de `runtime/health.py` (ingesta y spool del sensor) |
| honeypots | `runtime.honeypots.validate()` sobre inventario y perfil |
| gates | `runtime.cell_gate.gate_report()` por celda |
| despliegue | unidades de `deploy/systemd/` leídas como texto |

## Uso

```text
python -m runtime.cli ops status [opciones]
python -m runtime.cli ops verify [opciones]
```

Opciones comunes:

```text
--state-root PATH          raíz de estado (por defecto /var/lib/dystopia)
--control-env-dir PATH     directorio de entorno (por defecto /etc/dystopia)
--elastic-env PATH         fichero .env analítico
--inventory PATH           inventario de honeypots
--profile PATH             perfil de celda
--policy CELL=PATH         política de celda validada; repetible
--artifacts PATH           evidencias de verificación de una celda
--units-dir PATH           directorio de unidades systemd
```

`status` siempre devuelve JSON y código de salida `0`: es un informe, aunque
alguna comprobación falle. `verify` devuelve el mismo informe con
`action: ops-verify` y código `2` cuando `ok` es `false`.

## Comprobaciones

| id | falla cuando |
|----|--------------|
| `control_state_present` | falta el almacén de identidades o el plan de instalación |
| `backup_contract_ready` | falta un artefacto obligatorio de la tabla de backup |
| `runtime_state_readable` | la base de ingesta existe pero no se puede leer en solo lectura |
| `honeypot_profile_valid` | inventario/perfil inválidos o fuera de los invariantes de seguridad |
| `honeypot_data_root_aligned` | la raíz de datos de la celda queda fuera de `/var/lib/dystopia` |
| `unit_paths_accounted_for` | una unidad referencia una ruta de estado que ningún contrato declara |
| `cell_policies_valid` | una política solicitada no se puede leer o validar |
| `activation_gate_fail_closed` | el gate autoriza una celda o realiza una activación |

Una comprobación `skipped` es neutra: significa que el plano no se solicitó o
que el artefacto no existe en este host, no que se haya verificado.

## Garantías

- No se inicia, detiene, recarga ni reconfigura ningún servicio.
- No se ejecuta Docker, nftables, KVM/libvirt, systemd ni ningún comando del
  sistema; las unidades se leen como texto y nunca se le piden a systemd.
- Las bases SQLite se abren en modo `?mode=ro` con `PRAGMA query_only=ON`; una
  base ausente nunca se crea.
- Los ficheros de entorno se describen únicamente por los **nombres** de sus
  ajustes permitidos. Los valores, contraseñas, tokens y claves no se
  materializan en el informe.
- El gate de activación sigue siendo fail-closed: `activation_performed` es
  siempre `false` y un bundle v1 nunca autoriza una celda.

## Huecos declarados

`runtime.backup.UNCOVERED_RUNTIME_STATE` enumera el estado que existe en un host
aprovisionado y que la tabla de backup **no** cubre, para que un operador vea el
hueco en lugar de suponer que el backup cubre todo el host:

- `sensor/spool.db`: telemetría en cola; se drena, no se restaura.
- `sensor/token`, `sensor/ca.crt`: material secreto/TLS del host.
- `sensor.env`, `ingest.env`: entorno de los servicios, no estado de control.
- `cells/`, `honeypots/`: datos de carga operativa, no del plano de control.

El informe también compara las rutas de las unidades desplegadas con la tabla
de backup. Una ruta de `/var/lib/dystopia` o `/etc/dystopia` que no sea ni
artefacto cubierto ni hueco declarado se clasifica como `unaccounted` y hace
fallar `verify`.

## Validación

```text
python -m pytest tests/ops-integration
python -m ruff check runtime tests/ops-integration
python -m pyright runtime/backup.py runtime/cell_gate.py runtime/cli.py runtime/ops.py
```

Los tests usan raíces sintéticas y bases SQLite con los esquemas reales de
`runtime`, de modo que el informe se ejercita sin servicios ni privilegios.

## Pendiente de Linux real

Esta integración **no** sustituye una validación en el host Linux:

- leer rutas `0600` propiedad de las cuentas de servicio requiere ejecutar el
  informe con privilegios suficientes (solo lectura);
- las evidencias de `cells gate` deben generarse en el host real con su
  manifiesto firmado; aquí solo se consume un directorio de evidencias;
- las garantías de systemd, nftables, KVM, Docker y Elastic no se comprueban
  desde este informe: pertenecen a sus propios contratos y a la validación de
  laboratorio.
