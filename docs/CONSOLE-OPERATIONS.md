# Consola operativa Dystopia — contratos y límites

La interfaz se sirve en `/` por el control plane FastAPI y usa JavaScript/CSS locales sin framework adicional. Se conservó la entrega estática existente: se sustituyeron valores ficticios y JS inline por un shell accesible y assets locales, sin cambiar de framework. **No es un plano de ejecución:** no arranca invitados, listeners, servicios, interfaces ni filtros. Abre la consola únicamente en loopback o tras un despliegue TLS aprobado.

## Capacidades verificadas en código

| Recurso | Contrato real | Alcance |
|---|---|---|
| Sesión | `POST /api/auth/login`, `GET /api/auth/me` | JWT vinculado a hash/rol actual; login con límite por IP del socket, sin confiar en cabeceras de proxy; token solo en `sessionStorage` (no URL). Al cerrar sesión se elimina del navegador. No hay revocación individual ni MFA. |
| Entorno y permisos | `GET /api/console/capabilities` | `NETPULSE_ENV=production` del instalador tiene precedencia; si no existe, `DYSTOPIA_ENVIRONMENT=laboratory|production` sirve para entorno local. Ausente/otro valor = `unconfigured`. La UI no cambia el entorno. |
| Celdas | `GET /api/console/cells`, `GET/POST/PUT /api/console/cells/{id}` | Borradores declarativos privados SQLite; revisión obligatoria en PUT. No se crea VM, red, identidad o sensor. El perfil es descriptivo, no una imagen preparada. |
| Validación | `POST /api/console/cells/{id}/validate` con `{revision}` | Comprueba solo sintaxis y presencia de campos. Respuesta contiene `scope=declarative_only`, versión/fecha y `activation_allowed=false`. No verifica que un sensor exista ni que una IP pertenezca al segmento. Cambio de borrador elimina la validación anterior transaccionalmente. |
| Operaciones | `GET /api/console/cells/{id}/history` | Registro transaccional en DB de celdas de actor, acción, revisión, resultado y fecha; sin payload/secretos. La auditoría HTTP separada puede degradarse y se indica en health. |
| Preparar/activar | `POST /api/console/cells/{id}/prepare|activate` | Siempre 409 `ActivationBlocked`; no se invoca libvirt/nft. |
| Eventos | `GET /api/console/events`, `/events/{sensor}/{event_id}`, `/activity`, `/events.csv` | Consulta sobre el socket Unix de `dystopia-query` con UID de control verificado; el control no recibe ruta ni permiso de BD. Sin socket/servicio: 503 con ID, no falso cero ni fallback. Solo metadatos permitidos; no payload capturado. |
| Auditoría | `GET /api/console/audit` | Solo admin, metadatos de audit privado; nunca detalles ni IP cliente. BD ausente/inaccesible: 503. |
| Usuarios | `/api/admin/users` | Creación/listado administrativos existentes; UI exige contraseña de 16+ caracteres. No hay gestión de sesiones o MFA. |
| Infraestructura | `GET /api/vms` | Solo registro de lectura. Sin indicador verificable de host/capacidad/conectividad. |
| Incidentes | — | **Sin correlación**. La vista no trata alertas como incidentes ni inventa severidad/confianza/responsables. |
| Sensores | CLI local `runtime.cli rotate-sensor|revoke-sensor` | Sin API administrativa de heartbeat, certificados o provisioning. UI muestra “no disponible”, nunca secretos existentes. |

### Seguridad de eventos

- Máximo 100 por página, cursor HMAC efímero y offset interno acotado a 10 000 sobre una marca de inserción estable; orden por recepción descendente, sensor e ID. Periodo de recepción por defecto 24 h, máximo 7 días. Filtros parametrizados: sensor, `device` (ID v1, no ID de celda), IP origen, tipo, protocolo y periodo con zona; filtros en URL solo como valores no secretos. Si se declara `device_id` en borrador se usa para correlación de consulta, **no** prueba asignación en el registro de sensores.
- CSV respeta los filtros, exporta como máximo 500 filas y antepone apóstrofo a texto cuyo primer carácter significativo podría activar una fórmula de hoja de cálculo (`=`, `+`, `-`, `@` o controles). La respuesta expone `X-Export-Truncated` y `X-Export-Rows`; el panel advierte si se truncó. No se interpreta como exportación completa más allá del límite.
- La UI usa `textContent` o HTML escapado para metadatos. El servidor no devuelve `payload`; enlaces/comandos capturados no se renderizan ni ejecutan.
- La lectura SQLite `mode=ro/query_only` ocurre exclusivamente en el proceso `dystopia-query`; el control usa socket Unix y mantiene `InaccessiblePaths` de ingestión. El puente está implementado en código, **no instalado ni verificado bajo identidades Linux reales**. Sin socket/DB/índice, 503 observable. No conceder al control acceso SQLite para “hacer funcionar” la gráfica. Ver [puente de consulta](<docs/QUERY-BRIDGE.md>) para permisos exactos, despliegue y límites.

## Matriz efectiva por rol

| Operación | Viewer | Operator | Admin | Pendiente del backend |
|---|---:|---:|---:|---:|
| Leer estado, celdas, eventos, registro VM | Sí | Sí | Sí | — |
| Validar campos de borrador | No | Sí | Sí | Verificación de contención real |
| Crear/editar borrador | No | No | Sí | — |
| Historial de celda | Sí | Sí | Sí | — |
| Crear usuarios / leer auditoría | No | No | Sí | Sesiones y MFA |
| Provisionar/revocar sensores desde UI | No | No | No | Solo CLI local revisado |
| Cuarentena desde UI | No | No | No | Backend seguro/autorización aún no conectados |
| Preparar/activar/arrancar VM | No | No | No | Verificador Linux independiente y lifecycle libvirt |

El CRUD heredado de usuarios usa YAML y no implementa una revisión optimista multiadministrador; evitar cambios simultáneos de cuentas hasta migrarlo a transacciones y probar contención. Todas las restricciones se vuelven a comprobar por API; ocultar un botón no es control de acceso. No hay bypass para activar producción. Acciones sensibles futuras requerirán reautenticación cuando exista contrato.

## Recorrido seguro de una celda

1. Autenticarse como admin; confirmar el entorno y el estado del backend en la barra superior. Si el entorno aparece “no configurado”, no presumir laboratorio ni producción.
2. En **Celdas**, crear borrador: ID estable, propósito, perfil, segmento, IP, ID de sensor previsto y `device_id` de telemetría v1, recursos y puertos deseados. El panel **no** provisiona el sensor ni la VM. No introducir secretos ni datos reales de producción en la descripción.
3. Revisar el resumen y guardar. Esperar respuesta 201/200; ante timeout se consulta el recurso antes de asumir fracaso o reenviar. La edición exige revisión exacta: un 409 indica conflicto y obliga a recargar.
4. Validar campos; leer alcance `declarative_only`, fecha y versión. Una modificación invalida ese resultado. En **Verificaciones** debe seguir figurando “contención no verificada”.
5. En **Eventos**, consultar el `device_id` v1; si el socket o el lector no están disponibles se ve 503 con ID de diagnóstico. La ausencia de eventos no prueba seguridad. Aplicar filtros y exportar CSV solo dentro del límite.
6. Preparación/activación siguen en 409 hasta contar con helper, verificación externa y ensayo autorizado de Linux/KVM/libvirt/nft. No intentar el arranque heredado para sortear el bloqueo.

## Estados que NO se inventan

El panel distingue carga, vacío confirmado, 401, 403, 503, desconexión, datos con más de dos minutos sin actualizar y mutación con resultado incierto. Las gráficas dependen del servicio de consulta real; sin socket o DB no muestran barras sintéticas. No hay inventario de hosts, estado de conexión del sensor, lag/cola central como API administrativa en vivo, ni servicio de incidentes. El porcentaje de “preparación” mostrado por versiones anteriores no representa ninguna medición y fue retirado.

## Pruebas visuales y operativas

La suite ASGI `tests/ui` pasa. En el laboratorio de evaluación se arrancó el
control con un estado temporal y se capturaron login, resumen, celdas y detalle
de celda a 1600×1000 con Chrome headless. El servicio de consulta no estaba
arrancado, por lo que las capturas muestran “datos no disponibles” en lugar de
inventar eventos.

En esa prueba se detectó y corrigió un fallo real del login: el manejador
asíncrono usaba `event.currentTarget` después de un `await`, cuando ya era
`null`, y lanzaba `Cannot read properties of null (reading 'reset')`. Ahora
captura el formulario antes del `await` y hay una prueba de regresión.

Siguen pendientes las comprobaciones de 1440, 1024 y 390 px, teclado, foco,
contraste, scroll y WCAG AA visual, además de repetir la prueba en Ubuntu 24.04
con UID distintos. Las capturas están en `docs/images/console-*.png`.
