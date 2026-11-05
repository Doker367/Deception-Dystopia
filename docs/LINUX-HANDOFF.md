# Handoff al servidor Linux — checklist de la primera ola

Este documento es la lista de trabajo para cuando esté disponible el servidor
Ubuntu 24.04. No sustituye a
[`HARDENING-OPERATIONS.md`](HARDENING-OPERATIONS.md): la resume en orden de
ejecución y define qué evidencias hay que recoger antes de abrir la red señuelo.

## 0. Antes de tocar el servidor

- [ ] Confirmar hardware: CPU con virtualización, RAM, discos y NIC.
- [ ] Confirmar que la máquina puede reinstalarse o revertirse.
- [ ] Definir IP de gestión, IP señuelo, VLANs y rutas permitidas.
- [ ] Reservar DNS/NTP y salida HTTPS para imágenes/actualizaciones.
- [ ] Tener acceso a consola/IPMI o recuperación fuera de banda.
- [ ] Crear el gestor de secretos y decidir quién custodia cada credencial.
- [ ] Preparar bundle offline de Python, lock con hashes y artefactos aprobados.
- [ ] Fijar el commit exacto de Dystopia que se va a desplegar.
- [ ] Revisar licencias, avisos de dependencias y SBOM.

## 1. Base del sistema

- [ ] Instalar Ubuntu Server 24.04 LTS mínimo, sin escritorio.
- [ ] Configurar SSH por clave y restringir origen de gestión.
- [ ] Configurar hora, zona horaria y NTP.
- [ ] Actualizar el sistema base y reiniciar si corresponde.
- [ ] Crear usuario administrador local y usuario de servicio.
- [ ] Verificar disco, RAM, `ulimit`, `vm.max_map_count` y reloj.
- [ ] No abrir todavía los puertos de honeypots.

## 2. Artefactos y directorios

- [ ] Copiar el repo en el commit acordado.
- [ ] Copiar el bundle offline y verificar hashes.
- [ ] Crear `/etc/dystopia`, `/var/lib/dystopia` y subdirectorios.
- [ ] Verificar propietarios y permisos; no usar `777`.
- [ ] Instalar unidades systemd desde `deploy/systemd/`.
- [ ] Verificar que no haya servicios heredados ni listeners abiertos.

## 3. Plan de instalación

- [ ] Ejecutar:

```bash
python3 -m runtime.install --dry-run --config deploy/install.example.json
```

- [ ] Revisar `write_units`, `create_directories`, `ownership`, `network_changes`
  y `activation`.
- [ ] Confirmar que `network_changes` está vacío y `activation` bloqueado.
- [ ] Guardar la salida como evidencia.
- [ ] No ejecutar `apply` hasta tener autorización explícita.

## 4. Control, ingesta y consulta

- [ ] Aplicar la instalación aprobada.
- [ ] Crear el primer administrador local con `bootstrap-admin`.
- [ ] Arrancar `dystopia-control`, `dystopia-query.socket` y servicios asociados.
- [ ] Verificar `/api/health` y el socket Unix.
- [ ] Comprobar `systemctl status` y logs sin secretos.
- [ ] Verificar que el control no abre la red señuelo.

## 5. Elasticsearch y Kibana

- [ ] Preparar `.env` real fuera del repo y con permisos `0600`.
- [ ] Generar certificados y proteger la CA.
- [ ] Arrancar ES/Kibana con el perfil `deception-elastic`.
- [ ] Ejecutar `bootstrap-security.sh --all`.
- [ ] Verificar roles, usuarios, API key, ILM y data streams.
- [ ] Importar el bundle Kibana con `overwrite=true`.
- [ ] Verificar 53/53 objetos y los 7 dashboards.
- [ ] Añadir TLS/reverse proxy para Kibana antes de exposición.

## 6. Red y honeypots

- [ ] Aplicar nftables y routing aprobados.
- [ ] Verificar aislamiento de gestión y salida a Internet.
- [ ] Desplegar una sola celda de laboratorio.
- [ ] Construir y arrancar los honeypots aprobados.
- [ ] Confirmar que solo están expuestos los puertos del perfil.
- [ ] Verificar logs nativos y normalización.
- [ ] No habilitar más celdas hasta validar la primera.

## 7. E2E mínimo

- [ ] Generar un evento sintético contra la celda autorizada.
- [ ] Verificar sensor → ingesta → normalización → publicador.
- [ ] Verificar `event.id` y duplicado `409`.
- [ ] Verificar writer sin lectura y analyst sin escritura.
- [ ] Verificar documento en `deception-events`.
- [ ] Verificar Discover y el dashboard de salud.
- [ ] Verificar que no se filtran credenciales ni payloads sensibles.

## 8. Evidencias que hay que guardar

- [ ] `uname -a`, `lsb_release -a`, CPU/RAM/disco.
- [ ] Salida del dry-run y del apply aprobado.
- [ ] `systemctl status` y `systemd-analyze verify`.
- [ ] `nft list ruleset` saneado.
- [ ] `docker compose ps` y versiones de imagen.
- [ ] Resultado de healthchecks y `/api/status`.
- [ ] Import Kibana y capturas de los dashboards.
- [ ] Prueba de escritura, duplicado, lectura y denegaciones.
- [ ] Logs de error sin secretos.
- [ ] Fecha, operador y commit desplegado.

## 9. Criterios de no-go

No abrir tráfico señuelo si ocurre cualquiera de estos:

- el dry-run no coincide con lo aprobado;
- hay listeners inesperados;
- falla la separación de roles;
- el control puede leer la base del sensor;
- Elasticsearch/Kibana no arrancan con TLS;
- el import de Kibana falla;
- no hay rollback probado;
- no hay consola de recuperación;
- se detectan secretos en logs o en el repo.

## 10. Rollback

- [ ] Detener servicios y contenedores.
- [ ] Retirar reglas nftables y rutas aplicadas.
- [ ] Restaurar configuración y unidades anteriores.
- [ ] Restaurar datos desde backup probado.
- [ ] Verificar que no quedan listeners ni procesos huérfanos.
- [ ] Documentar la causa y el estado final.

## 11. Después de la primera ola

- [ ] Snapshot/restore de Elasticsearch.
- [ ] Observabilidad y alertas de caída.
- [ ] Rotación de API keys.
- [ ] Runbook de incidentes.
- [ ] Revisión de seguridad y threat model.
- [ ] Prueba de carga y retención.
- [ ] Documentar resultados en `docs/RUNTIME-DATAPLANE.md`.
