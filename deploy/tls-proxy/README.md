# TLS y reverse proxy de gestión

Plantillas versionadas para publicar Kibana a través de TLS, sin publicar
Elasticsearch, y para ofrecer opcionalmente un endpoint separado del control
plane. **No despliegan servicios ni cambian versiones de Elastic.** Elegir
Caddy o nginx, no ejecutar ambos sobre los mismos puertos.

## Topología y nombres esperados

Valores de documentación que deben sustituirse por los DNS/IP aprobados:

| Servicio | Nombre esperado | Escucha por defecto | Destino local |
|---|---|---|---|
| Kibana analítica | `kibana.mgmt.example.invalid` | `127.0.0.1:8443` TLS | `127.0.0.1:5601` TLS |
| Control plane (opcional) | `control.mgmt.example.invalid` | `127.0.0.1:9443` TLS | `127.0.0.1:8082` HTTP loopback |
| Proxy del host | IP de gestión aprobada, por ejemplo `192.0.2.40` | Sin bind remoto por defecto | Elasticsearch no es destino del proxy |

`example.invalid` y `192.0.2.40` son placeholders reservados, no direcciones
reales. El DNS debe resolver al host del proxy, y los SAN del certificado deben
incluir todos los DNS/IP que usarán los clientes. Kibana y Elasticsearch
continúan publicados por Compose solo en loopback; el puerto 9200 no se enruta
ni aparece como upstream.

## TLS y certificados

El TLS de entrada es obligatorio: las plantillas solo crean listeners `https`
o `ssl` y no ofrecen listener HTTP. Kibana también usa TLS en el salto local
proxy→Kibana, validado contra la CA de Elastic. `config/kibana/kibana.yml` deja TLS preparado para el despliegue Linux, cuando el
proxy y Kibana se muevan a HTTPS. En el laboratorio canónico actual el
fake `KIBANA_PUBLIC_BASE_URL` sigue apuntando a HTTP para no romper el import.
`deploy/elastic/scripts/generate-certs.sh`; el `.env` del despliegue debe fijar
`KIBANA_PUBLIC_BASE_URL` al URL HTTPS del proxy cuando se habilita TLS, por ejemplo
`https://kibana.mgmt.example.invalid:8443`.

Para certificados de entrada de laboratorio/gestión (la clave de CA queda en
la máquina que los genera):

```bash
PROXY_CERT_DIR=/etc/dystopia/tls-proxy/certs \
  ./deploy/tls-proxy/generate-certs.sh \
  kibana.mgmt.example.invalid control.mgmt.example.invalid 192.0.2.40
```

El script crea CA local y hoja con SAN DNS/IP. Para producción, es preferible
usar una CA corporativa o certificados emitidos por la PKI aprobada. Distribuir
solo `proxy-ca.crt` a clientes confiables; **nunca** distribuir
`proxy-ca.key`. El certificado backend de Kibana y su CA provienen de la
carpeta privada `ELASTIC_CERTS_DIR`; copiar únicamente `ca.crt` a
`/etc/dystopia/elastic/certs/ca.crt` para que el proxy verifique Kibana.

El script crea su directorio `0700`, claves privadas `0600` y certificados
públicos `0644`. Si el daemon no corre como root, ajustar propietario/grupo y
directorio a `0750`/clave a `0640` para lectura exclusiva del servicio. La clave
privada de la CA debe quedar offline y con respaldo controlado. No usar `777`,
no versionar `.env`, claves, certificados generados ni credenciales. Los artefactos del
script quedan en `deploy/tls-proxy/certs/`, ignorado por Git.

## Restricción de red

- El bind por defecto es `127.0.0.1` en los dos proxies. Para acceso remoto,
  usar túnel SSH/VPN o cambiar el bind **solo** a la IP de una interfaz de
  gestión/analítica dedicada. No usar `0.0.0.0`.
- Al habilitar una interfaz remota, restringir por CIDR con firewall del host
  y ACL de red: permitir 8443 solo a analistas autorizados y 9443 solo a
  administradores. En nginx añadir `allow <CIDR>;` y `deny all;` a cada
  virtual host. En Caddy, adaptar el matcher `remote_ip` al CIDR aprobado y
  verificarlo junto al firewall antes de cambiar `bind`.
- No publicar el puerto del servicio Kibana directamente; el único endpoint
  de analítica permitido es el TLS proxy. No añadir una ruta/upstream para
  Elasticsearch. `/api/status` de Kibana pasa por el proxy; `/api/deception`
  y sus subrutas devuelven 404 y nunca se envían al control plane.
- El control plane es opcional, en otro puerto y hostname. Las plantillas
  reducen retención de datos: access log deshabilitado, sin caché, respuestas
  `no-store`, sin identificadores del cliente reenviados al backend y con las
  rutas `/api/deception/*` denegadas. Esto es minimización técnica, **no una
  garantía de cumplimiento GDPR**: hay que definir responsable, base legal,
  retención, acceso y auditoría de la instalación real.

HSTS (`max-age=31536000`) está únicamente en los virtual hosts TLS. No activar
HSTS en una configuración HTTP; antes de publicarlo, verificar TLS real y el
certificado con los clientes previstos. Se omiten `includeSubDomains` y
`preload` para no imponer la política a dominios no revisados.

## Instalación (pendiente en Linux; no ejecutada aquí)

En el entorno de preparación no estaban instalados `nginx`, `caddy` ni
`pytest`, y no había acceso de red para instalar los validadores. Se comprobó
la estructura de bloques/directivas nginx y los bloques/strings Caddy con los
checks estáticos del test, pero eso no sustituye `nginx -t` ni `caddy
validate`. Los YAML modificados se parsearon con Ruby/Psych y el generador se
validó con `bash -n` y una emisión/verify de certificado temporal con OpenSSL.
Los nueve contratos nuevos se ejecutaron directamente con Python; la ejecución
del runner pytest queda pendiente en CI/Linux.

1. Revisar DNS, direcciones de interfaz de gestión, CIDR analíticos,
   propietarios y reglas de firewall. Asegurar que Compose conserva los binds
   localhost de Kibana y Elasticsearch.
2. Preparar los certificados de Elastic con el flujo existente y la hoja del
   proxy con el SAN correcto. Habilitar TLS de Kibana y fijar
   `KIBANA_PUBLIC_BASE_URL` en `deploy/elastic/.env` (fuera de Git).
3. Instalar **una** alternativa: `Caddyfile` como
   `/etc/dystopia/tls-proxy/Caddyfile`; o `nginx.conf` como
   `/etc/nginx/nginx.conf` (o integrar sus bloques en la configuración
   existente) y `kibana.conf`, `kibana-proxy-headers.conf` y `control.conf`
   bajo `/etc/dystopia/tls-proxy/`. Ajustar nombres DNS y rutas de certificado.
4. En el Linux objetivo ejecutar `nginx -t -c /etc/nginx/nginx.conf` y/o
   `caddy validate --config /etc/dystopia/tls-proxy/Caddyfile`; comprobar los
   listeners con `ss -lntp`, las ACL/firewall y
   `curl --cacert <proxy-ca.crt> https://<nombre>:8443/api/status`.
5. Confirmar desde un cliente no autorizado que no hay conexión; desde un
   autorizado validar autenticación de Kibana, cabeceras, rechazo de
   `/api/deception/*`, ausencia de caché/logs sensibles y que 9200 no es
   accesible desde la red.
6. Configurar rotación/renovación, confianza de CA, backups y retención de
   logs. Documentar evidencias, permisos y rollback antes de abrir el acceso.

**Riesgo:** exponer Kibana/control sin TLS permite interceptar sesiones,
credenciales y datos analíticos; exponerlos sin ACL amplía el acceso al panel y
los eventos de honeypots. No abrir el proxy hasta completar los pasos de Linux.

## Rutas versionadas

- `deploy/tls-proxy/README.md`: esta guía.
- `deploy/tls-proxy/Caddyfile`: alternativa Caddy.
- `deploy/tls-proxy/nginx.conf`: configuración raíz de nginx.
- `deploy/tls-proxy/kibana.conf`: proxy TLS de Kibana y bloqueo de rutas del
  control plane.
- `deploy/tls-proxy/kibana-proxy-headers.conf`: validación TLS del upstream
  Kibana y cabeceras de proxy.
- `deploy/tls-proxy/control.conf`: proxy TLS opcional de control con
  minimización GDPR.
- `deploy/tls-proxy/generate-certs.sh`: CA local/hoja con SAN DNS o IP.
- `tests/deploy/test_tls_proxy_config.py`: contratos de red, TLS, rutas y
  headers de configuración.
