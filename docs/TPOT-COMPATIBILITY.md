# Compatibilidad y relación con T-Pot

Dystopia toma como referencia el modelo de **T-Pot - The All In One Multi
Honeypot Platform** y reutiliza su enfoque de contenedores y Elastic Stack, pero
no es un clon ni pretende sustituirlo. Esta página deja claro qué se adopta, qué
se sustituye y qué queda fuera del MVP.

Referencia: <https://github.com/telekom-security/tpotce>

## Qué comparte Dystopia con T-Pot

- Honeypots desplegados como contenedores Docker.
- Elasticsearch + Kibana como plano de visualización.
- Normalización de eventos de distintos sensores a un contrato común.
- Separación entre honeypots, herramientas de análisis y servicios de gestión.
- Posibilidad de desplegar en una sola máquina o separar sensores.

## Qué cambia Dystopia

| Área | T-Pot | Dystopia |
|---|---|---|
| Ingesta | Logstash / EWSposter | Publicador propio idempotente por `event.id` |
| Contrato | Campos particulares de cada honeypot | ECS + bloque `dystopia.*` |
| Topología | Inventario de despliegue | Dystopia es la fuente de verdad de dispositivos y segmentos |
| Gestión | NGINX + Kibana + herramientas web | Control API, consola de solo lectura y Kibana |
| Honeypots | 20+ | 6 del MVP + OpenCanary |
| Datos | Envío comunitario por defecto en T-Pot | Sin envío comunitario; publicador explícito |
| Alcance | Plataforma completa de honeypots | Integración de deception con analítica y control |

## Honeypots de T-Pot y estado en Dystopia

Estados:

- **MVP:** adaptador, normalización y configuración versionada.
- **No incluido:** aparece en el ecosistema T-Pot, pero no está integrado en esta entrega.
- **Fuera de alcance:** requiere LLM o hardware específico.

| Honeypot | Estado en Dystopia |
|---|---|
| adbhoney | No incluido |
| beelzebub | Fuera de alcance: requiere LLM |
| ciscoasa | No incluido |
| citrixhoneypot | No incluido |
| conpot | No incluido |
| cowrie | **MVP** |
| ddospot | No incluido |
| dicompot | No incluido |
| dionaea | **MVP** |
| elasticpot | No incluido |
| endlessh | **MVP** |
| galah | Fuera de alcance: requiere LLM |
| go-pot | No incluido |
| glutton | No incluido |
| h0neytr4p | No incluido |
| hellpot | No incluido |
| heralding | **MVP** |
| honeyaml | No incluido |
| honeypots | No incluido |
| honeytrap | No incluido |
| ipphoney | No incluido |
| log4pot | No incluido |
| mailoney | No incluido |
| medpot | No incluido |
| miniprint | No incluido |
| redishoneypot | **MVP** |
| rdphoneypot | No incluido |
| sentrypeer | No incluido |
| snare | No incluido |
| tanner | No incluido |
| wordpot | No incluido |
| **opencanary** | **MVP de Dystopia**, no aparece en la lista actual de T-Pot |

## Herramientas de T-Pot y estado en Dystopia

| Herramienta T-Pot | Uso en T-Pot | Estado en Dystopia |
|---|---|---|
| Docker / Compose | Ejecutar honeypots y servicios | **Adoptado** para analítica y contenedores |
| Elastic Stack | Almacenar y visualizar eventos | **Adoptado** con ES/Kibana 9.3.5 |
| Logstash | Ingesta y transporte | Sustituido por publicador propio |
| NGINX | Reverse proxy y acceso web | Pendiente para TLS/proxy de producción |
| Kibana | Dashboards | **Adoptado** con 7 dashboards propios |
| Attack Map | Mapa animado de ataques | No incluido; el dashboard de mapa es estático |
| CyberChef | Análisis y transformación | No incluido |
| Elasticvue | Navegador de Elasticsearch | No incluido |
| Spiderfoot | OSINT | No incluido |
| Suricata | NSM | No incluido |
| Fatt | Extracción de metadatos pcap | No incluido |
| P0f | Fingerprinting pasivo | No incluido |
| Autoheal | Reinicio por healthcheck | No incluido |
| EWSposter | Envío comunitario | No incluido; publicación explícita |
| Ollama / ChatGPT | Honeypots LLM | Fuera de alcance |

## Requisitos y soporte

T-Pot documenta Hive con 16 GB de RAM y 256 GB SSD, y sensores con 8 GB y
128 GB. Dystopia usa esa referencia para el laboratorio completo, pero la cifra
final depende de retención, número de sensores y volumen de eventos.

| Entorno | Soporte Dystopia | Notas |
|---|---|---|
| Ubuntu Server 24.04 LTS + KVM/libvirt | Objetivo de producción | Pendiente de validación final en servidor |
| Ubuntu Server 24.04 sin KVM | Limitado | Control y analítica; no valida celdas |
| macOS con Docker Desktop/Colima | Evaluación | Solo plano analítico, contratos y dashboards |
| Windows con Docker Desktop | No validado | T-Pot lo documenta con limitaciones; Dystopia no lo certifica |
| ARM64 | No validado | No se afirma compatibilidad de imágenes |

## Qué no se debe afirmar

- Que Dystopia sustituye a T-Pot.
- Que integra los 20+ honeypots de T-Pot.
- Que el despliegue Linux ya está certificado.
- Que macOS/Windows sirven para producción.
- Que las herramientas no incluidas están disponibles por el simple hecho de
  compartir el ecosistema T-Pot.

## Atribución

T-Pot es un proyecto de Telekom Security y su comunidad. Dystopia reutiliza
conceptos y algunos honeypots, pero mantiene su propio contrato, publicador y
modelo de control. Las licencias de cada honeypot y herramienta pertenecen a sus
proyectos originales; consulte sus repositorios y la documentación de T-Pot.
