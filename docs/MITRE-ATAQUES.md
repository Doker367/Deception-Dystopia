# MITRE ATT&CK — referencia para el análisis de señuelos

Esta ficha se indexa en la memoria del RAG. Sirve para que el modelo use el
**nombre correcto** de cada técnica y no invente tácticas. La asignación es
una inferencia a partir de la evidencia observada, no una atribución.

| ID | Técnica | Táctica | Evidencia típica en Dystopia |
|---|---|---|---|
| **T1110** | Brute Force | Credential Access | Muchos `login_attempt` desde una IP, usuarios repetidos (`root`, `admin`), herramientas como `hydra` o `medusa` |
| **T1078** | Valid Accounts | Initial Access / Persistence / Privilege Escalation / Defense Evasion | `login_success` en un señuelo, uso de credenciales que parecen válidas |
| **T1190** | Exploit Public-Facing Application | Initial Access | `http_request` a rutas administrativas o vulnerables (`/admin`, `/wp-login.php`, `/.env`) |
| **T1046** | Network Service Discovery | Discovery | `connect` o `scan` contra varios puertos/servicios desde el mismo origen |
| **T1059** | Command and Scripting Interpreter | Execution | `command` capturado en Cowrie u otro señuelo (`uname -a`, `whoami`, `bash -i`) |
| **T1105** | Ingress Tool Transfer | Command and Control | Descargas con `wget`/`curl` o transferencia de binarios al señuelo |

## Cómo citarlo

- T1110 es **fuerza bruta**, no exfiltración ni "exfiltración de credenciales".
- T1046 es **descubrimiento de servicios de red**, no "recopilación de datos".
- T1078 es **cuentas válidas**; un login aceptado en un señuelo no confirma por
  sí solo que el atacante tenga credenciales reales del entorno productivo.
- T1190 es **explotación de una aplicación expuesta**; una petición HTTP a
  `/admin` es un indicio, no una explotación confirmada.
- T1105 es **transferencia de herramientas**, no ejecución (esa es T1059).

## Límites

La técnica se infiere de eventos normalizados y puede estar equivocada. Una IP
observada no prueba la identidad del atacante. La clasificación es asesora:
requiere revisión humana y nunca autoriza bloqueo o aislamiento automático.
