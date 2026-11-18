# IA local y RAG de ataques

Memoria local para que un modelo abierto ayude a **examinar los ataques
capturados por los señuelos**, con evidencia citable y sin servicios externos.
La capa es opcional, asesora y fail-closed: si el modelo o el índice no están,
Dystopia sigue funcionando con sus reglas.

> Esta capa **no** sustituye a la analítica SQLite, al filtro de falsos
> positivos (`app/services/deception/fp_svc.py`) ni a Laya
> (`docker-compose.ai.yml`). Laya sigue siendo el motor de decisiones tipadas;
> el RAG es memoria y explicación.

## Cómo leer la pantalla (para quien no es experto)

- **Memoria**: son los eventos y documentos que la IA tiene preparados para
  consultar. “Documentos en memoria” indica cuántos hay y en cuántos trozos de
  texto se dividieron para poder buscarlos.
- **Alerta o sospecha**: una pista que la IA quiere que revises. No es una
  prueba, no confirma un ataque y no bloquea nada.
- **Buscar**: por defecto consulta ataques reales; los filtros permiten ver
  notas o documentación. Cada resultado muestra un resumen legible y deja el
  texto técnico dentro de “Ver detalle técnico”.
- **Confianza**: cuánto se parece lo observado a un patrón de ataque conocido.
  No es una probabilidad matemática ni una orden.
- **Aciertos al alertar (precisión)**: de las alertas que una persona revisó,
  cuántas eran ataques reales. Más alto significa menos ruido.
- **Ataques detectados (cobertura)**: de los ataques etiquetados, cuántos
  encontró. Más alto significa que se le escapan menos.
- **Qué nunca hace**: no bloquea, no aísla, no borra eventos y no silencia
  alertas. Confirmar, descartar o contener siempre es una decisión humana.

## 1. Qué modelo usar en esta máquina

Hardware medido: RTX 5070 Ti **16 GB**, Ryzen 7 7700X, 30 GB de RAM,
610 GB libres.

| Modelo | Peso Q4 | KV @ contexto | VRAM total | ¿Holgado? |
|---|---|---|---|---|
| **DeepSeek-V4-Pro-Qwen3.5-9B-UNCENSORED-heretic** | 5.63 GB | ~1.1 GB @64k | **~8 GB** | Sí, sobran ~8 GB |
| Qwen3-14B-Instruct | 9.0 GB | ~2.6 GB @32k | ~12.6 GB | Sí, justo |
| GPT-OSS-20B | 12.1 GB | ~1.5 GB @32k | ~14 GB | No |
| Mistral Small 24B | 14.3 GB | — | >16 GB | No entra |

**Recomendación primaria:** el 9B híbrido (atención completa cada 4 capas, 262k
nativos, español, tool-calling, Apache-2.0). A 64k deja VRAM libre y entiende
comandos ofensivos sin negarse.

**Segundo voto:** `Qwen3-14B-Q4_K_M` (ya está en `~/ia/models/`) para casos
ambiguos. Es más predecible citando y calibrando, pero deja menos VRAM.

Advertencias del 9B `heretic/abliterated`:

- La ablación reduce rechazos, pero puede degradar JSON estricto, citas y
  calibración. Validá con el set de evaluación antes de confiar en `triage`.
- Es un modelo de razonamiento: genera cadena de pensamiento. El cliente envía
  `enable_thinking=false` en la plantilla Qwen; si tu versión no lo soporta,
  arrancá con `--reasoning-format none`.
- No uses 262k de contexto para RAG: el prompt real ronda 3–6k tokens.

**Embeddings:** `Qwen3-Embedding-0.6B` (1024 dims, multilingüe, 32k). No uses
`bge-small-en-v1.5`: es solo inglés y 512 tokens. Alternativa: `bge-m3`
(1024 dims).

### Arranque de los dos servidores

Primero detené el `llama-server` actual de 262k si sigue ocupando 12 GB.
Dos servidores compiten por la misma VRAM. Los modelos escuchan en `0.0.0.0`
y un firewall limita `8081`/`8091` a `127.0.0.0/8` y a la subred del control
(`dystopia-local_default`). El control los alcanza por `host.docker.internal`
(`host-gateway`); el monitor, en `network_mode: host`, por `127.0.0.1`.

```bash
# 1) Modelo generativo del RAG (puerto 8091, ~7-8 GB)
/home/doker/llama.cpp/build/bin/llama-server \
  --model /home/doker/models/DeepSeek-V4-Pro-Qwen3.5-9B-UNCENSORED-heretic-Q4_K_M.gguf \
  --alias her-9b \
  --host 0.0.0.0 --port 8091 \
  --ctx-size 65536 --n-gpu-layers 99 --flash-attn on \
  --cache-type-k q8_0 --cache-type-v q8_0 \
  --parallel 1 --threads 8 --jinja --reasoning-format none

# 2) Embeddings (puerto 8081, ~0.5 GB)
/home/doker/llama.cpp/build/bin/llama-server \
  --model /home/doker/models/Qwen3-Embedding-0.6B-Q8_0.gguf \
  --alias qwen3-embedding-0.6b \
  --host 0.0.0.0 --port 8081 \
  --embeddings --pooling last -c 8192 -b 8192 -ub 8192 \
  --n-gpu-layers 99 --flash-attn on
```

Descarga:

```bash
huggingface-cli download Sakura721/DeepSeek-V4-Pro-Qwen3.5-9B-UNCENSORED-heretic-GGUF \
  DeepSeek-V4-Pro-Qwen3.5-9B-UNCENSORED-heretic-Q4_K_M.gguf \
  --local-dir /home/doker/models
huggingface-cli download Qwen/Qwen3-Embedding-0.6B-GGUF \
  Qwen3-Embedding-0.6B-Q8_0.gguf --local-dir /home/doker/models
```

Si tu build de `llama-server` no acepta `--reasoning-format`, quitá esa opción
y agregá al prompt la instrucción de no mostrar razonamiento (ya está incluida).

## 2. Qué memoria indexa

| Ámbito | Fuente | Contenido |
|---|---|---|
| `event` | `deception.db` | Resumen por `(src_ip, hora)`: tipos, dispositivos, puertos, accesos, MITRE probable |
| `note` | `investigations.db` | Alias, clasificación, manejo, etiquetas y notas del analista |
| `knowledge` | `docs/**`, `README`, `SECURITY`, inventario | Runbooks, arquitectura, MITRE y contexto operativo |

Los eventos se agregan por hora, no se indexa el payload crudo. Con
`NETPULSE_RAG_INCLUDE_PAYLOAD=true` se añaden **muestras redactadas** de
usuarios, comandos y URLs (máximo 5 por grupo y 220 caracteres). Los secretos se
redactan siempre (`sanitize.py`).

Las fuentes se abren en **solo lectura**. Indexar nunca escribe en
`deception.db` ni en `investigations.db`.

## 3. Configuración

```bash
export NETPULSE_RAG_ENABLED=true
export NETPULSE_RAG_DB=/var/lib/dystopia/deception/rag.db
# En el host: 127.0.0.1. Dentro de un contenedor: host.docker.internal
# (con extra_hosts: "host.docker.internal:host-gateway").
export NETPULSE_RAG_EMBED_URL=http://127.0.0.1:8081/v1/embeddings
export NETPULSE_RAG_EMBED_MODEL=qwen3-embedding-0.6b
export NETPULSE_RAG_EMBED_DIM=1024
export NETPULSE_RAG_LLM_URL=http://127.0.0.1:8091/v1/chat/completions
export NETPULSE_RAG_LLM_MODEL=her-9b
export NETPULSE_RAG_LLM_DISABLE_THINKING=true
export NETPULSE_RAG_INCLUDE_PAYLOAD=false
```

Opcionales: `NETPULSE_RAG_TOP_K` (8), `NETPULSE_RAG_MIN_SCORE` (0.20),
`NETPULSE_RAG_CONTEXT_CHARS` (12000), `NETPULSE_RAG_MAX_VECTORS` (100000),
`NETPULSE_RAG_EVENT_DAYS` (90), `NETPULSE_RAG_KNOWLEDGE_DIRS` (rutas extra
separadas por `:`).

El proyecto **no carga `.env` automáticamente**; exportá las variables o
ponelas en el entorno del servicio.

## 4. Indexar y consultar

```bash
python3 scripts/rag_cli.py index --scope all
python3 scripts/rag_cli.py status

python3 scripts/rag_cli.py search "fuerza bruta SSH" --ip 203.0.113.9
python3 scripts/rag_cli.py ask "¿Qué hizo 203.0.113.9 anoche?" --ip 203.0.113.9
python3 scripts/rag_cli.py triage "Clasificá el caso de 203.0.113.9" --ip 203.0.113.9
```

La primera indexación de 20 000 eventos puede tardar; el embedder procesa por
lotes de 16. Reindexá con `--force` después de cambiar de modelo de embeddings.

### API

Todas las rutas requieren JWT; lectura con rol `viewer`.

| Método | Ruta | Rol | Uso |
|---|---|---|---|
| GET | `/api/ai/rag/status` | viewer | Estado y contadores |
| GET | `/api/ai/rag/search?q=...&src_ip=...` | viewer | Búsqueda híbrida |
| POST | `/api/ai/rag/ask` | viewer | Respuesta con citas |
| POST | `/api/ai/rag/triage` | viewer | Veredicto JSON |
| POST | `/api/ai/rag/index` | admin | Indexar fuentes |
| POST | `/api/ai/rag/feedback` | operator | Etiquetar TP/FP |
| GET | `/api/ai/rag/metrics` | viewer | Precisión y recall |

Ejemplo:

```bash
curl -s -X POST http://127.0.0.1:8082/api/ai/rag/triage \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"question":"Clasificá el caso","src_ip":"203.0.113.9","mode":"triage"}'
```

Si la pregunta se abre desde una ficha de atacante o de un acceso aceptado, se
puede enviar `include_movements: true` junto con `src_ip`. El servidor añade
como evidencia adicional un resumen acotado de las sesiones aceptadas, los
comandos ejecutados y la salida emulada del señuelo. Ese contexto se genera
siempre en el servidor desde la evidencia local; el navegador no puede inyectar
texto libre como si fuera evidencia.

## 4.1 Sección IA en la interfaz

Dystopia Web incorpora la vista **IA** (`#ai`) con cuatro pestañas:

- **Hallazgos**: lo que el monitor considera anómalo, con severidad, confianza,
  veredicto, evidencia y acciones “Marcar revisado”, “Confirmar ataque” y
  “Falso positivo”.
- **Consultar**: pregunta libre o triage estructurado, con IP opcional,
  citas `[n]` y fragmentos recuperados.
- **Memoria**: búsqueda híbrida con procedencia y similitud.
- **Evaluación**: TP/FP/FN/TN, precisión, recall y F1.

El botón **Activar avisos** pide permiso de `Notification` al navegador y
muestra los hallazgos nuevos mientras la pestaña esté abierta. Para push con la
pestaña cerrada se usan los canales del servidor (webhook, Telegram, Slack,
email o ntfy).

## 4.2 Monitor proactivo y push

`scripts/ai_monitor.py` lee eventos nuevos, elige candidatos con reglas
(volumen, logins fallidos, accesos aceptados, puertos, comandos sensibles),
consulta la memoria y pide un triage. Si el modelo falla, emite un hallazgo por
reglas. **Nunca bloquea ni suprime.**

```bash
# una pasada manual
NETPULSE_AI_MONITOR_ENABLED=true python3 scripts/ai_monitor.py --once --force

# bucle continuo
python3 scripts/ai_monitor.py --loop --interval 300
```

| Variable | Defecto | Uso |
|---|---|---|
| `NETPULSE_AI_MONITOR_ENABLED` | `false` | Habilita el monitor |
| `NETPULSE_AI_MONITOR_WINDOW_MIN` | `15` | Ventana de análisis |
| `NETPULSE_AI_MONITOR_MIN_EVENTS` | `8` | Umbral de volumen |
| `NETPULSE_AI_MONITOR_MIN_SCORE` | `3` | Puntuación mínima de reglas |
| `NETPULSE_AI_MONITOR_MIN_CONFIDENCE` | `0.55` | Confianza mínima para notificar |
| `NETPULSE_AI_MONITOR_COOLDOWN_MIN` | `180` | Silencio por IP |
| `NETPULSE_AI_MONITOR_NOTIFY_MIN_SEVERITY` | `medium` | Severidad mínima |

Push autoalojado con ntfy (sin SaaS):

```bash
export NETPULSE_NTFY_URL=http://127.0.0.1:8085
export NETPULSE_NTFY_TOPIC=dystopia-ia
```

También puedes declarar un webhook en `config/webhooks.json` suscrito al evento
`ai_finding`; recibirá un POST JSON con título, severidad, IP, veredicto,
confianza, MITRE y el aviso de que no se bloqueó nada.

Los hallazgos también se guardan en SQLite y se consultan con:

| Método | Ruta | Rol |
|---|---|---|
| GET | `/api/ai/rag/findings?limit=30&unacked=true` | viewer |
| POST | `/api/ai/rag/findings/{id}/ack` | operator |
| POST | `/api/ai/rag/scan` | admin |

### Servicios de usuario de esta máquina

Los modelos y el monitor están instalados como unidades de usuario:

```bash
systemctl --user daemon-reload
systemctl --user enable --now dystopia-ai-embed.service
systemctl --user enable --now dystopia-ai-llm.service
systemctl --user enable --now dystopia-ai-monitor.timer
systemctl --user status dystopia-ai-llm.service
journalctl --user -u dystopia-ai-monitor.service -n 50
```

El entorno vive en `~/.config/dystopia/ai.env` (0600). La unidad del monitor
usa `~/.venvs/dystopia-ai` (solo `httpx`). El control plane debe arrancar con
`NETPULSE_RAG_ENABLED=true` para que la API y la vista IA funcionen; si corre
en un contenedor, reinícialo con ese entorno.

## 5. Cómo evita falsos positivos y falsos negativos

No se puede garantizar cero de ambos a la vez con un modelo probabilístico. El
diseño separa las dos métricas y obliga a que un humano decida:

1. **Reglas primero.** El motor determinista y las allowlists siguen mandando.
   La IA nunca suprime una alerta (`suppress` es siempre `false`).
2. **Evidencia obligatoria.** Cada afirmación debe citar `[n]`; sin citas la
   respuesta se marca `grounded=false`.
3. **Abstención explícita.** Sin fragmentos recuperados, responde
   `EVIDENCIA INSUFICIENTE` y no llama al modelo.
4. **Triage conservador.** `benign` exige evidencia de escáner autorizado,
   health-check, backup o laboratorio. Ante la duda: `suspicious` o `unknown`.
5. **Sin bloqueo automático.** `recommended_actions` es una lista para que un
   humano valide; el firewall del control sigue en dry-run.
6. **Medición separada.** `POST /feedback` guarda `predicted` y la etiqueta
   humana (`true_positive`/`false_positive`). `/metrics` calcula precisión y
   recall por separado.

Protocolo mínimo:

- Reuní **30 casos reales o sintéticos etiquetados** por un analista.
- Ejecutá `triage` en cada uno y guardá `predicted` + etiqueta.
- Revisá `precision` (ruido) y `recall` (ataques que se escapan) por separado.
- Si priorizás no perder ataques, bajá el umbral o tratá `unknown` como
  positivo; aceptarás más falsos positivos.
- Si priorizás cero ruido, subí el umbral; aceptarás falsos negativos.
- Repetí la evaluación al cambiar modelo, embeddings o prompt, y reindexá.

## 6. Límites actuales

- El recorrido vectorial es lineal: `NETPULSE_RAG_MAX_VECTORS` corta a 100 000
  fragmentos. Para más volumen, migrar a `sqlite-vec` manteniendo el contrato.
- La búsqueda semántica se degrada a léxica si el embedder no responde; se
  informa `mode="keyword"`.
- El contexto enviado al modelo se recorta a `NETPULSE_RAG_CONTEXT_CHARS`
  (~12 000 caracteres por defecto, unos 3 000 tokens).
- La indexación por API es síncrona; para lotes grandes usá la CLI.
- Los eventos se agregan por hora: no es un historial evento por evento.
- Sin streaming: una respuesta puede tardar; timeout por defecto 120 s.
- El RAG no consulta NetBox, no ejecuta comandos y no modifica el firewall.

## 6.1 Puesta en marcha en esta máquina (2026-11-13)

- Modelos descargados: `~/models/DeepSeek-V4-Pro-Qwen3.5-9B-UNCENSORED-heretic-Q4_K_M.gguf`
  y `~/models/Qwen3-Embedding-0.6B-Q8_0.gguf` (≈8.9 GB de VRAM en total).
- Servicios de usuario activos: `dystopia-ai-llm.service` (8091),
  `dystopia-ai-embed.service` (8081) y `dystopia-ai-monitor.timer` (cada 5 min).
- Memoria de conocimiento ya indexada: 43 documentos y 906 fragmentos.
- El monitor usa `NETPULSE_DECEPTION_DATA_DIR` para localizar
  `deception.db`. Si el control plane corre en un contenedor o usa otro
  `DYSTOPIA_CONTROL_STATE`, ajusta esa ruta en `~/.config/dystopia/ai.env`;
  de lo contrario el monitor no verá eventos.
- **El control plane debe reiniciarse** con `NETPULSE_RAG_ENABLED=true` y las
  variables del bloque RAG. La web nueva (`web/dist`) también requiere que el
  servicio que sirve `/static/web/` use ese build.

> **Si el control corre en Docker** (`deploy/local/docker-compose.yml`), el
> evento DB vive en el volumen `deception_db` y la web va dentro de la imagen.
> La integración preparada usa `deploy/local/docker-compose.ai.yml`: el
> control conserva la red puente y alcanza los modelos por `host.docker.internal`
> (`host-gateway`); un
> contenedor `ai-monitor` con `network_mode: host` comparte el volumen
> `deception_db` y escribe la misma `rag.db` que lee la interfaz.
>
> `/usr/local/sbin/dystopia-up.sh` incluye este compose, así que el control
> siempre arranca con las variables RAG.
>
> La subred del compose puede cambiar entre recreaciones. Los modelos
> escuchan en `0.0.0.0`; el firewall solo permite `127.0.0.0/8` y la subred
> actual del control (`dystopia-local_default`, hoy `172.22.0.0/16`).
> `dystopia-up.sh` crea esas reglas en cada arranque.

> ```bash
> # Los modelos escuchan en 0.0.0.0 (unidades de usuario ya ajustadas)
> systemctl --user restart dystopia-ai-embed.service dystopia-ai-llm.service
>
> # Reconstruye la imagen (copia web/dist, scripts y docs) y reinicia
> sudo ./scripts/restart_ai_stack.sh
> ```
>
> El script valida los modelos, ejecuta los tres compose y muestra el estado.
> Si el control no alcanzara los modelos, revisa `host.docker.internal` y las
> reglas INPUT de 8081/8091; no uses una IP fija de subred Docker.

## 7. Diagnóstico

| Síntoma | Causa | Acción |
|---|---|---|
| 503 `RAG deshabilitado` | `NETPULSE_RAG_ENABLED` falso | Exportar `true` y reiniciar |
| 503 `no existe el índice` | Falta indexar | `rag_cli.py index --scope all` |
| 503 `embeddings no disponibles` | Servidor 8081 caído | Revisar `llama-server` y el puerto |
| Timeout o 503 en `/ask` desde el control | Modelos en otra subred o firewall | Usar `host.docker.internal` y permitir la subred del control en `8081`/`8091` |
| Panel sin variables RAG | Control arrancado sin `docker-compose.ai.yml` | Arrancar con `dystopia-up.sh` (ya incluye AI) y reiniciar |
| `grounded=false` | El modelo no citó | Revisar prompt/modelo; no confiar en la respuesta |
| `el modelo de embeddings cambió` | Índice incompatible | Reindexar con `--force` |
| Respuestas vacías o solo razonamiento | La plantilla ignoró `enable_thinking` y consumió `max_tokens` | Arrancar con `--reasoning-format none` o subir `NETPULSE_RAG_LLM_MAX_TOKENS` |
| OOM de VRAM | Contexto o modelo grande | Bajar `--ctx-size`, usar Q4, cerrar otros servidores |

## 5.1 Evaluación de la recuperación (scripts/eval_rag.py)

`scripts/eval_rag.py` mide la calidad del recuperador en un corpus
sintético determinista (semilla 20261115, sin red) y — con `--real` —
contra la base SQLite real. El corpus de calidad cubre seis dominios de
consulta: ataques por IP, credenciales capturadas, MITRE, dispositivos
señuelo, movimiento lateral y puertos; 15 casos en total.

| Métrica | Qué mide |
|---|---|
| `recall@8` | el fragmento gold aparece entre los 8 primeros |
| `citation_hit@1` | la cita `[1]` de la respuesta cae en el fragmento gold |
| `mrr` | media del inverso del puesto del gold |

Resultado medido con embedder sintético (bolsa de palabras, dim 128):

| Modo | recall@8 | citation_hit@1 | mrr |
|---|---|---|---|
| baseline (RRF puro) | 0.867 | 0.600 | 0.702 |
| RRF + señales (rerank) | 0.867 | **0.867** | **0.867** |

El reranking no cambia el recall (los candidatos ya incluyen el gold) pero
sí la calidad de la cita: sube de 0.60 a 0.867 la proporción de preguntas
cuya primera evidencia es el fragmento correcto. En la base real
(43 documentos, 906 fragmentos) las 6 consultas de conocimiento anotadas
aciertan al gold enpuesto 1 en ambos modos.

## 5.2 Reranking determinista y señales (tarea 2)

Tras la fusión RRF, `app/services/ai/rag/rerank.py` recalcula el orden con
señales baratas (todas en `[0, 1]`) y pesos configurables:

| Señal | Peso (env) | Defecto | Motivo |
|---|---|---|---|
| `rrf_norm` | `NETPULSE_RAG_RERANK_W_RRF` | 1.0 | domina: conserva el fusionado de ambas vías (léxico + semántico) |
| `exact` | `NETPULSE_RAG_RERANK_W_EXACT` | 0.35 | IP/puerto/usuario citado en la query es un identificador único: sube al fragmento que lo contiene |
| `proximity` | `NETPULSE_RAG_RERANK_W_PROXIMITY` | 0.25 | ventana mínima de términos: premisa de frase ("fuerza bruta SSH" contigua) |
| `recency` | `NETPULSE_RAG_RERANK_W_RECENCY` | 0.15 | eventos recientes pesan algo más; `tau` = `NETPULSE_RAG_RERANK_RECENCY_DAYS` (45 días) |

- `rrf_norm` es el score RRF del candidato normalizado por el máximo del
  pool: sin sesgo de volumen.
- `exact` detecta IPs (regex estricta), puertos (2-5 dígitos) y tokens de
  contenido; cuenta fracción de entidades de la consulta presentes.
- `proximity` usa ventana mínima que cubre todos los términos; 1/(1+extra).
- `recency` es `exp(-edad_días/tau)` con `tau` 45; documentos sin `ts`
  valen 0 (no penalizan conocimiento estable).
- Empates: desempate por `chunk_id` — orden estable y determinista.
- Desactivar todo: `NETPULSE_RAG_RERANK_ENABLED=false`, o pesos 0.

## 5.3 Citas validadas contra fragmentos recuperados (tarea 3)

La respuesta valida cada cita `[n]` con `answer.validate_citations`:

1. `[n]` fuera de rango (no hay evidencia n) se **descarta** y aparece en
   `dropped_citations`.
2. `[n]` que apunta a un `chunk_id` **no recuperado** por el híbrido se
   descarta: nunca se cita de memoria ni inventa fuente y figura en
   `dropped_citations`.
3. `citation_chunks` enumera los `chunk_id` recuperados que respaldan las
   citas válidas; `citations` mantiene el índice `[n]` (formato UI).
4. `grounded` queda `false` si tras validar no queda ninguna cita.

Test: `tests/test_ai_rag.py::test_citas_validadas_descarta_inventadas`.

## 5.4 Degradación y límites de escaneo (tareas 4 y 5)

- **Sin embedder** (o `embedder=None`): la búsqueda sigue léxica con
  `degraded=true` y `mode="keyword"`; la respuesta se abstiene si no hay
  evidencia. Test: `test_degradado_sin_embedder` y `..._nulo`.
- **Escaneo vectorial acotado**: `store.vector_search` recorre en lotes
  (`NETPULSE_RAG_SCAN_BATCH`, 2048 filas) y corta o degrada cuando la
  consulta supera `NETPULSE_RAG_SCAN_CAP` (defecto 20000):
  | Cap | p50 (10k chunk, dim 1024) | Cobertura |
  |---|---|---|
  | 250 | 4.9 ms | degrada (20k+ corpus) |
  | 2000 | 33.1 ms | degrada |
  | 5000 | 80.6 ms | degrada |
  | 10000 (índice completo) | 154.8 ms | híbrido completo |
  El coste es ≈15 ms por 1 000 fragmentos a 1024 dims; para superar el
  millón de fragmentos, migrar a `sqlite-vec` manteniendo el contrato.
- Latencias a 10 000 fragmentos (fake embedder, dim 1024, p50/p95):
  keyword 5.4/6.4 ms · vector 153.9/156.9 ms · híbrido RRF 159.2/163.2 ms ·
  híbrido + señales 159.1/163.4 ms. El reranking añade < 0.3 ms por
  consulta: opera solo sobre los ~24 candidatos, nunca sobre todo el índice.
