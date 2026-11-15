import { expect, test, type Page } from "@playwright/test";

const IP = "203.0.113.9";

const evidence = {
  n: 1, chunk_id: 11, doc_key: `event:${IP}:2026-11-13T18`, kind: "event", source: "deception_events",
  src_ip: IP, ts: "2026-11-13T18", heading: `${IP} · 2026-11-13T18`,
  text: "Resumen de honeypot · 4 eventos, 2 intentos de login, 1 acceso aceptado, comando hydra.",
  score: 0.03, similarity: 0.71, matched_by: ["keyword", "vector"],
};

const status = {
  enabled: true, indexed: true, db: "/tmp/rag.db", docs: 42, chunks: 180,
  findings: 3, unacked_findings: 1, embedding_match: true,
  embed: { url: "http://127.0.0.1:8081/v1/embeddings", model: "qwen3-embedding-0.6b", dim: 1024 },
  llm: { url: "http://127.0.0.1:8091/v1/chat/completions", model: "her-9b", disable_thinking: true },
  limits: { top_k: 8, min_score: 0.2, context_chars: 12000, max_vectors: 100000, event_days: 90 },
  monitor: { enabled: true, window_min: 15, min_events: 8, min_confidence: 0.55, cooldown_min: 180, last_scan: "2026-11-13T18:30:00+00:00" },
  privacy: { include_payload: false },
};

const findings = {
  unacked: 1,
  items: [{
    id: 7, ts: "2026-11-13T18:25:00+00:00", src_ip: IP, verdict: "malicious",
    confidence: 0.91, severity: "critical", title: `Ataque probable · ${IP}`,
    summary: "12 intentos de login, un acceso aceptado y comando hydra. MITRE: T1110.",
    evidence: [evidence], model: "her-9b", source: "ai", notified: true, ack: false,
  }],
};

const metrics = {
  tp: 5, fp: 1, fn: 0, tn: 4, precision: 0.8333, recall: 1, f1: 0.9091, labeled: 10,
  note: "muestra pequeña: no interpretar sin al menos 30 casos etiquetados",
};

const answered = {
  mode: "analysis", question: "¿Qué hizo la IP?",
  answer: [
    "EN UNA FRASE: Se observan intentos de login y un acceso aceptado [1].",
    "QUÉ SE OBSERVÓ:",
    "- Varios intentos de login [1]",
    "- Un acceso aceptado [1]",
    "QUÉ SIGNIFICA: Es consistente con T1110 (fuerza bruta de contraseñas) [1].",
    "QUÉ HACER: Revisa el acceso aceptado y las credenciales usadas.",
  ].join("\n"),
  abstained: false, grounded: true, citations: [1], evidence: [evidence],
  model: "her-9b", retrieval: { mode: "hybrid", degraded: false, count: 1 },
};

const eventEvidence = {
  n: 1, chunk_id: 12, doc_key: `event:${IP}:2026-11-12T05`, kind: "event", source: "deception_events",
  src_ip: IP, ts: "2026-11-12T05", heading: `${IP} · 2026-11-12T05`,
  text: [
    `Qué pasó: 4 eventos desde ${IP} contra srv-files-01; 0 accesos aceptados.`,
    `Resumen de honeypot · origen ${IP} · 2026-11-12T05:00 UTC`,
    "Eventos observados: 4",
    "Dispositivos señuelo: srv-files-01 (4)",
    "Tipos: conexiones=1, intentos de acceso=3",
    "Protocolos: ssh=4",
    "Destinos: 2222/ssh=4",
    "Accesos aceptados en señuelo: 0",
    "MITRE ATT&CK probable (inferido, no confirmado): T1046 Network Service Discovery (Discovery)",
  ].join("\n"),
  score: 0.02, similarity: 0.43, matched_by: ["vector"],
};

const searched = { query: "fuerza bruta", mode: "hybrid", degraded: false, results: [eventEvidence] };

const analytics: Record<string, unknown> = {
  "/api/analytics/health": { collector: { status: "ok" } },
  "/api/analytics/overview": {
    total_events: 0, unique_sources: 0, alerts: 0, max_severity: "info",
    latest_event: null, protocols: [], datasets: [],
  },
  "/api/analytics/timeline": { interval: "1h", buckets: [] },
  "/api/analytics/origins": { origins: [], unlocated: 0 },
  "/api/analytics/events": { total: 0, items: [] },
  "/api/analytics/campaigns": { campaigns: [] },
};

function fakeToken() {
  const payload = { sub: "e2e", role: "admin", exp: Math.floor(Date.now() / 1000) + 3600 };
  return `e2e.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.e2e`;
}

test.beforeEach(async ({ page }) => {
  await page.addInitScript((token: string) => {
    window.localStorage.setItem("dystopia.access_token", token);
  }, fakeToken());

  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (path === "/api/auth/login") {
      await route.fulfill({ json: { access_token: fakeToken() } });
      return;
    }
    if (path === "/api/ai/rag/status") return route.fulfill({ json: status });
    if (path === "/api/ai/rag/findings") return route.fulfill({ json: findings });
    if (path === "/api/ai/rag/metrics") return route.fulfill({ json: metrics });
    if (path === "/api/ai/rag/search") return route.fulfill({ json: searched });
    if (path === "/api/ai/rag/ask" || path === "/api/ai/rag/triage") {
      return route.fulfill({ json: answered });
    }
    if (path === "/api/ai/rag/scan") {
      return route.fulfill({ json: { findings: 1, notified: 1, candidates: 2 } });
    }
    if (path === "/api/ai/rag/index") {
      return route.fulfill({ json: { docs: 1, chunks: 2, skipped: 0 } });
    }
    if (Object.hasOwn(analytics, path)) return route.fulfill({ json: analytics[path] });
    return route.abort("blockedbyclient");
  });
});

async function openAi(page: Page) {
  await page.goto("/#ai");
  await expect(page.getByRole("heading", { name: "IA de análisis" })).toBeVisible();
}

test("explica el propósito de la IA en lenguaje claro", async ({ page }) => {
  await openAi(page);
  await expect(page.getByRole("region", { name: "Cómo funciona la IA" })).toBeVisible();
  await expect(page.getByText("Lee lo que pasó")).toBeVisible();
  await expect(page.getByText("3. Tú decides", { exact: true })).toBeVisible();
  await expect(page.getByText("solo aconseja · nunca bloquea")).toBeVisible();
});

test("muestra hallazgos, evidencia y acciones de revisión", async ({ page }) => {
  await openAi(page);
  await expect(page.getByText(`Ataque probable · ${IP}`)).toBeVisible();
  await expect(page.getByText("sin revisar", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: /Ver de dónde sale/ }).click();
  await expect(page.getByText(/4 eventos, 2 intentos de login/).first()).toBeVisible();
  await expect(page.getByRole("button", { name: /Buscar amenazas ahora/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /Actualizar memoria/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /Preguntar por esta IP/ })).toBeVisible();
});

test("consulta la memoria y exige citas", async ({ page }) => {
  await openAi(page);
  await page.getByRole("tab", { name: "Preguntar" }).click();
  await page.getByLabel("¿Qué quieres saber?").fill("¿Qué hizo 203.0.113.9?");
  await page.getByRole("button", { name: /^Preguntar$/ }).click();
  await expect(page.getByText("respuesta basada en fuentes")).toBeVisible();
  await expect(page.getByText("EN UNA FRASE")).toBeVisible();
  await expect(page.getByText("QUÉ HACER", { exact: true })).toBeVisible();
  await expect(page.getByText(/Es consistente con T1110/)).toBeVisible();
  await expect(page.locator(".ai-cite").first()).toHaveText("[1]");
});

test("busca en la memoria con procedencia", async ({ page }) => {
  await openAi(page);
  await page.getByRole("tab", { name: "Buscar" }).click();
  await page.getByRole("button", { name: /^Buscar$/ }).click();
  await expect(page.getByText(/Se registraron 4 eventos desde esta IP contra srv-files-01/)).toBeVisible();
  await expect(page.getByText("sin accesos aceptados")).toBeVisible();
  await expect(page.getByText(/T1046 · escaneo de red/)).toBeVisible();
  await expect(page.getByText("parecido 43%")).toBeVisible();
});

test("muestra precisión y cobertura por separado", async ({ page }) => {
  await openAi(page);
  await page.getByRole("tab", { name: "Calidad" }).click();
  await expect(page.getByText("Aciertos (era ataque)")).toBeVisible();
  await expect(page.getByText("Ataques que se escaparon")).toBeVisible();
  await expect(page.getByText("83%")).toBeVisible();
  await expect(page.getByText("100%")).toBeVisible();
  await expect(page.getByText(/no interpretar sin al menos 30 casos/i)).toBeVisible();
});
