import { expect, test, type Page } from "@playwright/test";

// RFC 5737 documentation addresses only. The browser never contacts a real BFF.
const CA_IP = "203.0.113.7";
const TX_IP = "198.51.100.20";

const origins = {
  origins: [
    {
      countryCode: "US", country: "Estados Unidos", region: "California", regionCode: "CA",
      city: "Los Ángeles", ip: CA_IP, lat: 34.05, lng: -118,
      events: 2, uniqueSources: 1, severity: "high", protocol: "ssh", sensor: "cowrie",
      lastEvent: "2026-11-05T12:05:00+00:00",
    },
    {
      countryCode: "US", country: "Estados Unidos", region: "Texas", regionCode: "TX",
      city: "Austin", ip: TX_IP, lat: 30.27, lng: -97.74,
      events: 1, uniqueSources: 1, severity: "low", protocol: "ssh", sensor: "cowrie",
      lastEvent: "2026-11-05T12:01:00+00:00",
    },
  ],
};

const events = {
  total: 2,
  items: [
    {
      id: "evt_ca", timestamp: "2026-11-05T12:05:00+00:00", sensor: "cowrie",
      device: "test-sensor", source: CA_IP, country: "Estados Unidos", countryCode: "US",
      kind: "command", proto: "ssh", port: 22, action: "Comando ejecutado",
      severity: "high", message: "Evento sintético CA",
    },
    {
      id: "evt_tx", timestamp: "2026-11-05T12:01:00+00:00", sensor: "cowrie",
      device: "test-sensor", source: TX_IP, country: "Estados Unidos", countryCode: "US",
      kind: "connect", proto: "ssh", port: 22, action: "Conexión",
      severity: "low", message: "Evento sintético TX",
    },
  ],
};

const analytics: Record<string, unknown> = {
  "/api/analytics/health": { collector: { status: "ok" } },
  "/api/analytics/overview": {
    total_events: 3, unique_sources: 2, alerts: 0, max_severity: "high",
    latest_event: "2026-11-05T12:05:00+00:00", protocols: [], datasets: [],
  },
  "/api/analytics/timeline": { interval: "1h", buckets: [] },
  "/api/analytics/origins": origins,
  "/api/analytics/events": events,
};

test.beforeEach(async ({ page }) => {
  // Install interception before navigation: no fixture can fall through to Vite's /api proxy.
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/auth/login") {
      expect(route.request().method()).toBe("POST");
      expect(route.request().postDataJSON()).toEqual({ username: "lab", password: "e2e-only" });
      await route.fulfill({ json: { access_token: "e2e-only-session" } });
      return;
    }
    if (Object.hasOwn(analytics, path)) {
      await route.fulfill({ json: analytics[path] });
      return;
    }
    await route.abort("blockedbyclient");
    throw new Error(`Unmocked API request: ${path}`);
  });
});

async function loginAndOpenMap(page: Page) {
  await page.goto("/");
  await expect(page.getByRole("dialog", { name: "Conectar datos en vivo" })).toBeVisible();
  await page.getByLabel("Contraseña").fill("e2e-only");
  await page.getByRole("button", { name: "Iniciar sesión" }).click();
  await page.getByRole("button", { name: /Mapa global/ }).click();
  await expect(page).toHaveURL(/#map$/);
  await expect(page.getByRole("heading", { name: "Mapa global de ataques" })).toBeVisible();
  await expect(page.locator(".map-filter-bar .filter-count")).toHaveText("2 de 2 orígenes");
}

test("filtra California y Texas sin mezclar sus orígenes", async ({ page }) => {
  await loginAndOpenMap(page);
  const state = page.getByRole("combobox", { name: "Estado / región" });
  await expect(state.getByRole("option", { name: /California/ })).toBeAttached();
  await expect(state.getByRole("option", { name: /Texas/ })).toBeAttached();

  await state.selectOption("US|CA");
  await expect(page.locator(".map-filter-bar .filter-count")).toHaveText("1 de 2 orígenes");
  await expect(page.locator(".map-rank .rank-row")).toHaveCount(1);
  await expect(page.locator(".map-focus")).toContainText(CA_IP);
  await expect(page.locator(".map-rank")).not.toContainText("Texas");
  await expect(page.getByRole("img", { name: /1 origen y 1 región activa/ })).toBeVisible();

  await state.selectOption("US|TX");
  await expect(page.locator(".map-rank .rank-row")).toHaveCount(1);
  await expect(page.locator(".map-focus")).toContainText(TX_IP);
  await expect(page.locator(".map-rank")).not.toContainText("California");
});

test("el globo carga los polígonos US y no emite errores de consola", async ({ page }) => {
  const errors: string[] = [];
  page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
  page.on("pageerror", (error) => errors.push(error.message));
  const statesResponse = page.waitForResponse((response) => new URL(response.url()).pathname === "/us-states.geo.json");

  await loginAndOpenMap(page);
  const response = await statesResponse;
  expect(response.ok()).toBe(true);
  const geojson = await response.json();
  expect(geojson.features.some((feature: { properties: { code: string } }) => feature.properties.code === "CA")).toBe(true);
  expect(geojson.features.some((feature: { properties: { code: string } }) => feature.properties.code === "TX")).toBe(true);
  await expect(page.getByRole("img", { name: /2 orígenes y 2 regiones activas/ })).toBeVisible();
  await expect(page.locator(".page-map .globe-canvas canvas")).toBeVisible();
  expect(errors, errors.join("\n")).toEqual([]);
});

test("el selector tiene label explícito y foco visible", async ({ page }) => {
  await loginAndOpenMap(page);
  const state = page.getByRole("combobox", { name: "Estado / región" });
  await expect(state).toHaveAttribute("id", "map-subdivision");
  const label = page.locator('label[for="map-subdivision"]');
  await expect(label).toContainText("Estado / región");
  await state.focus();
  await expect(state).toBeFocused();
  await expect(label).toHaveCSS("outline-style", "solid");
  await expect(label).toHaveCSS("outline-width", "2px");
});

test("login → mapa → origen seleccionado → eventos filtrados", async ({ page }) => {
  await loginAndOpenMap(page);
  await page.locator(".map-rank .rank-row").filter({ hasText: "Texas" }).click();
  await expect(page.locator(".map-focus")).toContainText(TX_IP);
  await page.getByRole("button", { name: "Ver eventos de este origen" }).click();
  await expect(page).toHaveURL(/#events$/);
  await expect(page.getByRole("heading", { name: "Eventos", exact: true })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Buscar en Dystopia" })).toHaveValue(TX_IP);
  const rows = page.locator(".discover-panel .event-table tbody tr");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText(TX_IP);
  await expect(rows.first()).not.toContainText(CA_IP);
});

test("permite zoom profundo y muestra etiquetas al acercarse", async ({ page }) => {
  await loginAndOpenMap(page);
  const canvas = page.locator(".globe-canvas");
  const zoomIn = page.getByRole("button", { name: "Acercar mapa" });
  await expect(zoomIn).toBeVisible();
  const before = Number(await canvas.getAttribute("data-zoom"));
  for (let index = 0; index < 4; index += 1) {
    await zoomIn.click();
    await page.waitForTimeout(400);
  }
  await expect.poll(async () => Number(await canvas.getAttribute("data-zoom"))).toBeLessThan(before - 0.2);
  await expect.poll(async () => Number(await canvas.getAttribute("data-labels"))).toBeGreaterThan(0);
  await expect(page.getByRole("button", { name: "Alejar mapa" })).toBeVisible();
});
