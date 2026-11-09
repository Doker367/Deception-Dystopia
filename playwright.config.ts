import { defineConfig } from "@playwright/test";

const baseURL = "http://127.0.0.1:5179";

export default defineConfig({
  testDir: "./tests/e2e",
  workers: 1,
  use: {
    baseURL,
    browserName: "chromium",
    headless: true,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "npm --prefix web run dev -- --host 127.0.0.1 --port 5179 --strictPort",
    url: baseURL,
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
