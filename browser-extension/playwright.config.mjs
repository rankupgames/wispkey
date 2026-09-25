import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/browser",
  retries: 0,
  workers: 2,
  reporter: "list",
  use: { headless: true, screenshot: "only-on-failure", trace: "off" },
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
    { name: "firefox", use: { browserName: "firefox" } },
  ],
});
