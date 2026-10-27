// Built tray UI against synthetic owner IPC. Native clipboard, dialogs and vault
// cryptography remain covered at their native and CLI boundaries.
import { test, expect } from "@playwright/test";
import { readFile, readdir } from "node:fs/promises";

const html = await readFile(new URL("../../../crates/wispkey-tray/ui-dist/index.html", import.meta.url), "utf8");
const scope = "synthetic-project";

async function fixture(page, view = "intake", options = {}) {
  await page.addInitScript(({ view, options }) => {
    window.__WISPKEY_VIEW = view;
    window.calls = [];
    window.fixtureState = {
      initialized: options.initialized !== false,
      session_active: !["unlock"].includes(view),
      active_project: "synthetic-project",
      ...options.status,
    };
    window.ipc = { postMessage(raw) {
      const request = JSON.parse(raw);
      window.calls.push(request);
      const { method } = request;
      let result = {};
      let error;
      if (method === "clipboard_import" && options.bareClipboard && !request.params.name) error = { code: "clipboard_name_required", message: "Name required" };
      else if (method === options.failMethod) error = { code: "refused", message: "Synthetic owner refusal" };
      else if (method === "status") result = { ...window.fixtureState };
      else if (method === "unlock" || method === "initialize") {
        window.fixtureState.initialized = true;
        window.fixtureState.session_active = true;
        result = { initialized: true, session_active: true };
      } else if (method === "lock") {
        window.fixtureState.session_active = false;
        result = { session_active: false };
      } else if (method === "list_projects") result = { projects: [{ name: "synthetic-project", active: true }] };
      else if (method === "list_partitions") result = { partitions: [{ name: "default" }] };
      else if (method === "list_credentials") result = { credentials: options.credentials || [] };
      else if (method === "get_settings") result = { start_at_login: false, start_at_login_supported: false };
      else if (method === "choose_import_files") result = { paths: ["/synthetic/project/.env"], cancelled: false };
      else if (method === "choose_import_directory") result = { paths: ["/synthetic/project"], cancelled: options.cancelPicker === true };
      else if (method === "clipboard_import" || method === "import_preview") result = {
        plan_id: "synthetic-plan", items: [{ id: "synthetic-item", key: "API_KEY", name: "default-api-key", type: "api_key", source: ".env", environment: request.params.environment || "default", conflict: options.conflict === true || options.scopeConflict === true, conflict_status: options.scopeConflict ? "scope_conflict" : options.conflict ? "different" : "new", needs_hosts: true, tokenizable: true }, ...(options.mixedImport ? [{ id: "synthetic-db-item", key: "DATABASE_URL", name: "default-database-url", type: "api_key", source: ".env", environment: request.params.environment || (options.mixedEnvironments ? "synthetic-secondary" : "default"), conflict: false, conflict_status: "new", needs_hosts: false, tokenizable: false }] : [])], warnings: [],
      };
      else if (method === "import_commit") result = { imported: 1, reused: 0, skipped: 0, credentials: [], files: [{ path: ".env", status: options.sourceFailure ? "failed" : request.params.rewrite_http ? "updated" : "unchanged", ...(options.sourceFailure ? { message: "Synthetic source is read-only" } : {}) }] };
      else if (method === "copy_token") result = { copied: true };
      queueMicrotask(() => window.__wispkeyResolve(request.id, error ? { ok: false, error } : { ok: true, result }));
    } };
  }, { view, options });
  await page.route("https://tray.test/**", (route) => route.fulfill({ contentType: "text/html", body: html.replaceAll("WISPKEY_INITIAL_VIEW", view) }));
  await page.goto("https://tray.test/");
}

async function operations(page, method) {
  return page.evaluate((method) => window.calls.filter((call) => call.method === method), method);
}

async function completeManual(page) {
  await page.getByLabel("Name", { exact: true }).fill("synthetic-key");
  await page.getByLabel("Allowed hosts", { exact: true }).fill("api.example.test");
  await page.getByLabel("Secret", { exact: true }).fill("synthetic-secret");
  await expect(page.getByLabel("Partition", { exact: true })).toHaveValue("default");
}

test("embedded dark popout bootstraps without external assets or account routes", async ({ page }) => {
  const requests = [];
  const errors = [];
  page.on("request", (request) => requests.push(request.url()));
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/*", (route) => route.abort());
  await fixture(page);
  await expect(page.getByRole("button", { name: "Choose files to import" })).toBeVisible();
  await expect(page.locator("script[src], link[rel=stylesheet], link[rel=modulepreload]")).toHaveCount(0);
  expect(await readdir(new URL("../../../crates/wispkey-tray/ui-dist/", import.meta.url))).toEqual(["index.html"]);
  expect(requests).toEqual(["https://tray.test/"]);
  expect(errors).toEqual([]);
  await expect(page.locator("main")).toHaveCSS("width", "460px");
  await page.getByRole("button", { name: "Navigation", exact: true }).focus();
  await expect(page.getByRole("navigation")).toBeVisible();
  await expect(page.getByRole("navigation").getByRole("button")).toHaveText(["Intake", "Credentials", "Add credential"]);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("navigation")).toHaveCount(0);
  expect(await operations(page, "close_window")).toHaveLength(0);
  await page.keyboard.press("Escape");
  await expect.poll(async () => (await operations(page, "close_window")).length).toBe(1);
  await expect(page.getByRole("button", { name: /Cloud|Sync|Services|Account|Theme/i })).toHaveCount(0);
});

test("dropzone reveals integrated actions for keyboard and hover without changing height", async ({ page }) => {
  await fixture(page);
  const zone = page.locator(".dropzone");
  const before = await zone.boundingBox();
  await page.getByRole("button", { name: "Choose files to import" }).focus();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "Clipboard import", exact: true })).toBeFocused();
  await expect(page.getByRole("button", { name: "Import project", exact: true })).toBeVisible();
  await zone.hover();
  expect((await zone.boundingBox()).height).toBe(before.height);
  await expect(page.getByRole("button", { name: "More", exact: true })).toHaveCount(0);
});

test("unlock stays inside the masked field and clears a refused password", async ({ page }) => {
  await fixture(page, "unlock", { failMethod: "unlock" });
  const field = page.getByLabel("Master password", { exact: true });
  await field.fill("synthetic-master-password");
  await page.getByLabel("Remember this device", { exact: true }).check();
  await expect(field).toHaveAttribute("type", "password");
  await expect(page.locator(".password-input").getByRole("button", { name: "Unlock", exact: true })).toBeVisible();
  await field.press("Enter");
  await expect(page.getByRole("alert")).toHaveText("Synthetic owner refusal");
  await expect(field).toHaveValue("");
  expect((await operations(page, "unlock"))[0].params).toEqual({ password: "synthetic-master-password", remember: true });
  await expect(page.getByRole("navigation")).toHaveCount(0);
});

test("first vault requires matching confirmation and an explicit create action", async ({ page }) => {
  await fixture(page, "unlock", { initialized: false });
  await expect(page.getByRole("button", { name: "Create vault" })).toBeVisible();
  expect(await operations(page, "initialize")).toHaveLength(0);
  await page.getByLabel("Master password", { exact: true }).fill("synthetic-master-password");
  await page.getByLabel("Confirm password", { exact: true }).fill("synthetic-other-password");
  await page.getByRole("button", { name: "Create vault" }).click();
  await expect(page.getByRole("alert")).toHaveText("Passwords must match");
  expect(await operations(page, "initialize")).toHaveLength(0);
  await page.getByLabel("Master password", { exact: true }).fill("synthetic-master-password");
  await page.getByLabel("Confirm password", { exact: true }).fill("synthetic-master-password");
  await page.getByRole("button", { name: "Create vault" }).click();
  await expect(page.getByRole("button", { name: "Choose files to import" })).toBeVisible();
  expect((await operations(page, "initialize"))[0].params).toEqual({ password: "synthetic-master-password", password_confirmation: "synthetic-master-password" });
});

for (const transport of ["missing", "throws"]) {
  test(`unlock clears entered password when IPC ${transport}`, async ({ page }) => {
    await fixture(page, "unlock");
    await page.getByLabel("Master password", { exact: true }).fill("synthetic-master-password");
    await page.evaluate((transport) => {
      window.ipc = transport === "missing" ? undefined : { postMessage() { throw new Error("Synthetic disconnected transport"); } };
    }, transport);
    await page.getByRole("button", { name: "Unlock", exact: true }).click();
    await expect(page.getByRole("alert")).toHaveText("IPC unavailable");
    await expect(page.getByLabel("Master password", { exact: true })).toHaveValue("");
    expect(await page.evaluate(() => Object.keys(window.__wispkeyPending))).toEqual([]);
  });
}

for (const refused of [false, true]) {
  test(`manual save reviews destination and clears secrets on ${refused ? "refusal" : "success"}`, async ({ page }) => {
    await fixture(page, "add", { failMethod: refused ? "add_credential" : undefined });
    await completeManual(page);
    await page.getByRole("button", { name: "Show secret" }).click();
    await expect(page.getByLabel("Secret", { exact: true })).toHaveAttribute("type", "text");
    await page.getByRole("button", { name: "Save", exact: true }).click();
    expect(await operations(page, "add_credential")).toHaveLength(0);
    const destination = page.getByRole("checkbox", { name: /^Save to/ });
    await destination.check();
    await page.getByLabel("Partition", { exact: true }).fill("synthetic-environment");
    await expect(destination).not.toBeChecked();
    await destination.check();
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByText(refused ? "Synthetic owner refusal" : "Saved", { exact: true })).toBeVisible();
    await expect(page.getByLabel("Secret", { exact: true })).toHaveValue("");
    await expect(page.getByLabel("Secret", { exact: true })).toHaveAttribute("type", "password");
    await expect(destination).not.toBeChecked();
    const [request] = await operations(page, "add_credential");
    expect(request.params).toMatchObject({ name: "synthetic-key", value: "synthetic-secret", project: scope, partition: "synthetic-environment", hosts: "api.example.test", destination_confirmed: true });
  });
}

test("OVH template sends all three secrets in one reviewed request", async ({ page }) => {
  await fixture(page, "add");
  await page.getByLabel("Entry", { exact: true }).selectOption("ovh_api");
  await page.getByLabel("Name prefix", { exact: true }).fill("synthetic-ovh");
  await page.getByLabel("Allowed hosts", { exact: true }).fill("api.example.test");
  await page.getByLabel("Application key", { exact: true }).fill("synthetic-application-key");
  await page.getByLabel("Application secret", { exact: true }).fill("synthetic-application-secret");
  await page.getByLabel("Consumer key", { exact: true }).fill("synthetic-consumer-key");
  await page.getByRole("checkbox", { name: /^Save to/ }).check();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("status")).toHaveText("Saved");
  const [request] = await operations(page, "add_template");
  expect(request.params).toMatchObject({ template: "ovh_api", application_key: "synthetic-application-key", application_secret: "synthetic-application-secret", consumer_key: "synthetic-consumer-key", project: scope, partition: "default", destination_confirmed: true });
  await expect(page.getByLabel("Application secret", { exact: true })).toHaveValue("");
});

test("generated login requires current destination review and receives no secret", async ({ page }) => {
  await fixture(page, "login");
  await page.getByLabel("Name", { exact: true }).fill("synthetic-login");
  await page.getByLabel("Username or email").fill("synthetic@example.test");
  await page.getByLabel("Website URL (HTTPS)", { exact: true }).fill("https://example.test");
  await page.getByRole("button", { name: "Generate and save" }).click();
  expect(await operations(page, "generate_login")).toHaveLength(0);
  const destination = page.getByRole("checkbox", { name: /^Save to/ });
  await destination.check();
  await page.getByLabel("Project", { exact: true }).fill("synthetic-other-project");
  await expect(destination).not.toBeChecked();
  await expect(page.getByLabel("Partition", { exact: true })).toHaveValue("default");
  await destination.check();
  await page.getByRole("button", { name: "Generate and save" }).click();
  await expect(page.getByRole("status")).toHaveText("Login saved");
  expect((await operations(page, "generate_login"))[0].params).toEqual({ name: "synthetic-login", username: "synthetic@example.test", url: "https://example.test", project: "synthetic-other-project", partition: "default", destination_confirmed: true });
  await expect(page.locator('input[type="password"]')).toHaveCount(0);
});

for (const source of ["clipboard", "project"]) {
  test(`${source} import reviews metadata and defaults to store only`, async ({ page }) => {
    await fixture(page);
    await page.getByRole("button", { name: "Choose files to import" }).focus();
    await page.getByRole("button", { name: source === "clipboard" ? "Clipboard import" : "Import project", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Review import" })).toBeVisible();
    if (source === "project") expect((await operations(page, "import_preview"))[0].params).toEqual({ directory: "/synthetic/project", project: scope });
    else expect((await operations(page, "clipboard_import"))[0].params).toEqual({ project: scope });
    await expect(page.getByRole("button", { name: "Store only", exact: true })).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByRole("button", { name: "Import 1", exact: true })).toBeDisabled();
    await page.getByLabel("Allowed hosts for API_KEY").fill("api.example.test");
    await page.getByRole("checkbox", { name: /^Save to/ }).check();
    await page.getByRole("button", { name: "Import 1", exact: true }).click();
    await expect(page.getByRole("heading", { name: "1 credential stored" })).toBeVisible();
    expect((await operations(page, "import_commit"))[0].params).toEqual({ plan_id: "synthetic-plan", project: scope, environment: "default", items: [{ id: "synthetic-item", selected: true, hosts: "api.example.test", action: "keep", environment: "default" }], rewrite_http: false, destination_confirmed: true });
    await expect(page.getByText("Unchanged", { exact: true })).toBeVisible();
  });
}

test("conflict blocks import and source failure stays distinct from vault success", async ({ page }) => {
  await fixture(page, "intake", { conflict: true, sourceFailure: true });
  await page.getByRole("button", { name: "Choose files to import" }).click();
  await page.getByLabel("Allowed hosts for API_KEY").fill("api.example.test");
  await page.getByRole("checkbox", { name: /^Save to/ }).check();
  await expect(page.getByRole("button", { name: "Import 1", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Keep stored", exact: true }).click();
  await expect(page.getByRole("button", { name: "Replace HTTP values with tokens" })).toBeDisabled();
  await page.getByRole("button", { name: "Replace", exact: true }).click();
  await page.getByRole("button", { name: "Replace HTTP values with tokens" }).click();
  await page.getByRole("button", { name: "Import 1", exact: true }).click();
  await expect(page.getByRole("heading", { name: "1 credential stored" })).toBeVisible();
  await expect(page.getByText("Not changed", { exact: true })).toBeVisible();
  await expect(page.getByText("Synthetic source is read-only", { exact: true })).toBeVisible();
  expect((await operations(page, "import_commit"))[0].params).toMatchObject({ rewrite_http: true, items: [{ id: "synthetic-item", selected: true, hosts: "api.example.test", action: "replace", environment: "default" }] });
});

test("cancelled native project picker starts no import", async ({ page }) => {
  await fixture(page, "intake", { cancelPicker: true });
  await page.getByRole("button", { name: "Choose files to import" }).focus();
  await page.getByRole("button", { name: "Import project", exact: true }).click();
  expect(await operations(page, "import_preview")).toHaveLength(0);
  await expect(page.getByRole("button", { name: "Choose files to import" })).toBeVisible();
});

test("native blur and external vault lock clear private forms without list access while locked", async ({ page }) => {
  await page.clock.install();
  await fixture(page, "add");
  await completeManual(page);
  await page.evaluate(() => window.__wispkeyBlur());
  await expect(page.getByRole("button", { name: "Choose files to import" })).toBeVisible();
  await page.getByRole("button", { name: "Navigation", exact: true }).focus();
  await page.getByRole("navigation").getByRole("button", { name: "Add credential", exact: true }).click();
  await expect(page.getByLabel("Secret", { exact: true })).toHaveValue("");
  await completeManual(page);
  await page.evaluate(() => { window.fixtureState.session_active = false; });
  await page.clock.runFor(2100);
  await expect(page.getByLabel("Master password", { exact: true })).toHaveValue("");
  await expect(page.getByLabel("Secret", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Navigation", exact: true })).toHaveCount(0);
  expect(await operations(page, "list_credentials")).toHaveLength(0);
});

test("credential actions use native token copy and reviewed rotation and removal", async ({ page }) => {
  await fixture(page, "list", { credentials: [{ id: "synthetic-id", name: "synthetic-key", project: scope, partition: "default", type: "api_key", updated_at: "2026-01-01T00:00:00Z" }] });
  await expect(page.getByRole("button", { name: "Copy token for synthetic-key", exact: true })).toBeVisible();
  expect((await operations(page, "list_credentials"))[0].params).toEqual({ all_projects: true });
  await page.getByRole("button", { name: "By project", exact: true }).click();
  await expect.poll(async () => (await operations(page, "list_credentials")).length).toBe(2);
  expect((await operations(page, "list_credentials"))[1].params).toEqual({ project: scope });
  await page.getByRole("button", { name: "Copy token for synthetic-key", exact: true }).click();
  await expect(page.getByRole("status")).toHaveText("Token copied");
  expect((await operations(page, "copy_token"))[0].params).toEqual({ name: "synthetic-key", project: scope });
  await page.getByRole("button", { name: "Rotate token for synthetic-key", exact: true }).click();
  expect(await operations(page, "rotate_credential")).toHaveLength(0);
  await page.getByRole("button", { name: "Rotate token", exact: true }).click();
  expect((await operations(page, "rotate_credential"))[0].params).toEqual({ name: "synthetic-key", project: scope, destination_confirmed: true });
  await page.getByRole("button", { name: "Remove synthetic-key", exact: true }).click();
  expect(await operations(page, "remove_credential")).toHaveLength(0);
  await page.getByRole("button", { name: "Remove credential", exact: true }).click();
  expect((await operations(page, "remove_credential"))[0].params).toEqual({ name: "synthetic-key", project: scope, destination_confirmed: true });
});


test("bare clipboard imports request only an explicit name before metadata review", async ({ page }) => {
  await fixture(page, "intake", { bareClipboard: true });
  await page.getByRole("button", { name: "Choose files to import" }).focus();
  await page.getByRole("button", { name: "Clipboard import", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Clipboard import" })).toBeVisible();
  await page.getByLabel("Name", { exact: true }).fill("synthetic-clipboard-key");
  await page.getByRole("button", { name: "Import clipboard", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Review import" })).toBeVisible();
  expect((await operations(page, "clipboard_import")).map((call) => call.params)).toEqual([{ project: scope }, { project: scope, name: "synthetic-clipboard-key" }]);
});


test("changing an import destination refreshes the source plan before committing", async ({ page }) => {
  await fixture(page);
  await page.getByRole("button", { name: "Choose files to import" }).click();
  await page.getByLabel("Environment", { exact: true }).fill("synthetic-environment");
  await page.getByLabel("Environment", { exact: true }).press("Tab");
  await expect.poll(async () => (await operations(page, "import_preview")).length).toBe(2);
  await expect(page.getByLabel("Environment", { exact: true })).toHaveValue("synthetic-environment");
  await expect(page.getByRole("checkbox", { name: /^Save to/ })).not.toBeChecked();
  expect((await operations(page, "import_preview"))[1].params).toEqual({ paths: ["/synthetic/project/.env"], environment: "synthetic-environment", project: scope });
  expect(await operations(page, "import_cancel")).toHaveLength(1);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("button", { name: "Choose files to import" })).toBeVisible();
  expect(await operations(page, "close_window")).toHaveLength(0);
});


test("a silent IPC transport times out and clears the entered master password", async ({ page }) => {
  await page.clock.install();
  await fixture(page, "unlock");
  await page.getByLabel("Master password", { exact: true }).fill("synthetic-master-password");
  await page.evaluate(() => { window.ipc = { postMessage() {} }; });
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await page.clock.runFor(30001);
  await expect(page.getByRole("alert")).toContainText("The operation timed out");
  await expect(page.getByLabel("Master password", { exact: true })).toHaveValue("");
});


test("mixed HTTP and non-HTTP imports stay store-only until the non-HTTP row is excluded", async ({ page }) => {
  await page.setViewportSize({ width: 460, height: 360 });
  await fixture(page, "intake", { mixedImport: true, mixedEnvironments: true });
  await page.getByRole("button", { name: "Choose files to import" }).click();
  await expect(page.getByRole("heading", { name: "Review import" })).toBeVisible();
  expect((await page.locator("main").boundingBox()).height).toBeLessThanOrEqual(360);
  expect(await page.locator(".content").evaluate((content) => content.scrollHeight > content.clientHeight)).toBe(true);
  await expect.poll(async () => (await operations(page, "resize_window")).some((request) => request.params.height > 360)).toBe(true);
  await expect(page.getByLabel("Environment", { exact: true })).toHaveAttribute("placeholder", "From source files");
  await expect(page.getByRole("checkbox", { name: /^Save to/ })).toHaveAccessibleName(`Save to ${scope} / source environments`);
  const rewrite = page.getByRole("button", { name: "Replace HTTP values with tokens" });
  await expect(rewrite).toBeDisabled();
  await page.getByLabel("Import DATABASE_URL", { exact: true }).uncheck();
  await expect(rewrite).toBeEnabled();
  await rewrite.click();
  await page.getByLabel("Import DATABASE_URL", { exact: true }).check();
  await expect(rewrite).toBeDisabled();
  await expect(page.getByRole("button", { name: "Store only", exact: true })).toHaveAttribute("aria-pressed", "true");
  await page.getByLabel("Allowed hosts for API_KEY").fill("api.example.test");
  await page.getByRole("checkbox", { name: /^Save to/ }).check();
  await page.getByRole("button", { name: "Import 2", exact: true }).click();
  await expect.poll(async () => (await operations(page, "import_commit")).length).toBe(1);
  expect((await operations(page, "import_commit"))[0].params).toMatchObject({ rewrite_http: false, items: [{ id: "synthetic-item", selected: true, hosts: "api.example.test", action: "keep", environment: "default" }, { id: "synthetic-db-item", selected: true, hosts: "", action: "keep", environment: "synthetic-secondary" }] });
});

test("scope conflicts offer only skip or destination review", async ({ page }) => {
  await fixture(page, "intake", { scopeConflict: true, mixedImport: true });
  await page.getByRole("button", { name: "Choose files to import" }).click();
  await expect(page.getByRole("button", { name: "Keep stored", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Replace", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Import 2", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Skip", exact: true }).click();
  await page.getByRole("checkbox", { name: /^Save to/ }).check();
  await page.getByRole("button", { name: "Import 1", exact: true }).click();
  await expect.poll(async () => (await operations(page, "import_commit")).length).toBe(1);
  expect((await operations(page, "import_commit"))[0].params.items).toEqual([{ id: "synthetic-item", selected: false, hosts: "", action: "skip", environment: "default" }, { id: "synthetic-db-item", selected: true, hosts: "", action: "keep", environment: "default" }]);
});
