// Real built Svelte UI with synthetic, mocked owner IPC; not OS authentication.
import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";

const html = await readFile(new URL("../../../crates/wispkey-tray/ui-dist/index.html", import.meta.url), "utf8");

async function fixture(page, view, ok = true, transport = "available") {
  await page.addInitScript(({ view, ok, transport }) => {
    window.__WISPKEY_VIEW = view;
    window.calls = [];
    if (transport === "missing") return;
    window.ipc = { postMessage(raw) {
      if (transport === "throws") throw new Error("Synthetic disconnected transport");
      const request = JSON.parse(raw);
      window.calls.push(request);
      queueMicrotask(() => window.__wispkeyResolve(request.id, ok
        ? { ok: true, result: { origin: "https://example.test" } }
        : { ok: false, error: { message: "Synthetic owner refusal" } }));
    } };
  }, { view, ok, transport });
  await page.route("https://tray.test/**", (route) => route.fulfill({ contentType: "text/html", body: html.replaceAll("WISPKEY_INITIAL_VIEW", view) }));
  await page.goto("https://tray.test/");
}

test("generated login requires current destination confirmation and sends metadata only", async ({ page }) => {
  await fixture(page, "login");
  await page.getByLabel("Name", { exact: true }).fill("careers");
  await page.getByLabel("Username or email").fill("synthetic@example.test");
  await page.getByLabel("Website URL").fill("https://example.test");
  await page.getByRole("button", { name: "Generate and save" }).click();
  expect(await page.evaluate(() => calls)).toEqual([]);
  await page.getByRole("button", { name: "Use job application preset" }).click();
  await page.getByRole("checkbox").check();
  await page.getByLabel("Project", { exact: true }).fill("changed-project");
  await expect(page.getByRole("checkbox")).not.toBeChecked();
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: "Generate and save" }).click();
  await expect(page.getByText("Login saved for", { exact: false })).toBeVisible();
  const calls = await page.evaluate(() => window.calls);
  expect(calls).toHaveLength(1);
  expect(calls[0].method).toBe("generate_login");
  expect(calls[0].params).toEqual({ name: "careers", username: "synthetic@example.test", url: "https://example.test",
    project: "changed-project", partition: "job-applications", destination_confirmed: true });
  await expect(page.locator('input[type="password"]')).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Copy", exact: true })).toHaveCount(0);
  await expect(page.getByRole("checkbox")).not.toBeChecked();
});

for (const ok of [true, false]) {
  test(`credential save clears the secret and reveal state on ${ok ? "success" : "refusal"}`, async ({ page }) => {
    await fixture(page, "add", ok);
    await page.getByLabel("Name", { exact: true }).fill("synthetic-key");
    await page.getByLabel("Value", { exact: true }).fill("synthetic-secret");
    await page.getByRole("button", { name: "Reveal" }).click();
    await expect(page.getByLabel("Value", { exact: true })).toHaveAttribute("type", "text");
    await page.getByRole("checkbox").check();
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByText(ok ? "Saved" : "Synthetic owner refusal", { exact: true })).toBeVisible();
    await expect(page.getByLabel("Value", { exact: true })).toHaveValue("");
    await expect(page.getByLabel("Value", { exact: true })).toHaveAttribute("type", "password");
    await expect(page.getByRole("checkbox")).not.toBeChecked();
    expect(await page.evaluate(() => Object.keys(__wispkeyPending))).toEqual([]);
  });
}

for (const transport of ["missing", "throws"]) {
  test(`unlock clears entered password when IPC ${transport}`, async ({ page }) => {
    await fixture(page, "unlock", false, transport);
    await page.getByLabel("Master password").fill("synthetic-master-password");
    await page.getByRole("button", { name: "Unlock", exact: true }).click();
    await expect(page.getByText("IPC unavailable", { exact: true })).toBeVisible();
    await expect(page.getByLabel("Master password")).toHaveValue("");
    expect(await page.evaluate(() => Object.keys(__wispkeyPending))).toEqual([]);
  });
}
