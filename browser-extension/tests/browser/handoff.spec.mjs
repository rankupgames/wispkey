// These browser-engine fixtures use synthetic credentials and mocked extension
// transport. They exercise real DOM/layout, not native installation or OS auth.
import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";

const flow = await readFile(new URL("../../src/flow.js", import.meta.url), "utf8");
const form = '<form action="/login"><label>Email<input id="username" type="email" autocomplete="username"></label><label>Password<input id="password" type="password"></label><button>Sign in</button></form>';

async function fixture(page, html = form) {
  await page.route("https://example.test/**", (route) => route.fulfill({ contentType: "text/html", body: route.request().url().endsWith("/login") ? html : form }));
  await page.goto("https://example.test/login");
  await page.evaluate(() => {
    globalThis.browser = { runtime: { id: "fixture", onConnect: {
      addListener(fn) { globalThis.connectFixture = fn; }, removeListener() {},
    } } };
    globalThis.submissions = 0;
    document.addEventListener("submit", (event) => { event.preventDefault(); globalThis.submissions++; });
  });
  await page.addScriptTag({ content: flow });
}

test("fills visible fields once without submitting", async ({ page }) => {
  await fixture(page);
  const result = await page.evaluate(() => {
    const installed = WispKeyFlow.installReceiver("nonce", location.origin);
    const replies = [];
    let receive;
    connectFixture({ name: "wispkey-fill-nonce", sender: { id: "fixture" },
      onMessage: { addListener(fn) { receive = fn; } }, postMessage(value) { replies.push(value); } });
    receive({ origin: location.origin, login: { username: "synthetic@example.test", password: "synthetic-test-password" } });
    receive({ origin: location.origin, login: { username: "replay", password: "replay" } });
    return { installed, replies, submissions };
  });
  expect(result).toEqual({ installed: true, replies: [{ ready: true }, { completed: true }], submissions: 0 });
  await expect(page.locator("#username")).toHaveValue("synthetic@example.test");
  await expect(page.locator("#password")).toHaveValue("synthetic-test-password");
});

test("refuses forms changed after inspection and hidden password fields", async ({ page }) => {
  await fixture(page);
  const result = await page.evaluate(() => {
    WispKeyFlow.installReceiver("nonce", location.origin);
    const replies = [];
    let receive;
    connectFixture({ name: "wispkey-fill-nonce", sender: { id: "fixture" },
      onMessage: { addListener(fn) { receive = fn; } }, postMessage(value) { replies.push(value); } });
    document.querySelector("form").action = "https://other.test/collect";
    receive({ origin: location.origin, login: { username: "synthetic", password: "synthetic" } });
    document.querySelector("form").action = "/login";
    document.querySelector("#password").style.display = "none";
    return { replies, hidden: WispKeyFlow.installReceiver("second", location.origin) };
  });
  expect(result).toEqual({ replies: [{ ready: true }, { completed: false }], hidden: false });
  await expect(page.locator("#password")).toHaveValue("");
});

test("refuses a login form inside a same-origin iframe", async ({ page }) => {
  await fixture(page, '<iframe src="/frame"></iframe>');
  await expect(page.frameLocator("iframe").locator("#username")).toBeVisible();
  const frame = page.frames().find((candidate) => candidate !== page.mainFrame());
  await frame.addScriptTag({ content: flow });
  expect(await frame.evaluate(() => WispKeyFlow.installReceiver("nonce", location.origin))).toBe(false);
});

test("popup escapes request text and requires profile acknowledgement", async ({ page }, testInfo) => {
  await page.addInitScript(() => {
    globalThis.browser = { runtime: { sendMessage: async () => ({ ok: true, result: {
      origin: "https://example.test", approval_available: true,
      requests: [{ request_id: "synthetic", project: "default", name: "careers", origin: "https://example.test",
        requester: "test-agent", reason: '<img src=x onerror="alert(1)">', expires_at: 2000000000 }],
    } }) } };
  });
  const family = testInfo.project.name === "firefox" ? "firefox" : "chromium";
  await page.goto(new URL(`../../dist/${family}/popup.html`, import.meta.url).href);
  await expect(page.getByRole("button", { name: "Approve with Windows Hello" })).toBeDisabled();
  await expect(page.locator("article img")).toHaveCount(0);
  await expect(page.locator("article")).toContainText('<img src=x onerror="alert(1)">');
  await page.getByRole("checkbox").check();
  await expect(page.getByRole("button", { name: "Approve with Windows Hello" })).toBeEnabled();
  await page.screenshot({ path: testInfo.outputPath("popup.png") });
});
