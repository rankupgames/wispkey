import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../src/background.js", import.meta.url), "utf8");

test("background accepts only its own popup and serializes approvals", async () => {
  let listener;
  let releaseTab;
  let releaseFill;
  let nativeCalls = 0;
  const api = {
    runtime: {
      id: "extension", getURL: (path) => `chrome-extension://extension/${path}`,
      onMessage: { addListener(fn) { listener = fn; } },
    },
    tabs: { query: () => new Promise((resolve) => { releaseTab = resolve; }) },
  };
  const context = vm.createContext({
    chrome: api,
    WispKeyFlow: {
      httpsOrigin: () => "https://example.com",
      nativeClient: () => {
        nativeCalls++;
        return { request: async () => ({ approval_available: true, requests: [{ request_id: "request", origin: "https://example.com" }] }), close() {} };
      },
      fill: () => new Promise((resolve) => { releaseFill = resolve; }),
    },
  });
  vm.runInContext(source, context);
  const message = { method: "fill", request_id: "request" };
  const popup = { id: "extension", url: "chrome-extension://extension/popup.html" };
  for (const sender of [
    { id: "other", url: popup.url },
    { ...popup, tab: { id: 1 } },
    { id: "extension", url: "https://example.com" },
  ]) {
    assert.equal(listener(message, sender, () => assert.fail("must not respond to untrusted sender")), false);
  }
  assert.equal(nativeCalls, 0);
  const first = new Promise((resolve) => listener(message, popup, resolve));
  const second = await new Promise((resolve) => listener(message, popup, resolve));
  assert.equal(second.ok, false);
  assert.match(second.error, /already in progress/);
  releaseTab([{ id: 1, url: "https://example.com" }]);
  assert.equal((await first).ok, true);
  assert.equal(nativeCalls, 1);
  releaseFill("Filled");
});
