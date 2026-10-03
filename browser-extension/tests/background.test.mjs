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

test("unavailable OS verification refuses fill and closes native connection", async () => {
  let listener;
  let closed = false;
  const api = {
    runtime: {
      id: "extension", getURL: (path) => `chrome-extension://extension/${path}`,
      onMessage: { addListener(fn) { listener = fn; } },
    },
    tabs: { query: async () => [{ id: 1, url: "https://example.com" }] },
  };
  vm.runInContext(source, vm.createContext({
    chrome: api,
    WispKeyFlow: {
      httpsOrigin: () => "https://example.com",
      nativeClient: () => ({
        request: async () => ({ approval_available: false, requests: [{ request_id: "request" }] }),
        close() { closed = true; },
      }),
      fill: () => assert.fail("unavailable verification must never start fill"),
    },
  }));
  const response = await new Promise((resolve) => listener(
    { method: "fill", request_id: "request" },
    { id: "extension", url: "chrome-extension://extension/popup.html" }, resolve,
  ));
  assert.equal(response.ok, false);
  assert.match(response.error, /no browser approval backend/);
  assert.equal(closed, true);
});
