import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { readFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";

const source = await readFile(new URL("../src/flow.js", import.meta.url), "utf8");
function event() {
  const callbacks = new Set();
  return { addListener: (fn) => callbacks.add(fn), removeListener: (fn) => callbacks.delete(fn), emit: (v) => { for (const fn of [...callbacks]) fn(v); } };
}
function port() {
  return { onMessage: event(), onDisconnect: event(), sent: [],
    postMessage(message) { this.sent.push(structuredClone(message)); },
    disconnect() { this.onDisconnect.emit(); },
  };
}
function flow() {
  const context = vm.createContext({ URL, crypto: webcrypto, setTimeout, clearTimeout });
  vm.runInContext(source, context);
  return context.WispKeyFlow;
}

test("HTTPS origin checks reject userinfo, insecure URLs and sibling origins", () => {
  const f = flow();
  assert.equal(f.httpsOrigin("https://example.com:443/login?q=a"), "https://example.com");
  for (const url of ["http://example.com", "https://user:pass@example.com", "about:blank"]) {
    assert.throws(() => f.httpsOrigin(url));
  }
});

test("fill is document-bound and reports completion without returning the password", async () => {
  const f = flow();
  const content = port();
  const originalPost = content.postMessage;
  content.postMessage = function(message) {
    originalPost.call(this, message);
    queueMicrotask(() => this.onMessage.emit({ completed: true }));
  };
  const calls = [];
  const native = { async request(message) {
    calls.push(message);
    return message.method === "fill" ? { request_id: "req", origin: "https://example.com", login: { username: "test", password: "synthetic-password" } } : {};
  } };
  const api = {
    runtime: {}, scripting: { executeScript: async (options) => {
      assert.deepEqual([...options.target.frameIds], [0]);
      assert.equal(options.args.length, 2, "no plaintext in script injection arguments");
      return [{ frameId: 0, result: true }];
    } },
    tabs: { connect() { queueMicrotask(() => content.onMessage.emit({ ready: true })); return content; }, get: async () => ({ url: "https://example.com/login" }) },
  };
  const result = await f.fill(api, native, { id: 1, url: "https://example.com/login" }, { origin: "https://example.com", request_id: "req" });
  assert.match(result, /submit it yourself/);
  assert.equal(content.sent[0].login.password, "synthetic-password");
  assert.equal(calls[1].completed, true);
  assert.ok(!JSON.stringify(calls).includes("synthetic-password"));
});

test("navigation during OS approval never sends the login to a page", async () => {
  const f = flow();
  const content = port();
  const calls = [];
  const native = { async request(message) {
    calls.push(message);
    if (message.method === "fill") {
      content.disconnect();
      return { request_id: "req", origin: "https://example.com", login: { username: "test", password: "synthetic-password" } };
    }
    return {};
  } };
  const api = {
    runtime: {}, scripting: { executeScript: async () => [{ frameId: 0, result: true }] },
    tabs: { connect() { queueMicrotask(() => content.onMessage.emit({ ready: true })); return content; } },
  };
  await assert.rejects(f.fill(api, native, { id: 1, url: "https://example.com" }, { origin: "https://example.com", request_id: "req" }), /page changed/);
  assert.equal(content.sent.length, 0);
  assert.equal(calls[1].completed, false);
});

function documentFixture(options = {}) {
  const form = { action: options.action || "https://example.com/login", querySelectorAll: (selector) => selector === "[formaction]" ? [] : [username, ...passwords] };
  class Input {
    constructor(type) { this.type = type; this.form = form; this.autocomplete = ""; this.events = []; this.stored = ""; }
    getClientRects() { return options.hidden ? [] : [{}]; }
    set value(value) { this.stored = value; }
    dispatchEvent(event) { this.events.push(event.type); }
  }
  const username = new Input("email");
  const passwords = Array.from({ length: options.passwords ?? 1 }, () => new Input("password"));
  for (const password of passwords) password.autocomplete = options.autocomplete ?? (passwords.length === 2 ? "new-password" : "current-password");
  const onConnect = event();
  const window = {}; window.top = options.iframe ? {} : window;
  const context = vm.createContext({
    URL, window, location: { origin: "https://example.com", protocol: "https:", href: "https://example.com/login" },
    document: { querySelectorAll: () => passwords }, HTMLInputElement: Input,
    getComputedStyle: () => ({ visibility: "visible" }), Event: class { constructor(type) { this.type = type; } },
    browser: { runtime: { id: "extension", onConnect } },
    setTimeout: () => 1, clearTimeout() {},
  });
  vm.runInContext(source, context);
  return { context, username, passwords, onConnect, install: () => context.WispKeyFlow.installReceiver("nonce", "https://example.com") };
}

test("receiver refuses hidden, ambiguous, framed and cross-origin forms", () => {
  for (const options of [{ hidden: true }, { iframe: true }, { passwords: 3 }, { passwords: 2, autocomplete: "current-password" }, { autocomplete: "one-time-code" }, { action: "https://evil.test/collect" }, { action: "http://example.com/login" }]) {
    assert.equal(documentFixture(options).install(), false);
  }
});

test("receiver fills once, revalidates origin and never submits", () => {
  const fixture = documentFixture({ passwords: 2 });
  assert.equal(fixture.install(), true);
  const content = port(); content.name = "wispkey-fill-nonce"; content.sender = { id: "extension" };
  fixture.onConnect.emit(content);
  const message = { origin: "https://example.com", login: { username: "test@example.com", password: "synthetic-password" } };
  content.onMessage.emit(message);
  assert.equal(fixture.username.stored, "test@example.com");
  assert.equal(fixture.passwords[1].stored, "synthetic-password");
  assert.deepEqual(fixture.passwords[0].events, ["input", "change"]);
  assert.equal(message.login.password, "");
  content.onMessage.emit({ origin: "https://example.com", login: { username: "changed", password: "changed" } });
  assert.equal(fixture.passwords[0].stored, "synthetic-password");
  assert.deepEqual(content.sent, [{ ready: true }, { completed: true }]);

  const navigated = documentFixture();
  assert.equal(navigated.install(), true);
  const second = port(); second.name = "wispkey-fill-nonce"; second.sender = { id: "extension" };
  navigated.onConnect.emit(second);
  navigated.context.location.origin = "https://evil.test";
  second.onMessage.emit({ origin: "https://example.com", login: { username: "test", password: "synthetic-password" } });
  assert.equal(navigated.passwords[0].stored, "");
  assert.equal(second.sent.at(-1).completed, false);
});
