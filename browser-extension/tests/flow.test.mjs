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
  const form = { action: options.action || "https://example.com/login", get elements() { return [...text, ...passwords]; } };
  class Input {
    constructor(type) { this.type = type; this.form = form; this.autocomplete = ""; this.events = []; this.stored = ""; }
    getClientRects() { return options.hidden ? [] : [{}]; }
    matches(selector) { return selector === ":disabled" && this.fieldsetDisabled === true; }
    getAttribute(name) { return name === "autocomplete" ? this.autocomplete : null; }
    set value(value) { this.stored = value; }
    dispatchEvent(event) { this.events.push(event.type); }
  }
  const username = new Input(options.usernameType ?? "email");
  username.autocomplete = options.usernameAutocomplete ?? "";
  const text = [username, ...(options.extraText ?? []).map((attributes) => Object.assign(new Input("text"), attributes))];
  const passwords = Array.from({ length: options.passwords ?? 1 }, () => new Input("password"));
  for (const password of passwords) password.autocomplete = options.autocomplete ?? (passwords.length === 2 ? "new-password" : "current-password");
  const onConnect = event();
  const window = {}; window.top = options.iframe ? {} : window;
  const context = vm.createContext({
    URL, window, location: { origin: "https://example.com", protocol: "https:", href: "https://example.com/login" },
    document: { querySelectorAll: (selector) => selector === "[formaction]" ? [] : passwords }, HTMLInputElement: Input,
    getComputedStyle: () => ({ visibility: "visible" }), Event: class { constructor(type) { this.type = type; } },
    browser: { runtime: { id: "extension", onConnect } },
    setTimeout: () => 1, clearTimeout() {},
  });
  vm.runInContext(source, context);
  return { context, username, text, passwords, form, Input, onConnect, install: () => context.WispKeyFlow.installReceiver("nonce", "https://example.com") };
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

function connectReceiver(fixture) {
  assert.equal(fixture.install(), true);
  const content = port();
  content.name = "wispkey-fill-nonce";
  content.sender = { id: "extension" };
  fixture.onConnect.emit(content);
  return content;
}

for (const autocomplete of ["email", "section-signup email", "section-signup billing work email", "USERNAME", "section-signup username webauthn"]) {
  test(`receiver maps declared identity (${autocomplete}) without touching profile fields`, () => {
    const fixture = documentFixture({ usernameType: "text", usernameAutocomplete: autocomplete, passwords: 2,
      extraText: [{ autocomplete: "given-name", stored: "Existing name" }, { autocomplete: "one-time-code", stored: "123456" }] });
    const content = connectReceiver(fixture);
    content.onMessage.emit({ origin: "https://example.com", login: { username: "synthetic@example.test", password: "synthetic-password" } });
    assert.equal(fixture.username.stored, "synthetic@example.test");
    assert.equal(fixture.passwords[0].stored, fixture.passwords[1].stored);
    assert.equal(fixture.text[1].stored, "Existing name");
    assert.equal(fixture.text[2].stored, "123456");
    assert.deepEqual(fixture.text[1].events, []);
    assert.deepEqual(fixture.text[2].events, []);
    assert.equal(content.sent.at(-1).completed, true);
  });
}

test("receiver limits fallback to one text field without a declared non-login purpose", () => {
  assert.equal(documentFixture({ usernameType: "text", extraText: [{ autocomplete: "given-name" }] }).install(), true);
  assert.equal(documentFixture({ usernameType: "text", extraText: [{}] }).install(), false);
  for (const usernameAutocomplete of ["one-time-code", "given-name", "cc-number", "username email", "home username", "section- username", "unrecognized"])
    assert.equal(documentFixture({ usernameType: "text", usernameAutocomplete }).install(), false, usernameAutocomplete);
  assert.equal(documentFixture({ usernameAutocomplete: "one-time-code" }).install(), false, "email input with a declared non-login purpose");
  assert.equal(documentFixture({ usernameAutocomplete: "username", extraText: [{ autocomplete: "email" }] }).install(), false, "separate email and username require distinct profile values");
});

test("receiver rejects unsupported password purposes and disabled fieldsets", () => {
  for (const autocomplete of ["email", "one-time-code", "new-password current-password", "new-password one-time-code", "home new-password"])
    assert.equal(documentFixture({ autocomplete }).install(), false, autocomplete);
  const fixture = documentFixture();
  fixture.username.fieldsetDisabled = true;
  assert.equal(fixture.install(), false);
});

test("receiver refuses replaced targets, changed purposes and same-origin destination changes", () => {
  for (const mutate of [
    (fixture) => { fixture.text[0] = new fixture.Input("email"); },
    (fixture) => { fixture.passwords[0] = new fixture.Input("password"); },
    (fixture) => { fixture.username.autocomplete = "username"; },
    (fixture) => { fixture.form.action = "https://example.com/different-signup"; },
    (fixture) => { fixture.username.form = {}; },
    (fixture) => { fixture.username.fieldsetDisabled = true; },
  ]) {
    const fixture = documentFixture();
    const content = connectReceiver(fixture);
    mutate(fixture);
    content.onMessage.emit({ origin: "https://example.com", login: { username: "synthetic", password: "synthetic-password" } });
    assert.equal(content.sent.at(-1).completed, false);
    assert.equal(fixture.username.stored, "");
    assert.equal(fixture.passwords[0].stored, "");
    assert.equal(fixture.text[0].stored, "");
  }
});
