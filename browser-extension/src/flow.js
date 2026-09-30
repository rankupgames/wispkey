/* Shared between Chromium service worker and Firefox background scripts. */
globalThis.WispKeyFlow = (() => {
  function httpsOrigin(raw) {
    const url = new URL(raw);
    if (url.protocol !== "https:" || url.username || url.password) throw new Error("Open an HTTPS website first.");
    return url.origin;
  }

  // Runs in the isolated world of frame 0. The Port stays bound to this document;
  // navigation destroys it instead of delivering a secret to the next document.
  function installReceiver(nonce, origin) {
    const api = globalThis.browser || globalThis.chrome;
    if (window !== window.top || location.origin !== origin || location.protocol !== "https:") return false;
    const visible = (input) => !input.disabled && !input.matches(":disabled") && !input.readOnly
      && input.getClientRects().length > 0 && getComputedStyle(input).visibility === "visible"
      && getComputedStyle(input).opacity !== "0";
    // Read the declared attribute: Firefox may expose an empty property for
    // valid detail tokens. Unknown/ambiguous purposes must not become username
    // fallback candidates. Only the supported subset of HTML autocomplete is
    // recognized; this is not a general profile/address autofill engine.
    function purpose(input) {
      const value = (input.getAttribute("autocomplete") || "").trim().toLowerCase();
      if (!value || value === "on" || value === "off") return "unspecified";
      const tokens = value.split(/\s+/);
      if (tokens.at(-1) === "webauthn") tokens.pop();
      if (tokens[0]?.startsWith("section-") && tokens[0].length > 8) tokens.shift();
      if (["shipping", "billing"].includes(tokens[0])) tokens.shift();
      const contact = ["home", "work", "mobile", "fax", "pager"].includes(tokens[0]);
      if (contact) tokens.shift();
      if (tokens.length !== 1 || (contact && tokens[0] !== "email")) return "other";
      return ["username", "email", "new-password", "current-password", "one-time-code"].includes(tokens[0])
        ? tokens[0] : "other";
    }
    function fields() {
      const passwords = [...document.querySelectorAll('input[type="password"]')].filter(visible);
      if (passwords.length < 1 || passwords.length > 2) return null;
      const passwordPurposes = passwords.map(purpose);
      if (passwordPurposes.some((value) => !["unspecified", "current-password", "new-password"].includes(value))) return null;
      if (passwords.length === 2 && passwordPurposes.some((value) => value !== "new-password")) return null;
      const form = passwords[0].form;
      if (!form || passwords.some((input) => input.form !== form)) return null;
      // Never fill forms that advertise a different destination, even though we
      // do not submit. Includes overrides on individual submit buttons.
      let destinations;
      try {
        destinations = [form.action, ...[...document.querySelectorAll("[formaction]")]
          .filter((el) => el.form === form).map((el) => el.formAction)]
          .map((value) => new URL(value, location.href));
      } catch { return null; }
      if (destinations.some((url) => url.origin !== origin)) return null;
      // Form ownership, rather than DOM ancestry, also covers controls attached
      // with form="id" and excludes descendants owned by a different form.
      const text = [...form.elements].filter((input) => input instanceof HTMLInputElement
        && input.form === form && visible(input) && ["text", "email"].includes(input.type));
      const usernames = text.filter((input) => ["username", "email"].includes(purpose(input))
        || (input.type === "email" && purpose(input) === "unspecified"));
      const candidates = usernames.length ? usernames : text.filter((input) => purpose(input) === "unspecified");
      if (candidates.length !== 1) return null;
      const username = candidates[0];
      return { form, username, passwords, destinations: destinations.map((url) => url.href).sort(),
        purposes: [purpose(username), ...passwordPurposes], usernameType: username.type };
    }
    const inspected = fields();
    if (!inspected) return false;
    function sameTargets(current) {
      return current && current.form === inspected.form && current.username === inspected.username
        && current.usernameType === inspected.usernameType
        && current.passwords.length === inspected.passwords.length
        && current.passwords.every((input, index) => input === inspected.passwords[index])
        && JSON.stringify(current.purposes) === JSON.stringify(inspected.purposes)
        && JSON.stringify(current.destinations) === JSON.stringify(inspected.destinations);
    }
    const listener = (port) => {
      if (port.name !== `wispkey-fill-${nonce}` || port.sender?.id !== api.runtime.id) return;
      api.runtime.onConnect.removeListener(listener);
      clearTimeout(cleanup);
      let used = false;
      port.onMessage.addListener((message) => {
        if (used) return;
        used = true;
        const targets = fields();
        if (location.origin !== origin || window !== window.top || !sameTargets(targets)
          || message.origin !== origin || typeof message.login?.username !== "string"
          || typeof message.login?.password !== "string") {
          port.postMessage({ completed: false });
          return;
        }
        try {
          const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
          setValue.call(targets.username, message.login.username);
          for (const password of targets.passwords) setValue.call(password, message.login.password);
          message.login.password = "";
          message.login.username = "";
          for (const input of [targets.username, ...targets.passwords]) {
            input.dispatchEvent(new Event("input", { bubbles: true }));
            input.dispatchEvent(new Event("change", { bubbles: true }));
          }
          port.postMessage({ completed: true });
        } catch {
          port.postMessage({ completed: false });
        }
      });
      port.postMessage({ ready: true });
    };
    api.runtime.onConnect.addListener(listener);
    const cleanup = setTimeout(() => api.runtime.onConnect.removeListener(listener), 15000);
    return true;
  }

  function nextMessage(port, timeoutMs = 120000, outgoing) {
    return new Promise((resolve, reject) => {
      const done = () => {
        clearTimeout(timer);
        port.onMessage.removeListener(message);
        port.onDisconnect.removeListener(disconnect);
      };
      const message = (value) => { done(); resolve(value); };
      const disconnect = () => { done(); reject(new Error("Connection closed. The page may have navigated.")); };
      const timer = setTimeout(() => { done(); reject(new Error("Approval or fill timed out.")); }, timeoutMs);
      port.onMessage.addListener(message);
      port.onDisconnect.addListener(disconnect);
      if (outgoing !== undefined) {
        try { port.postMessage(outgoing); }
        catch { done(); reject(new Error("Connection closed before delivery.")); }
      }
    });
  }

  function nativeClient(api) {
    const port = api.runtime.connectNative("com.wispkey.browser");
    // Consume Chromium's lastError without logging anything from native messages.
    port.onDisconnect.addListener(() => { void api.runtime.lastError; });
    return {
      async request(message) {
        const result = await nextMessage(port, 120000, message);
        if (!result.ok) throw new Error(result.error || "WispKey refused this request.");
        return result.result;
      },
      close() { port.disconnect(); },
    };
  }

  async function fill(api, native, tab, request) {
    const origin = httpsOrigin(tab.url);
    if (origin !== request.origin) throw new Error("The selected login has a different origin.");
    const nonce = crypto.randomUUID();
    const injected = await api.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [0] }, func: installReceiver, args: [nonce, origin],
    });
    if (injected.length !== 1 || injected[0].frameId !== 0 || injected[0].result !== true) {
      throw new Error("No unambiguous, visible login form in the top-level page. Nothing was filled.");
    }
    const content = api.tabs.connect(tab.id, { frameId: 0, name: `wispkey-fill-${nonce}` });
    let disconnected = false;
    content.onDisconnect.addListener(() => { disconnected = true; void api.runtime.lastError; });
    let released = false;
    let login;
    try {
      if (!(await nextMessage(content, 10000)).ready) throw new Error("The page is not ready.");
      const result = await native.request({ method: "fill", request_id: request.request_id, origin });
      released = true;
      login = result.login;
      if (disconnected || result.origin !== origin || result.request_id !== request.request_id) {
        throw new Error("The page changed during approval. Create a new request.");
      }
      // Recheck tab metadata as well as the document-bound receiver's origin.
      if (httpsOrigin((await api.tabs.get(tab.id)).url) !== origin) throw new Error("The page navigated during approval.");
      const completed = (await nextMessage(content, 10000, { origin, login })).completed === true;
      await native.request({ method: "complete", request_id: request.request_id, completed });
      released = false;
      if (!completed) throw new Error("The form changed. Nothing was submitted; create a new request.");
      return "Filled. Review the form and submit it yourself.";
    } finally {
      if (login) { login.password = ""; login.username = ""; }
      if (released) {
        try { await native.request({ method: "complete", request_id: request.request_id, completed: false }); } catch { /* expires closed */ }
      }
      content.disconnect();
    }
  }
  return { httpsOrigin, installReceiver, nativeClient, fill };
})();
