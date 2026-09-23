if (typeof importScripts === "function") importScripts("flow.js");
const api = globalThis.browser || globalThis.chrome;
const flow = globalThis.WispKeyFlow;
let busy = false;
let lastStatus = "";

async function dispatch(message) {
  if (message.method === "last_status") return { status: lastStatus, busy };
  if (!["pending", "deny", "fill"].includes(message.method)) throw new Error("Unsupported action.");
  if (busy) throw new Error("An approval is already in progress.");
  if (message.method === "fill") busy = true;
  let native;
  let detached = false;
  try {
    const [tab] = await api.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) throw new Error("Open a website first.");
    const origin = flow.httpsOrigin(tab.url);
    native = flow.nativeClient(api);
    const result = await native.request({ method: "pending", origin });
    if (message.method === "pending") return { ...result, origin, status: lastStatus };
    const request = result.requests.find((item) => item.request_id === message.request_id);
    if (!request) throw new Error("Request expired or no longer matches this page.");
    if (message.method === "deny") {
      return await native.request({ method: "deny", request_id: request.request_id });
    }
    if (!result.approval_available) throw new Error("This platform has no browser approval backend yet.");
    detached = true;
    lastStatus = "Waiting for Windows Hello approval.";
    // Keep the native connection and document Port in the background when the
    // popup closes as the OS approval dialog takes focus.
    void flow.fill(api, native, tab, request)
      .then((status) => { lastStatus = status; })
      .catch(() => { lastStatus = "Fill refused or failed. Reopen the site and create a new request if needed."; })
      .finally(() => { busy = false; native.close(); });
    return { status: lastStatus };
  } finally {
    if (!detached) {
      native?.close();
      if (message.method === "fill") busy = false;
    }
  }
}

api.runtime.onMessage.addListener((message, sender, respond) => {
  // No content-script, external-extension, website or agent request can approve.
  if (sender.id !== api.runtime.id || sender.tab || sender.url !== api.runtime.getURL("popup.html")) return false;
  dispatch(message).then((result) => respond({ ok: true, result }))
    .catch((error) => respond({ ok: false, error: error.message }));
  return true;
});
