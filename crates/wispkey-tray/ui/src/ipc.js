// The renderer receives metadata only. Native clipboard and file access stay in the host.
const pending = {};
const unavailable = { ok: false, error: { code: "unavailable", message: "IPC unavailable" } };

window.__wispkeyPending = pending;
window.__wispkeyResolve = (id, response) => pending[id]?.(response);

export function request(method, params = {}) {
  return new Promise((resolve) => {
    const id = crypto.randomUUID();
    const finish = (response) => {
      if (!pending[id]) return;
      clearTimeout(timer);
      delete pending[id];
      if (response?.ok === true && response.result && typeof response.result === "object") {
        resolve(response);
      } else if (response?.ok === false) {
        resolve({ ok: false, error: { code: typeof response.error?.code === "string" ? response.error.code : "unavailable", message: typeof response.error?.message === "string" ? response.error.message : "The operation failed" } });
      } else {
        resolve({ ok: false, error: { code: "invalid_response", message: "Invalid owner response" } });
      }
    };
    const timer = setTimeout(() => finish({ ok: false, error: { code: "timeout", message: "The operation timed out. Check its result before retrying." } }), 30000);
    pending[id] = finish;
    if (typeof window.ipc?.postMessage !== "function") {
      finish(unavailable);
      return;
    }
    Promise.resolve().then(() => window.ipc.postMessage(JSON.stringify({ id, method, params }))).then(undefined, () => finish(unavailable));
  });
}

export function cancelPending() {
  Object.values(pending).forEach((finish) => finish(unavailable));
}
