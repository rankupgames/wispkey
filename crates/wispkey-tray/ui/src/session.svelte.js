// One popout owns one coordinator. Privacy changes invalidate UI work, but a
// mutating request keeps its operation owner until that exact request settles.
export function createSession({ request, cancelPending }) {
  let generation = 0;
  let previewGeneration = 0;
  let operation = $state(null);
  let idleTimer;
  let redact;

  function activity() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => redact("idle"), 120000);
  }

  // Host callbacks and timers are installed once for this popout and removed
  // together. Feature controllers decide which private fields must be cleared.
  function bindWindow({ root, start, refreshStatus, filesDropped, setDragging, clearPrivate }) {
    let alive = true;
    let polling = false;
    redact = clearPrivate;
    void start(() => alive);
    const poll = setInterval(() => {
      if (!alive || polling || document.hidden) return;
      polling = true;
      void refreshStatus().then(() => { polling = false; });
    }, 2000);
    window.__wispkeyFiles = (paths) => {
      setDragging(false);
      filesDropped(paths);
    };
    window.__wispkeyDrag = (active) => setDragging(active === true);
    window.__wispkeyBlur = () => {
      setDragging(false);
      redact("blur");
    };
    const hidden = () => {
      if (!document.hidden) { void refreshStatus(); return; }
      redact("hidden");
    };
    document.addEventListener("visibilitychange", hidden);
    let previousHeight = 0;
    const observer = new ResizeObserver(() => {
      const content = root.querySelector(".content");
      const height = Math.ceil(root.querySelector("header").getBoundingClientRect().height + content.scrollHeight + 2);
      if (height === previousHeight) return;
      previousHeight = height;
      void request("resize_window", { height });
    });
    observer.observe(root);
    activity();
    return () => {
      alive = false;
      clearInterval(poll);
      clearTimeout(idleTimer);
      observer.disconnect();
      document.removeEventListener("visibilitychange", hidden);
      delete window.__wispkeyFiles;
      delete window.__wispkeyDrag;
      delete window.__wispkeyBlur;
      redact("destroy");
      cancelPending();
    };
  }

  return {
    get generation() { return generation; },
    get previewGeneration() { return previewGeneration; },
    get busy() { return operation !== null; },
    invalidate() { generation += 1; },
    invalidatePreview() { previewGeneration += 1; },
    abandonPreview() { operation = null; },
    begin() {
      const owner = Symbol();
      operation = owner;
      return owner;
    },
    finish(owner) { if (operation === owner) operation = null; },
    redactOutcome(result) {
      return { imported: result.imported, reused: result.reused, skipped: result.skipped, sourceFailed: result.sourceFailed || result.files.some((file) => file.status === "failed"), files: [] };
    },
    activity, bindWindow,
  };
}
