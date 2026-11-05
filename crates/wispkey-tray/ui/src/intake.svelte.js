import { meaningfulHosts } from "./hosts.js";

export function createIntake({ session, request, feedback, fail, isUnlocked, navigation }) {
  let project = $state("");
  let partitions = $state([]);
  let plan = $state(null);
  let importItems = $state([]);
  let environment = $state("");
  let rewriteHttp = $state(false);
  let outcome = $state(null);
  let clipboardName = $state("");
  let destinationConfirmed = $state(false);
  let previewSource = null;
  const selectedItems = $derived(importItems.filter((item) => item.selected));
  const mixedEnvironments = $derived(new Set(importItems.map((item) => item.environment)).size > 1);
  const canRewrite = $derived(selectedItems.length > 0 && selectedItems.every(rewritable));
  const unresolved = $derived(selectedItems.filter((item) => (item.conflict_status === "scope_conflict") || (item.conflict && !item.action) || (item.needs_hosts && (!item.conflict || item.action !== "keep") && !meaningfulHosts(item.hosts))));

  function rewritable(item) {
    return item.tokenizable && !(item.conflict && item.action === "keep") && /(?:^|[\\/])\.env(?:\.[^\\/]+)?$/.test(item.source || "");
  }

  function discardPlan() {
    session.invalidatePreview();
    const id = plan?.plan_id;
    plan = null;
    importItems = [];
    previewSource = null;
    rewriteHttp = false;
    if (id) void request("import_cancel", { plan_id: id });
  }

  async function previewImport(params, method = "import_preview") {
    if (!isUnlocked() || session.busy) return;
    discardPlan();
    outcome = null;
    feedback.message = "";
    feedback.notice = "";
    const owner = session.begin();
    navigation.view = "scanning";
    const epoch = session.previewGeneration;
    const response = await request(method, { ...params, project });
    session.finish(owner);
    if (epoch !== session.previewGeneration) {
      if (response.ok && response.result.plan_id) void request("import_cancel", { plan_id: response.result.plan_id });
      return;
    }
    if (!response.ok) {
      if (method === "clipboard_import" && response.error.code === "clipboard_name_required") {
        clipboardName = "";
        navigation.view = "clipboard_name";
        return;
      }
      navigation.view = "intake"; fail(response); return;
    }
    const next = response.result;
    if (typeof next.plan_id !== "string" || !Array.isArray(next.items) || !next.items.every((item) => typeof item.id === "string" && typeof item.key === "string" && typeof item.type === "string" && typeof item.conflict === "boolean" && typeof item.needs_hosts === "boolean" && typeof item.tokenizable === "boolean" && typeof item.environment === "string" && item.environment.trim().length > 0)) {
      if (typeof next.plan_id === "string") void request("import_cancel", { plan_id: next.plan_id });
      feedback.message = "Invalid import review";
      navigation.view = "intake";
      return;
    }
    plan = next;
    previewSource = { method, params };
    importItems = next.items.map((item) => ({ ...item, selected: true, hosts: Array.isArray(item.hosts) ? item.hosts.join(", ") : "", action: item.conflict ? "" : "keep" }));
    environment = next.items.length && next.items.every((item) => item.environment === next.items[0].environment) ? next.items[0].environment : "";
    destinationConfirmed = false;
    navigation.view = "review";
  }

  function repreviewDestination() {
    destinationConfirmed = false;
    if (previewSource) {
      const source = previewSource;
      const params = { ...source.params };
      if (environment.trim()) params.environment = environment.trim();
      else delete params.environment;
      void previewImport(params, source.method);
    }
  }

  async function chooseSource(directory) {
    feedback.message = "";
    const epoch = session.previewGeneration;
    const response = await request(directory ? "choose_import_directory" : "choose_import_files");
    if (epoch !== session.previewGeneration) return;
    if (!response.ok) { fail(response); return; }
    if (response.result.cancelled === true) return;
    if (!Array.isArray(response.result.paths) || !response.result.paths.length) { feedback.message = "No source was selected"; return; }
    await previewImport(directory ? { directory: response.result.paths[0] } : { paths: response.result.paths });
  }

  async function commitImport(event) {
    event.preventDefault();
    if (!plan || session.busy || !destinationConfirmed || !project || (!environment && !mixedEnvironments) || !selectedItems.length || unresolved.length) return;
    const owner = session.begin();
    feedback.message = "";
    const epoch = session.generation;
    const response = await request("import_commit", { plan_id: plan.plan_id, project, environment, items: importItems.map(({ id, selected, hosts, action, environment }) => ({ id, selected, hosts, action, environment })), rewrite_http: rewriteHttp && canRewrite, destination_confirmed: true });
    session.finish(owner);
    if (epoch === session.generation) destinationConfirmed = false;
    if (!response.ok) { if (epoch === session.generation) fail(response); else feedback.message = "The import failed. Check its result before retrying."; return; }
    const result = response.result;
    if (!Number.isInteger(result.imported) || !Array.isArray(result.files)) { feedback.message = "Invalid import result. Check the vault before retrying."; return; }
    outcome = epoch === session.generation ? result : session.redactOutcome(result);
    if (epoch === session.generation || (!session.busy && navigation.view === "intake")) {
      plan = null;
      importItems = [];
      navigation.view = "import_done";
    }
  }

  async function loadPartitions() {
    if (!project) { partitions = []; return; }
    const epoch = session.generation;
    const name = project;
    const response = await request("list_partitions", { project: name });
    if (epoch !== session.generation || name !== project) return;
    if (!response.ok) { partitions = []; fail(response); return; }
    if (!Array.isArray(response.result.partitions)) { feedback.message = "Invalid environment list"; return; }
    partitions = response.result.partitions;
  }

  function clearSecrets() {
    clipboardName = "";
    destinationConfirmed = false;
  }

  function clearPrivate() {
    clearSecrets();
    discardPlan();
    if (outcome) outcome = session.redactOutcome(outcome);
  }

  return {
    get project() { return project; }, set project(value) { project = value; },
    get partitions() { return partitions; },
    get plan() { return plan; },
    get importItems() { return importItems; },
    get environment() { return environment; }, set environment(value) { environment = value; },
    get rewriteHttp() { return rewriteHttp; }, set rewriteHttp(value) { rewriteHttp = value; },
    get outcome() { return outcome; }, set outcome(value) { outcome = value; },
    get clipboardName() { return clipboardName; }, set clipboardName(value) { clipboardName = value; },
    get destinationConfirmed() { return destinationConfirmed; }, set destinationConfirmed(value) { destinationConfirmed = value; },
    get selectedItems() { return selectedItems; },
    get mixedEnvironments() { return mixedEnvironments; },
    get canRewrite() { return canRewrite; },
    get unresolved() { return unresolved; },
    clearSecrets, clearPrivate, discardPlan, previewImport, repreviewDestination, chooseSource, commitImport, loadPartitions,
  };
}
