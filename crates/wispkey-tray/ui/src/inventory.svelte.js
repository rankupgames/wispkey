// Inventory scope and review targets belong to the list, not to save destinations.
export function createInventory({ session, request, feedback, fail, isUnlocked }) {
  let project = $state("");
  let credentials = $state([]);
  let filter = $state("all");
  let search = $state("");
  let removeTarget = $state(null);
  let rotateTarget = $state(null);
  const filteredCredentials = $derived.by(() => {
    const rows = credentials.filter((item) => item.name.toLowerCase().includes(search.toLowerCase()));
    if (filter !== "recent") return rows;
    return [...rows].sort((a, b) => (b.last_used_at || b.updated_at || "").localeCompare(a.last_used_at || a.updated_at || "")).slice(0, 10);
  });

  async function loadCredentials() {
    if (!isUnlocked() || !project) return;
    const epoch = session.generation;
    const response = await request("list_credentials", filter === "project" ? { project } : { all_projects: true });
    if (epoch !== session.generation) return;
    if (!response.ok) { credentials = []; fail(response); return; }
    if (!Array.isArray(response.result.credentials) || !response.result.credentials.every((item) => typeof item.name === "string" && typeof item.type === "string" && typeof item.project === "string")) {
      credentials = []; feedback.message = "Invalid credential list"; return;
    }
    credentials = response.result.credentials;
  }

  async function credentialAction(method, credential) {
    if (session.busy) return;
    feedback.message = "";
    const owner = session.begin();
    const epoch = session.generation;
    const response = await request(method, { name: credential.name, project: credential.project || project, ...(["remove_credential", "rotate_credential"].includes(method) ? { destination_confirmed: true } : {}) });
    session.finish(owner);
    if (epoch === session.generation) {
      removeTarget = null;
      rotateTarget = null;
    }
    if (!response.ok) { if (epoch === session.generation) fail(response); else feedback.message = "The credential operation failed. Check its result before retrying."; return; }
    feedback.notice = method === "copy_token" ? "Token copied" : method === "rotate_credential" ? "Token rotated" : "Credential removed";
    if (method !== "copy_token") feedback.mutationNotice = feedback.notice;
    if (method !== "copy_token" && epoch === session.generation) await loadCredentials();
  }

  function clearPrivate() {
    credentials = [];
    removeTarget = null;
    rotateTarget = null;
  }

  function dismissReview() {
    if (!removeTarget && !rotateTarget) return false;
    removeTarget = null;
    rotateTarget = null;
    return true;
  }

  return {
    get project() { return project; }, set project(value) { project = value; },
    get credentials() { return credentials; },
    get filter() { return filter; }, set filter(value) { filter = value; },
    get search() { return search; }, set search(value) { search = value; },
    get removeTarget() { return removeTarget; }, set removeTarget(value) { removeTarget = value; },
    get rotateTarget() { return rotateTarget; }, set rotateTarget(value) { rotateTarget = value; },
    get filteredCredentials() { return filteredCredentials; },
    loadCredentials, credentialAction, clearPrivate, dismissReview,
  };
}
