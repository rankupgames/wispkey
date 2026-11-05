<script>
  import { onMount } from "svelte";
  import Icon from "./Icon.svelte";
  import Unlock from "./Unlock.svelte";
  import AddCredential from "./AddCredential.svelte";
  import Credentials from "./Credentials.svelte";
  import Intake from "./Intake.svelte";
  import { request, cancelPending } from "./ipc.js";
  import { createSession } from "./session.svelte.js";
  import { createCredentialEntry } from "./credential-entry.svelte.js";
  import { createInventory } from "./inventory.svelte.js";
  import { createIntake } from "./intake.svelte.js";
  import "./app.css";

  const requestedView = window.__WISPKEY_VIEW;
  const initialView = ({ list: "credentials", add: "add", login: "add", unlock: "unlock", settings: "settings" })[requestedView] || "intake";
  const navigation = $state({ view: initialView });
  const feedback = $state({ message: "", notice: "", mutationNotice: "" });
  const fields = $state({ password: "", confirmation: "", revealPassword: false, remember: false });
  const session = createSession({ request, cancelPending });
  const entry = createCredentialEntry({ session, request, feedback, fail: failure, loadProjects, requestedView });
  const inventory = createInventory({ session, request, feedback, fail: failure, isUnlocked: () => unlocked });
  const intake = createIntake({ session, request, feedback, fail: failure, isUnlocked: () => unlocked, navigation });
  let vault = $state(null);
  let menuOpen = $state(false);
  let dragging = $state(false);
  let projects = $state([]);
  let startAtLogin = $state(false);
  let autostartSupported = $state(false);
  let root;
  let scopeInitialized = false;
  const view = $derived(navigation.view);
  const busy = $derived(session.busy);
  const message = $derived(feedback.message);
  const notice = $derived(feedback.notice);
  const unlocked = $derived(vault?.initialized === true && vault?.session_active === true);

  function clearSecrets() {
    fields.password = "";
    fields.confirmation = "";
    fields.revealPassword = false;
    entry.clearSecrets();
    intake.clearSecrets();
  }

  function clearPrivateState() {
    session.invalidate();
    clearSecrets();
    intake.clearPrivate();
    if (view === "scanning") session.abandonPreview();
    inventory.clearPrivate();
    menuOpen = false;
  }

  function privateView() {
    return unlocked ? intake.outcome ? "import_done" : "intake" : "unlock";
  }

  async function enterUnlocked() {
    navigation.view = "intake";
    await loadScope();
  }

  function failure(response) {
    feedback.message = response.error?.message || "The operation failed";
    if (["locked", "session_expired", "not_initialized"].includes(response.error?.code)) {
      clearPrivateState();
      vault = { ...vault, session_active: false, initialized: response.error.code !== "not_initialized" };
      navigation.view = "unlock";
    }
  }

  async function refreshStatus() {
    const response = await request("status");
    if (!response.ok) { failure(response); return; }
    const next = response.result;
    if (typeof next.initialized !== "boolean" || typeof next.session_active !== "boolean") {
      clearPrivateState();
      vault = null;
      feedback.message = "Invalid vault status";
      return;
    }
    const wasUnlocked = unlocked;
    vault = next;
    if (!next.initialized || !next.session_active) {
      if (wasUnlocked) clearPrivateState();
      if (view !== "settings") navigation.view = "unlock";
    }
    if (!scopeInitialized && typeof next.active_project === "string") {
      entry.form.project = next.active_project;
      intake.project = next.active_project;
      inventory.project = next.active_project;
      scopeInitialized = true;
    }
    if (!wasUnlocked && unlocked && view === "unlock") await enterUnlocked();
  }

  async function loadProjects() {
    const response = await request("list_projects");
    if (!response.ok) { failure(response); return; }
    if (!Array.isArray(response.result.projects)) { feedback.message = "Invalid project list"; return; }
    projects = response.result.projects;
  }

  async function loadScope() {
    await loadProjects();
    if (view === "add") await entry.loadPartitions(entry.form.project);
    else await intake.loadPartitions();
  }

  async function navigate(next) {
    session.invalidate();
    menuOpen = false;
    feedback.message = "";
    feedback.notice = "";
    feedback.mutationNotice = "";
    clearSecrets();
    if (view === "scanning") session.abandonPreview();
    intake.discardPlan();
    intake.outcome = null;
    navigation.view = next;
    if (next === "credentials") await inventory.loadCredentials();
    if (next === "add") await entry.loadPartitions(entry.form.project);
    if (next === "settings") await loadSettings();
  }

  async function unlockVault(event) {
    event.preventDefault();
    if (busy) return;
    feedback.message = "";
    if (!vault?.initialized && (!fields.password || fields.password !== fields.confirmation)) {
      feedback.message = "Passwords must match";
      clearSecrets();
      return;
    }
    const owner = session.begin();
    const epoch = session.generation;
    const response = await request(vault.initialized ? "unlock" : "initialize", vault.initialized
      ? { password: fields.password, remember: fields.remember }
      : { password: fields.password, password_confirmation: fields.confirmation });
    if (epoch === session.generation) clearSecrets();
    session.finish(owner);
    if (!response.ok) { failure(response); return; }
    await refreshStatus();
    if (!unlocked) { feedback.message = "The vault is still locked"; return; }
    if (view === "unlock") await enterUnlocked();
  }

  async function lockVault() {
    clearPrivateState();
    const owner = session.begin();
    const response = await request("lock");
    session.finish(owner);
    if (!response.ok) { failure(response); return; }
    vault = { ...vault, session_active: false };
    navigation.view = "unlock";
    feedback.message = "";
  }

  async function loadSettings() {
    const response = await request("get_settings");
    if (!response.ok) { failure(response); return; }
    startAtLogin = response.result.start_at_login === true;
    autostartSupported = response.result.start_at_login_supported === true;
  }

  async function saveSettings() {
    const response = await request("set_settings", { start_at_login: startAtLogin });
    if (!response.ok) { failure(response); return; }
    feedback.notice = "Settings saved";
  }

  function closeMenus(event) {
    if (!event.target.closest(".navigation")) menuOpen = false;
  }

  function escape(event) {
    if (event.key !== "Escape") return;
    if (menuOpen) { menuOpen = false; root?.querySelector(".menu-button")?.focus(); }
    else if (!inventory.dismissReview() && !busy) {
      if (intake.plan || view === "clipboard_name") void navigate("intake");
      else {
        if (unlocked) void navigate("intake");
        void request("close_window");
      }
    }
    clearSecrets();
  }

  onMount(() => session.bindWindow({
    root,
    start: async (isAlive) => {
      await refreshStatus();
      if (!isAlive() || !unlocked) return;
      await loadScope();
      if (view === "credentials") await inventory.loadCredentials();
      if (view === "settings") await loadSettings();
    },
    refreshStatus,
    filesDropped: (paths) => {
      if (!Array.isArray(paths) || !paths.length) { feedback.message = "No files were dropped"; return; }
      void intake.previewImport({ paths });
    },
    setDragging: (active) => { dragging = active; },
    clearPrivate: (reason) => {
      clearPrivateState();
      navigation.view = privateView();
      if (reason === "blur") {
        feedback.message = "";
        feedback.notice = feedback.mutationNotice;
      }
      if (reason === "idle") feedback.notice = "Entered secrets cleared after inactivity";
    },
  }));
</script>

<svelte:window onkeydown={(event) => { escape(event); session.activity(); }} onpointerdown={(event) => { closeMenus(event); session.activity(); }} />
<main bind:this={root}>
  <header>
    {#if unlocked}
      <div class="navigation" role="group" onpointerleave={() => (menuOpen = false)}>
        <button class="icon-button menu-button" aria-label="Navigation" aria-expanded={menuOpen} aria-controls="navigation-menu" onpointerenter={() => (menuOpen = true)} onfocus={() => (menuOpen = true)} onclick={() => (menuOpen = true)}><Icon name="menu" /></button>
        {#if menuOpen}
          <nav id="navigation-menu" aria-label="Local navigation">
            <button class:active={view === "intake"} onclick={() => navigate("intake")}><Icon name="download" />Intake</button>
            <button class:active={view === "credentials"} onclick={() => navigate("credentials")}><Icon name="key" />Credentials</button>
            <button class:active={view === "add"} onclick={() => navigate("add")}><Icon name="plus" />Add credential</button>
          </nav>
        {/if}
      </div>
    {/if}
    <span class="logo" role="img" aria-label="WispKey"><Icon name="key" /></span>
    <span class="spacer"></span>
    <button class="lock-control" disabled={!unlocked || busy} aria-label={unlocked ? "Lock vault" : vault?.initialized === false ? "No vault" : "Vault locked"} onclick={lockVault}><Icon name={unlocked ? "unlock" : "lock"} />{vault?.initialized === false ? "No vault" : unlocked ? "Unlocked" : "Locked"}</button>
    <button class="icon-button" aria-label="Settings" onclick={() => navigate("settings")}><Icon name="settings" /></button>
  </header>
  <section class="content" aria-busy={busy}>
    {#if !vault}
      <div class="empty"><p>Connecting to vault</p><button onclick={refreshStatus}>Retry</button></div>
    {:else if view === "settings"}
      <h1>Settings</h1>
      <label class="check"><input type="checkbox" bind:checked={startAtLogin} disabled={!autostartSupported} />Start at login</label>
      {#if !autostartSupported}<p class="muted">Start at login is not supported on this platform.</p>{/if}
      <div class="actions"><button onclick={() => navigate(unlocked ? "intake" : "unlock")}>Back</button><button class="primary" disabled={!autostartSupported} onclick={saveSettings}>Save</button></div>
    {:else if !unlocked}
      <Unlock {vault} {fields} {message} {busy} {unlockVault} />
    {:else if view === "add"}
      <AddCredential {entry} {projects} {busy} {feedback} {navigate} />
    {:else if view === "credentials"}
      <Credentials {inventory} {projects} {busy} />
    {:else}
      <Intake {intake} {view} {dragging} {busy} {navigate} />
    {/if}
    {#if message && (unlocked || view === "settings" || !vault)}<p class="error-text feedback" role="alert">{message}</p>{/if}
    {#if notice}<p class="feedback" role="status">{notice}</p>{/if}
  </section>
  <datalist id="projects">{#each projects as item}<option value={item.name}></option>{/each}</datalist>
</main>
