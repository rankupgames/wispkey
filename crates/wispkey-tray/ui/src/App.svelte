<script>
  import { onMount } from "svelte";
  import Icon from "./Icon.svelte";
  import { request, cancelPending } from "./ipc.js";
  import "./app.css";

  const requestedView = window.__WISPKEY_VIEW;
  const initialView = ({ list: "credentials", add: "add", login: "add", unlock: "unlock", settings: "settings" })[requestedView] || "intake";
  let view = $state(initialView);
  let vault = $state(null);
  let message = $state("");
  let notice = $state("");
  let busy = $state(false);
  let menuOpen = $state(false);
  let dragging = $state(false);
  let root;
  let projects = $state([]);
  let partitions = $state([]);
  let project = $state("");
  let credentials = $state([]);
  let filter = $state("all");
  let search = $state("");
  let removeTarget = $state(null);
  let rotateTarget = $state(null);
  let password = $state("");
  let confirmation = $state("");
  let revealPassword = $state(false);
  let remember = $state(false);
  let revealSecret = $state(false);
  let destinationConfirmed = $state(false);
  let mode = $state(requestedView === "login" ? "website_login" : "single");
  let form = $state({ name: "", type: "bearer_token", value: "", project: "", partition: "", hosts: "", description: "", tags: "", header_name: "", param_name: "", username: "", url: "", name_prefix: "", application_key: "", application_secret: "", consumer_key: "" });
  let plan = $state(null);
  let importItems = $state([]);
  let environment = $state("");
  let rewriteHttp = $state(false);
  let outcome = $state(null);
  let clipboardName = $state("");
  let previewSource = null;
  let startAtLogin = $state(false);
  let autostartSupported = $state(false);
  let generation = 0;
  let idleTimer;

  const unlocked = $derived(vault?.initialized === true && vault?.session_active === true);
  const selectedItems = $derived(importItems.filter((item) => item.selected));
  const mixedEnvironments = $derived(new Set(importItems.map((item) => item.environment)).size > 1);
  const canRewrite = $derived(selectedItems.length > 0 && selectedItems.every(rewritable));
  const unresolved = $derived(selectedItems.filter((item) => (item.conflict_status === "scope_conflict") || (item.conflict && !item.action) || (item.needs_hosts && (!item.conflict || item.action !== "keep") && !meaningfulHosts(item.hosts))));
  const filteredCredentials = $derived.by(() => {
    const rows = credentials.filter((item) => item.name.toLowerCase().includes(search.toLowerCase()));
    if (filter !== "recent") return rows;
    return [...rows].sort((a, b) => (b.last_used_at || b.updated_at || "").localeCompare(a.last_used_at || a.updated_at || "")).slice(0, 10);
  });

  function rewritable(item) {
    return item.tokenizable && !(item.conflict && item.action === "keep") && /(?:^|[\\/])\.env(?:\.[^\\/]+)?$/.test(item.source || "");
  }

  function meaningfulHosts(value) {
    return value.split(",").map((host) => host.trim()).filter(Boolean).some((host) => /[a-zA-Z0-9]/.test(host));
  }

  function clearSecrets() {
    password = "";
    confirmation = "";
    revealPassword = false;
    revealSecret = false;
    form.value = "";
    form.username = "";
    clipboardName = "";
    form.application_key = "";
    form.application_secret = "";
    form.consumer_key = "";
    destinationConfirmed = false;
  }

  function discardPlan() {
    const id = plan?.plan_id;
    plan = null;
    importItems = [];
    outcome = null;
    previewSource = null;
    rewriteHttp = false;
    if (id) void request("import_cancel", { plan_id: id });
  }

  function clearPrivateState() {
    generation += 1;
    clearSecrets();
    discardPlan();
    removeTarget = null;
    rotateTarget = null;
    credentials = [];
    menuOpen = false;
  }

  function resetIdle() {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      clearPrivateState();
      view = unlocked ? "intake" : "unlock";
      notice = "Entered secrets cleared after inactivity";
    }, 120000);
  }

  function failure(response) {
    message = response.error?.message || "The operation failed";
    if (["locked", "session_expired", "not_initialized"].includes(response.error?.code)) {
      clearPrivateState();
      vault = { ...vault, session_active: false, initialized: response.error.code !== "not_initialized" };
      view = "unlock";
    }
  }

  async function refreshStatus() {
    const response = await request("status");
    if (!response.ok) { failure(response); return; }
    const next = response.result;
    if (typeof next.initialized !== "boolean" || typeof next.session_active !== "boolean") {
      clearPrivateState();
      vault = null;
      message = "Invalid vault status";
      return;
    }
    const wasUnlocked = unlocked;
    vault = next;
    if (!next.initialized || !next.session_active) {
      if (wasUnlocked) clearPrivateState();
      if (view !== "settings") view = "unlock";
    }
    if (!project && typeof next.active_project === "string") {
      project = next.active_project;
      form.project = project;
    }
  }

  async function loadScope() {
    const response = await request("list_projects");
    if (!response.ok) { failure(response); return; }
    if (!Array.isArray(response.result.projects)) { message = "Invalid project list"; return; }
    projects = response.result.projects;
    await loadPartitions(project);
  }

  async function loadPartitions(name) {
    if (!name) { partitions = []; return; }
    const response = await request("list_partitions", { project: name });
    if (!response.ok) { partitions = []; failure(response); return; }
    if (!Array.isArray(response.result.partitions)) { message = "Invalid environment list"; return; }
    partitions = response.result.partitions;
    if (!form.partition && partitions.length === 1) form.partition = partitions[0].name;
  }

  async function navigate(next) {
    menuOpen = false;
    message = "";
    notice = "";
    clearSecrets();
    if (plan) discardPlan();
    view = next;
    if (next === "credentials") await loadCredentials();
    if (next === "add") {
      form.project = project;
      await loadPartitions(form.project);
    }
    if (next === "settings") await loadSettings();
  }

  async function unlockVault(event) {
    event.preventDefault();
    if (busy) return;
    message = "";
    if (!vault?.initialized && (!password || password !== confirmation)) {
      message = "Passwords must match";
      clearSecrets();
      return;
    }
    busy = true;
    const response = await request(vault.initialized ? "unlock" : "initialize", vault.initialized
      ? { password, remember }
      : { password, password_confirmation: confirmation });
    clearSecrets();
    busy = false;
    if (!response.ok) { failure(response); return; }
    await refreshStatus();
    if (!unlocked) { message = "The vault is still locked"; return; }
    view = "intake";
    await loadScope();
  }

  async function lockVault() {
    clearPrivateState();
    busy = true;
    const response = await request("lock");
    busy = false;
    if (!response.ok) { failure(response); return; }
    vault = { ...vault, session_active: false };
    view = "unlock";
    message = "";
  }

  async function loadCredentials() {
    if (!unlocked || !project) return;
    const epoch = generation;
    const response = await request("list_credentials", filter === "project" ? { project } : { all_projects: true });
    if (epoch !== generation) return;
    if (!response.ok) { credentials = []; failure(response); return; }
    if (!Array.isArray(response.result.credentials) || !response.result.credentials.every((item) => typeof item.name === "string" && typeof item.type === "string" && typeof item.project === "string")) {
      credentials = []; message = "Invalid credential list"; return;
    }
    credentials = response.result.credentials;
  }

  async function credentialAction(method, credential) {
    message = "";
    busy = true;
    const response = await request(method, { name: credential.name, project: credential.project || project, ...(["remove_credential", "rotate_credential"].includes(method) ? { destination_confirmed: true } : {}) });
    busy = false;
    removeTarget = null;
    rotateTarget = null;
    if (!response.ok) { failure(response); return; }
    notice = method === "copy_token" ? "Token copied" : method === "rotate_credential" ? "Token rotated" : "Credential removed";
    if (method !== "copy_token") await loadCredentials();
  }

  async function createScope(kind) {
    const name = kind === "project" ? form.project : form.partition;
    if (!name.trim()) { message = "Enter a name before creating it"; return; }
    const response = await request(kind === "project" ? "create_project" : "create_partition", kind === "project" ? { name, destination_confirmed: true } : { project: form.project, name, destination_confirmed: true });
    if (!response.ok) { failure(response); return; }
    await loadScope();
    await loadPartitions(form.project);
    notice = kind === "project" ? "Project created" : "Environment created";
  }

  async function saveCredential(event) {
    event.preventDefault();
    message = "";
    notice = "";
    if (!destinationConfirmed || !form.project || !form.partition) { message = "Confirm the destination before saving"; return; }
    if ((mode === "ovh_api" || (mode === "single" && form.type !== "api_key")) && !meaningfulHosts(form.hosts)) { message = "Enter a hostname or a bounded host pattern"; return; }
    busy = true;
    let method;
    let params;
    if (mode === "website_login") {
      method = "generate_login";
      params = { name: form.name, username: form.username, url: form.url, project: form.project, partition: form.partition, destination_confirmed: true };
    } else if (mode === "ovh_api") {
      method = "add_template";
      params = { template: "ovh_api", name_prefix: form.name_prefix, application_key: form.application_key, application_secret: form.application_secret, consumer_key: form.consumer_key, hosts: form.hosts, tags: form.tags, project: form.project, partition: form.partition, destination_confirmed: true };
    } else {
      method = "add_credential";
      params = { name: form.name, type: form.type, value: form.value, project: form.project, partition: form.partition, hosts: form.hosts, description: form.description, tags: form.tags, header_name: form.header_name, param_name: form.param_name, destination_confirmed: true };
    }
    const epoch = generation;
    const response = await request(method, params);
    clearSecrets();
    busy = false;
    if (epoch !== generation) return;
    if (!response.ok) { failure(response); return; }
    notice = mode === "website_login" ? "Login saved" : "Saved";
  }

  async function previewImport(params, method = "import_preview") {
    if (!unlocked || busy) return;
    discardPlan();
    message = "";
    notice = "";
    busy = true;
    view = "scanning";
    const epoch = generation;
    const response = await request(method, { ...params, project });
    busy = false;
    if (epoch !== generation) {
      if (response.ok && response.result.plan_id) void request("import_cancel", { plan_id: response.result.plan_id });
      return;
    }
    if (!response.ok) {
      if (method === "clipboard_import" && response.error.code === "clipboard_name_required") {
        clipboardName = "";
        view = "clipboard_name";
        return;
      }
      view = "intake"; failure(response); return;
    }
    const next = response.result;
    if (typeof next.plan_id !== "string" || !Array.isArray(next.items) || !next.items.every((item) => typeof item.id === "string" && typeof item.key === "string" && typeof item.type === "string" && typeof item.conflict === "boolean" && typeof item.needs_hosts === "boolean" && typeof item.tokenizable === "boolean" && typeof item.environment === "string" && item.environment.trim().length > 0)) {
      if (typeof next.plan_id === "string") void request("import_cancel", { plan_id: next.plan_id });
      message = "Invalid import review";
      view = "intake";
      return;
    }
    plan = next;
    previewSource = { method, params };
    importItems = next.items.map((item) => ({ ...item, selected: true, hosts: Array.isArray(item.hosts) ? item.hosts.join(", ") : "", action: item.conflict ? "" : "keep" }));
    environment = next.items.length && next.items.every((item) => item.environment === next.items[0].environment) ? next.items[0].environment : "";
    destinationConfirmed = false;
    view = "review";
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
    message = "";
    const response = await request(directory ? "choose_import_directory" : "choose_import_files");
    if (!response.ok) { failure(response); return; }
    if (response.result.cancelled === true) return;
    if (!Array.isArray(response.result.paths) || !response.result.paths.length) { message = "No source was selected"; return; }
    await previewImport(directory ? { directory: response.result.paths[0] } : { paths: response.result.paths });
  }

  async function commitImport(event) {
    event.preventDefault();
    if (!plan || busy || !destinationConfirmed || !project || (!environment && !mixedEnvironments) || !selectedItems.length || unresolved.length) return;
    busy = true;
    message = "";
    const epoch = generation;
    const response = await request("import_commit", { plan_id: plan.plan_id, project, environment, items: importItems.map(({ id, selected, hosts, action, environment }) => ({ id, selected, hosts, action, environment })), rewrite_http: rewriteHttp && canRewrite, destination_confirmed: true });
    busy = false;
    destinationConfirmed = false;
    if (epoch !== generation) return;
    if (!response.ok) { failure(response); return; }
    const result = response.result;
    if (!Number.isInteger(result.imported) || !Array.isArray(result.files)) { message = "Invalid import result. Check the vault before retrying."; return; }
    outcome = result;
    plan = null;
    importItems = [];
    view = "import_done";
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
    notice = "Settings saved";
  }

  function closeMenus(event) {
    if (!event.target.closest(".navigation")) menuOpen = false;
  }

  function escape(event) {
    if (event.key !== "Escape") return;
    if (menuOpen) { menuOpen = false; root?.querySelector(".menu-button")?.focus(); }
    else if (removeTarget || rotateTarget) { removeTarget = null; rotateTarget = null; }
    else if (!busy && (plan || view === "clipboard_name")) void navigate("intake");
    else if (!busy) {
      if (unlocked) void navigate("intake");
      void request("close_window");
    }
    clearSecrets();
  }

  onMount(() => {
    let alive = true;
    let polling = false;
    const start = async () => {
      await refreshStatus();
      if (!alive || !unlocked) return;
      await loadScope();
      if (view === "credentials") await loadCredentials();
      if (view === "settings") await loadSettings();
    };
    void start();
    const poll = setInterval(() => {
      if (!alive || polling || document.hidden) return;
      polling = true;
      void refreshStatus().then(() => { polling = false; });
    }, 2000);
    window.__wispkeyFiles = (paths) => {
      dragging = false;
      if (!Array.isArray(paths) || !paths.length) { message = "No files were dropped"; return; }
      void previewImport({ paths });
    };
    window.__wispkeyDrag = (active) => { dragging = active === true; };
    window.__wispkeyBlur = () => {
      clearPrivateState();
      busy = false;
      dragging = false;
      view = unlocked ? "intake" : "unlock";
      message = "";
      notice = "";
    };
    const hidden = () => {
      if (!document.hidden) { void refreshStatus(); return; }
      clearPrivateState();
      view = "intake";
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
    resetIdle();
    return () => {
      alive = false;
      clearInterval(poll);
      clearTimeout(idleTimer);
      observer.disconnect();
      document.removeEventListener("visibilitychange", hidden);
      delete window.__wispkeyFiles;
      delete window.__wispkeyDrag;
      delete window.__wispkeyBlur;
      clearPrivateState();
      cancelPending();
    };
  });
</script>

<svelte:window onkeydown={(event) => { escape(event); resetIdle(); }} onpointerdown={(event) => { closeMenus(event); resetIdle(); }} />
<main bind:this={root}>
  <header>
    {#if unlocked}
      <div class="navigation" onpointerleave={() => (menuOpen = false)}>
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
      <form class="vault-form" onsubmit={unlockVault}>
        <label for="master-password">Master password</label>
        <div class="password-input" class:invalid={!!message}>
          <input id="master-password" type={revealPassword ? "text" : "password"} bind:value={password} autocomplete={vault.initialized ? "current-password" : "new-password"} required disabled={busy} />
          <button type="button" class="icon-button reveal" aria-label={revealPassword ? "Hide password" : "Show password"} aria-pressed={revealPassword} onclick={() => (revealPassword = !revealPassword)}><Icon name="eye" /></button>
          {#if vault.initialized}<button class="primary inline-unlock" type="submit" disabled={busy}>Unlock</button>{/if}
        </div>
        {#if message}<p class="error-text" role="alert">{message}</p>{/if}
        {#if !vault.initialized}
          <label for="confirm-password">Confirm password</label><input id="confirm-password" type="password" bind:value={confirmation} autocomplete="new-password" required disabled={busy} />
          <p class="muted">A lost master password cannot be reset.</p>
          <button class="primary" type="submit" disabled={busy}>Create vault</button>
        {:else}
          <label class="check remember"><input type="checkbox" bind:checked={remember} disabled={busy} />Remember this device</label>
        {/if}
      </form>
    {:else if view === "intake"}
      <div class="dropzone" class:dragging>
        <button class="drop-target" aria-label="Choose files to import" disabled={busy} onclick={() => chooseSource(false)}><span class="drop-icon"><Icon name="download" size={20} /></span><strong>{dragging ? "Release to scan files" : "Drop secrets or config files"}</strong><span class="muted">.env, JSON or key files</span></button>
        <div class="intake-actions">
          <button disabled={busy} onclick={() => previewImport({}, "clipboard_import")}><Icon name="clipboard" size={14} />Clipboard import</button>
          <button disabled={busy} onclick={() => chooseSource(true)}><Icon name="folder" size={14} />Import project</button>
          <button disabled={busy} onclick={() => navigate("add")}><Icon name="plus" size={14} />Add credential</button>
        </div>
      </div>
    {:else if view === "add"}
      <form onsubmit={saveCredential}>
        <h1><button type="button" class="icon-button back" aria-label="Back to intake" onclick={() => navigate("intake")}><Icon name="back" size={14} /></button>{mode === "website_login" ? "Generate website login" : "Add credential"}</h1>
        <label for="entry-mode">Entry</label><select id="entry-mode" bind:value={mode} onchange={() => { clearSecrets(); message = ""; }}><option value="single">Single credential</option><option value="ovh_api">OVH API template</option><option value="website_login">Generated website login</option></select>
        <label for="credential-name">{mode === "ovh_api" ? "Name prefix" : "Name"}</label>{#if mode === "ovh_api"}<input id="credential-name" class="mono" bind:value={form.name_prefix} required />{:else}<input id="credential-name" class="mono" bind:value={form.name} required />{/if}
        <div class="field-row">
          <div><label for="credential-project">Project</label><input id="credential-project" list="projects" bind:value={form.project} oninput={() => (destinationConfirmed = false)} onchange={() => { form.partition = ""; void loadPartitions(form.project); }} required /></div>
          {#if mode === "single"}<div><label for="credential-type">Type</label><select id="credential-type" bind:value={form.type}><option value="bearer_token">Bearer token</option><option value="api_key">Secret</option><option value="basic_auth">Basic auth</option><option value="custom_header">Custom header</option><option value="query_param">Query parameter</option></select></div>{/if}
          <div><label for="credential-partition">Partition</label><input id="credential-partition" list="partitions" bind:value={form.partition} oninput={() => (destinationConfirmed = false)} required /></div>
        </div>
        {#if form.project && !projects.some((item) => item.name === form.project)}<button type="button" class="text-button" onclick={() => createScope("project")}>Create project</button>{/if}
        {#if form.partition && !partitions.some((item) => item.name === form.partition)}<button type="button" class="text-button" onclick={() => createScope("partition")}>Create environment</button>{/if}
        {#if mode === "website_login"}
          <label for="login-username">Username or email</label><input id="login-username" bind:value={form.username} autocomplete="off" required />
          <label for="login-url">Website URL (HTTPS)</label><input id="login-url" type="url" bind:value={form.url} required />
        {:else}
          <label for="credential-hosts">Allowed hosts</label><input id="credential-hosts" class="mono" bind:value={form.hosts} aria-invalid={form.hosts.length > 0 && !meaningfulHosts(form.hosts)} />
          {#if form.type === "custom_header"}<label for="header-name">Header name</label><input id="header-name" bind:value={form.header_name} required />{/if}
          {#if form.type === "query_param"}<label for="param-name">Parameter name</label><input id="param-name" bind:value={form.param_name} required />{/if}
          {#if mode === "ovh_api"}
            <label for="application-key">Application key</label><input id="application-key" type={revealSecret ? "text" : "password"} bind:value={form.application_key} autocomplete="off" required />
            <label for="application-secret">Application secret</label><input id="application-secret" type={revealSecret ? "text" : "password"} bind:value={form.application_secret} autocomplete="off" required />
            <label for="consumer-key">Consumer key</label><input id="consumer-key" type={revealSecret ? "text" : "password"} bind:value={form.consumer_key} autocomplete="off" required />
          {:else}
            <label for="credential-secret">Secret</label><div class="password-input"><input id="credential-secret" type={revealSecret ? "text" : "password"} bind:value={form.value} autocomplete="off" required /><button type="button" class="icon-button reveal" aria-label={revealSecret ? "Hide secret" : "Show secret"} aria-pressed={revealSecret} onclick={() => (revealSecret = !revealSecret)}><Icon name="eye" /></button></div>
          {/if}
        {/if}
        <label class="check destination"><input type="checkbox" bind:checked={destinationConfirmed} />Save to {form.project || "selected project"} / {form.partition || "selected partition"}</label>
        <div class="actions"><button type="button" disabled={busy} onclick={() => navigate("intake")}>Cancel</button><button class="primary" type="submit" disabled={busy}>{mode === "website_login" ? "Generate and save" : "Save"}</button></div>
      </form>
    {:else if view === "credentials"}
      <div class="title-row"><h1>Credentials</h1><span class="muted">{filteredCredentials.length} of {credentials.length}</span></div>
      <div class="filters" aria-label="Credential filters">{#each [["all", "All"], ["recent", "Recent"], ["project", "By project"]] as [value, label]}<button class:active={filter === value} aria-pressed={filter === value} onclick={() => { filter = value; void loadCredentials(); }}>{label}</button>{/each}</div>
      <div class="field-row">{#if filter === "project"}<div><label for="list-project">Project</label><select id="list-project" bind:value={project} onchange={loadCredentials}>{#each projects as item}<option value={item.name}>{item.name}</option>{/each}</select></div>{/if}<div><label for="search-credentials">Search</label><input id="search-credentials" type="search" bind:value={search} /></div></div>
      {#if !credentials.length}<p class="muted">No credentials in this project.</p>{:else}
        <ul class="credential-list">{#each filteredCredentials as credential (`${credential.project || project}:${credential.id || credential.name}`)}<li><div class="credential-row"><div class="grow"><strong>{credential.name}</strong><span class="muted">{credential.project || project} · {credential.partition || credential.type}</span></div><button class="icon-button" aria-label={`Copy token for ${credential.name}`} disabled={busy} onclick={() => credentialAction("copy_token", credential)}><Icon name="copy" size={14} /></button><button class="icon-button" aria-label={`Rotate token for ${credential.name}`} disabled={busy} onclick={() => { rotateTarget = credential; removeTarget = null; }}><Icon name="refresh" size={14} /></button><button class="icon-button danger" aria-label={`Remove ${credential.name}`} disabled={busy} onclick={() => { removeTarget = credential; rotateTarget = null; }}><Icon name="trash" size={14} /></button></div>{#if rotateTarget === credential}<div class="delete-review"><span>Rotate the token for {credential.name} in {credential.project || project}? The current token will stop working.</span><div class="actions"><button onclick={() => (rotateTarget = null)}>Cancel</button><button class="primary" disabled={busy} onclick={() => credentialAction("rotate_credential", credential)}>Rotate token</button></div></div>{/if}{#if removeTarget === credential}<div class="delete-review"><span>Remove {credential.name} from {credential.project || project}?</span><div class="actions"><button onclick={() => (removeTarget = null)}>Cancel</button><button class="danger-button" disabled={busy} onclick={() => credentialAction("remove_credential", credential)}>Remove credential</button></div></div>{/if}</li>{/each}</ul>
      {/if}
    {:else if view === "clipboard_name"}
      <form onsubmit={(event) => { event.preventDefault(); if (clipboardName.trim()) void previewImport({ name: clipboardName.trim() }, "clipboard_import"); }}>
        <h1>Clipboard import</h1>
        <label for="clipboard-name">Name</label><input id="clipboard-name" class="mono" bind:value={clipboardName} required />
        <div class="actions"><button type="button" onclick={() => navigate("intake")}>Cancel</button><button type="submit" class="primary" disabled={busy || !clipboardName.trim()}>Import clipboard</button></div>
      </form>
    {:else if view === "scanning"}
      <h1>Scanning local sources</h1><progress aria-label="Scanning local sources"></progress>
    {:else if view === "review" && plan}
      <form onsubmit={commitImport}>
        <div class="title-row"><h1>Review import</h1><span class="muted">{selectedItems.length} of {importItems.length} selected</span></div>
        <div class="field-row"><div><label for="import-project">Project</label><input id="import-project" list="projects" bind:value={project} oninput={() => (destinationConfirmed = false)} onchange={repreviewDestination} required /></div><div><label for="import-environment">Environment</label><input id="import-environment" list="partitions" bind:value={environment} oninput={() => (destinationConfirmed = false)} onchange={repreviewDestination} required={!mixedEnvironments} placeholder={mixedEnvironments ? "From source files" : ""} /></div></div>
        <ul class="import-list">{#each importItems as item (item.id)}<li class:conflict={item.conflict && item.selected}><div class="import-row"><input type="checkbox" aria-label={`Import ${item.key}`} bind:checked={item.selected} onchange={() => { rewriteHttp = false; destinationConfirmed = false; }} /><span class="mono grow">{item.key}</span><span class="muted source" title={`${item.environment} · ${item.source}`}>{item.environment} · {item.source}</span></div>{#if item.selected}{#if item.needs_hosts && item.conflict_status !== "scope_conflict"}<input id={`hosts-${item.id}`} class="mono" aria-label={`Allowed hosts for ${item.key}`} bind:value={item.hosts} placeholder="Allowed hosts" aria-invalid={(!item.conflict || item.action !== "keep") && !meaningfulHosts(item.hosts)} />{:else if item.hosts}<span class="mono muted">{item.hosts}</span>{/if}{#if item.conflict}<span class="error-text">{item.conflict_status === "scope_conflict" ? "Stored scope differs. Skip this item or change the destination." : "Stored value differs. Choose how to proceed."}</span><div class="segments" aria-label={`Conflict for ${item.key}`}>{#if item.conflict_status !== "scope_conflict"}<button type="button" class:active={item.action === "keep"} onclick={() => { item.action = "keep"; rewriteHttp = false; }}>Keep stored</button><button type="button" class:active={item.action === "replace"} onclick={() => (item.action = "replace")}>Replace</button>{/if}<button type="button" class:active={item.action === "skip"} onclick={() => { item.action = "skip"; item.selected = false; rewriteHttp = false; destinationConfirmed = false; }}>Skip</button></div>{/if}{/if}</li>{/each}</ul>
        {#each plan.warnings || [] as warning}<p class="warning">{warning.source ? `${warning.source}: ` : ""}{warning.message}</p>{/each}
        <span class="field-label">Source files</span><div class="segments"><button type="button" class:active={!rewriteHttp} aria-pressed={!rewriteHttp} onclick={() => (rewriteHttp = false)}>Store only</button><button type="button" class:active={rewriteHttp} aria-pressed={rewriteHttp} disabled={!canRewrite} onclick={() => (rewriteHttp = true)}>Replace HTTP values with tokens</button></div>
        <label class="check destination"><input type="checkbox" bind:checked={destinationConfirmed} />Save to {project || "selected project"} / {environment || (mixedEnvironments ? "source environments" : "selected environment")}</label>
        <div class="actions"><span class="warning-text grow">{unresolved.length ? `Resolve ${unresolved.length} items to import` : ""}</span><button type="button" disabled={busy} onclick={() => navigate("intake")}>Cancel</button><button class="primary" type="submit" disabled={busy || !destinationConfirmed || !selectedItems.length || !!unresolved.length}>Import {selectedItems.length}</button></div>
      </form>
    {:else if view === "import_done" && outcome}
      <div class="completion"><span class:warning-icon={outcome.files.some((file) => file.status === "failed")} class="completion-icon"><Icon name={outcome.files.some((file) => file.status === "failed") ? "alert" : "check"} size={22} /></span><h1>{outcome.imported} {outcome.imported === 1 ? "credential" : "credentials"} stored</h1></div>
      <ul class="result-list">{#each outcome.files as file}<li><span class="mono grow">{file.path}</span><span class:error-text={file.status === "failed"} class="muted">{file.status === "updated" ? "Tokens written" : file.status === "failed" ? "Not changed" : "Unchanged"}</span>{#if file.message}<p class="error-text">{file.message}</p>{/if}</li>{/each}</ul>
      {#if outcome.files.some((file) => file.status === "failed")}<p class="warning">Credentials were saved. Review the source files before retrying.</p>{/if}
      <div class="actions"><button onclick={() => navigate("credentials")}>View in Credentials</button><button class="primary" onclick={() => navigate("intake")}>Done</button></div>
    {/if}
    {#if message && (unlocked || view === "settings" || !vault)}<p class="error-text feedback" role="alert">{message}</p>{/if}
    {#if notice}<p class="feedback" role="status">{notice}</p>{/if}
  </section>
  <datalist id="projects">{#each projects as item}<option value={item.name}></option>{/each}</datalist>
  <datalist id="partitions">{#each partitions as item}<option value={item.name}></option>{/each}</datalist>
</main>
