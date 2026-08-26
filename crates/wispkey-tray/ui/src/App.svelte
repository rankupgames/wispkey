<script>
  import { onMount } from "svelte";

  const initialView =
    typeof window !== "undefined" && window.__WISPKEY_VIEW ? window.__WISPKEY_VIEW : "add";
  let view = $state(initialView);
  let mode = $state("single");
  let reveal = $state(false);
  let status = $state("");
  let credentials = $state([]);
  let startAtLogin = $state(false);
  let destinationConfirmed = $state(false);
  let form = $state({
    name: "",
    type: "bearer_token",
    value: "",
    description: "",
    tags: "",
    hosts: "",
    project: "",
    partition: "",
    headerName: "",
    paramName: "",
    namePrefix: "",
    applicationKey: "",
    applicationSecret: "",
    consumerKey: "",
    password: "",
  });

  window.__wispkeyPending = window.__wispkeyPending || {};
  window.__wispkeyResolve = function (id, payload) {
    const pending = window.__wispkeyPending[id];
    if (pending) {
      delete window.__wispkeyPending[id];
      pending(payload);
    }
  };

  function clearSecrets() {
    form.value = "";
    form.applicationKey = "";
    form.applicationSecret = "";
    form.consumerKey = "";
    form.password = "";
    reveal = false;
  }

  async function ipc(request) {
    return new Promise((resolve) => {
      const id = crypto.randomUUID();
      window.__wispkeyPending = window.__wispkeyPending || {};
      window.__wispkeyPending[id] = resolve;
      request.id = id;
      if (window.ipc && window.ipc.postMessage) {
        window.ipc.postMessage(JSON.stringify(request));
      } else {
        resolve({ ok: false, error: { message: "IPC unavailable" } });
      }
    });
  }

  async function copySecret(value) {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      status = "Copied";
    } catch (_error) {
      status = "Copy failed";
    }
  }

  async function save() {
    if (!destinationConfirmed) {
      status = "Confirm the destination before saving";
      return;
    }
    const response =
      mode === "ovh_api"
        ? await ipc({
            method: "add_template",
            params: {
              template: "ovh_api",
              name_prefix: form.namePrefix,
              application_key: form.applicationKey,
              application_secret: form.applicationSecret,
              consumer_key: form.consumerKey,
              project: form.project,
              partition: form.partition,
              hosts: form.hosts,
              tags: form.tags,
              destination_confirmed: true,
            },
          })
        : await ipc({
            method: "add_credential",
            params: {
              name: form.name,
              type: form.type,
              value: form.value,
              description: form.description,
              tags: form.tags,
              hosts: form.hosts,
              project: form.project,
              partition: form.partition,
              header_name: form.headerName,
              param_name: form.paramName,
              destination_confirmed: true,
            },
          });
    clearSecrets();
    destinationConfirmed = false;
    if (response.ok) {
      status = "Saved";
    } else {
      status = (response.error && response.error.message) || "Save failed";
    }
  }

  async function unlock() {
    const response = await ipc({
      method: "unlock",
      params: { password: form.password },
    });
    clearSecrets();
    status = response.ok ? "Unlocked" : (response.error && response.error.message) || "Unlock failed";
  }

  async function loadList() {
    const response = await ipc({ method: "list_credentials" });
    credentials = ((response.result || {}).credentials) || [];
  }

  async function loadSettings() {
    const response = await ipc({ method: "get_settings" });
    startAtLogin = !!(response.result || {}).start_at_login;
  }

  async function saveSettings() {
    const response = await ipc({
      method: "set_settings",
      params: { start_at_login: startAtLogin },
    });
    status = response.ok ? "Saved" : (response.error && response.error.message) || "Failed";
  }

  onMount(() => {
    if (view === "list") {
      void loadList();
    }
    if (view === "settings") {
      void loadSettings();
    }
    const timeoutId = setTimeout(() => {
      clearSecrets();
      status = "Secrets cleared after idle timeout";
    }, 120000);
    return () => clearTimeout(timeoutId);
  });
</script>

<main>
  <h1>WispKey</h1>
  {#if view === "add"}
    <label>Mode
      <select bind:value={mode}>
        <option value="single">Single credential</option>
        <option value="ovh_api">OVH API template</option>
      </select>
    </label>
    {#if mode === "ovh_api"}
      <label>Name prefix
        <input bind:value={form.namePrefix} />
      </label>
      <label>Application Key
        <input type={reveal ? "text" : "password"} bind:value={form.applicationKey} />
      </label>
      <button type="button" onclick={() => copySecret(form.applicationKey)}>Copy</button>
      <label>Application Secret
        <input type={reveal ? "text" : "password"} bind:value={form.applicationSecret} />
      </label>
      <button type="button" onclick={() => copySecret(form.applicationSecret)}>Copy</button>
      <label>Consumer Key
        <input type={reveal ? "text" : "password"} bind:value={form.consumerKey} />
      </label>
      <button type="button" onclick={() => copySecret(form.consumerKey)}>Copy</button>
    {:else}
      <label>Name
        <input bind:value={form.name} />
      </label>
      <label>Type
        <select bind:value={form.type}>
          <option value="bearer_token">bearer_token</option>
          <option value="api_key">api_key</option>
          <option value="basic_auth">basic_auth</option>
          <option value="custom_header">custom_header</option>
          <option value="query_param">query_param</option>
        </select>
      </label>
      {#if form.type === "custom_header"}
        <label>Header name
          <input bind:value={form.headerName} />
        </label>
      {/if}
      {#if form.type === "query_param"}
        <label>Param name
          <input bind:value={form.paramName} />
        </label>
      {/if}
      <label>Value
        <input type={reveal ? "text" : "password"} bind:value={form.value} />
      </label>
      <button type="button" onclick={() => copySecret(form.value)}>Copy</button>
      <label>Description
        <input bind:value={form.description} />
      </label>
    {/if}
    <label>Tags
      <input bind:value={form.tags} />
    </label>
    <label>Hosts
      <input bind:value={form.hosts} />
    </label>
    <label>Project
      <input bind:value={form.project} oninput={() => (destinationConfirmed = false)} />
    </label>
    <label>Partition
      <input bind:value={form.partition} oninput={() => (destinationConfirmed = false)} />
    </label>
    <label class="destination-confirmation">
      <input type="checkbox" bind:checked={destinationConfirmed} />
      Confirm save to project <strong>{form.project || "active project"}</strong>, partition <strong>{form.partition || "personal"}</strong>
    </label>
    <button type="button" onclick={() => (reveal = !reveal)}>Reveal</button>
    <button type="button" onclick={save}>Save</button>
    <button type="button" onclick={() => { clearSecrets(); window.close(); }}>Cancel</button>
  {:else if view === "list"}
    <button type="button" onclick={loadList}>Refresh</button>
    <ul>
      {#each credentials as credential (credential.name)}
        <li>{credential.name} · {credential.type}</li>
      {/each}
    </ul>
  {:else if view === "unlock"}
    <label>Master password
      <input type={reveal ? "text" : "password"} bind:value={form.password} />
    </label>
    <button type="button" onclick={() => (reveal = !reveal)}>Reveal</button>
    <button type="button" onclick={unlock}>Unlock</button>
    <button type="button" onclick={() => { clearSecrets(); window.close(); }}>Cancel</button>
  {:else}
    <label>
      <input type="checkbox" bind:checked={startAtLogin} />
      Start at login
    </label>
    <button type="button" onclick={saveSettings}>Save</button>
    <button type="button" onclick={loadSettings}>Reload</button>
  {/if}
  <p>{status}</p>
</main>
