<script>
  import Icon from "./Icon.svelte";
  import { meaningfulHosts } from "./hosts.js";
  let { entry, projects, busy, feedback, navigate } = $props();
</script>

<form onsubmit={entry.saveCredential}>
  <h1><button type="button" class="icon-button back" aria-label="Back to intake" onclick={() => navigate("intake")}><Icon name="back" size={14} /></button>{entry.mode === "website_login" ? "Generate website login" : "Add credential"}</h1>
  <label for="entry-mode">Entry</label><select id="entry-mode" bind:value={entry.mode} onchange={() => { entry.clearSecrets(); feedback.message = ""; }}><option value="single">Single credential</option><option value="ovh_api">OVH API template</option><option value="website_login">Generated website login</option></select>
  <label for="credential-name">{entry.mode === "ovh_api" ? "Name prefix" : "Name"}</label>{#if entry.mode === "ovh_api"}<input id="credential-name" class="mono" bind:value={entry.form.name_prefix} required />{:else}<input id="credential-name" class="mono" bind:value={entry.form.name} required />{/if}
  <div class="field-row">
    <div><label for="credential-project">Project</label><input id="credential-project" list="projects" bind:value={entry.form.project} oninput={() => (entry.destinationConfirmed = false)} onchange={() => { entry.form.partition = ""; void entry.loadPartitions(entry.form.project); }} required /></div>
    {#if entry.mode === "single"}<div><label for="credential-type">Type</label><select id="credential-type" bind:value={entry.form.type}><option value="bearer_token">Bearer token</option><option value="api_key">Secret</option><option value="basic_auth">Basic auth</option><option value="custom_header">Custom header</option><option value="query_param">Query parameter</option></select></div>{/if}
    <div><label for="credential-partition">Partition</label><input id="credential-partition" list="partitions" bind:value={entry.form.partition} oninput={() => (entry.destinationConfirmed = false)} required /></div>
  </div>
  {#if entry.form.project && !projects.some((item) => item.name === entry.form.project)}<button type="button" class="text-button" onclick={() => entry.createScope("project")}>Create project</button>{/if}
  {#if entry.form.partition && !entry.partitions.some((item) => item.name === entry.form.partition)}<button type="button" class="text-button" onclick={() => entry.createScope("partition")}>Create environment</button>{/if}
  {#if entry.mode === "website_login"}
    <label for="login-username">Username or email</label><input id="login-username" bind:value={entry.form.username} autocomplete="off" required />
    <label for="login-url">Website URL (HTTPS)</label><input id="login-url" type="url" bind:value={entry.form.url} required />
  {:else}
    <label for="credential-hosts">Allowed hosts</label><input id="credential-hosts" class="mono" bind:value={entry.form.hosts} aria-invalid={entry.form.hosts.length > 0 && !meaningfulHosts(entry.form.hosts)} />
    {#if entry.form.type === "custom_header"}<label for="header-name">Header name</label><input id="header-name" bind:value={entry.form.header_name} required />{/if}
    {#if entry.form.type === "query_param"}<label for="param-name">Parameter name</label><input id="param-name" bind:value={entry.form.param_name} required />{/if}
    {#if entry.mode === "ovh_api"}
      <label for="application-key">Application key</label><input id="application-key" type={entry.revealSecret ? "text" : "password"} bind:value={entry.form.application_key} autocomplete="off" required />
      <label for="application-secret">Application secret</label><input id="application-secret" type={entry.revealSecret ? "text" : "password"} bind:value={entry.form.application_secret} autocomplete="off" required />
      <label for="consumer-key">Consumer key</label><input id="consumer-key" type={entry.revealSecret ? "text" : "password"} bind:value={entry.form.consumer_key} autocomplete="off" required />
    {:else}
      <label for="credential-secret">Secret</label><div class="password-input"><input id="credential-secret" type={entry.revealSecret ? "text" : "password"} bind:value={entry.form.value} autocomplete="off" required /><button type="button" class="icon-button reveal" aria-label={entry.revealSecret ? "Hide secret" : "Show secret"} aria-pressed={entry.revealSecret} onclick={() => (entry.revealSecret = !entry.revealSecret)}><Icon name="eye" /></button></div>
    {/if}
  {/if}
  <label class="check destination"><input type="checkbox" bind:checked={entry.destinationConfirmed} />Save to {entry.form.project || "selected project"} / {entry.form.partition || "selected partition"}</label>
  <div class="actions"><button type="button" disabled={busy} onclick={() => navigate("intake")}>Cancel</button><button class="primary" type="submit" disabled={busy}>{entry.mode === "website_login" ? "Generate and save" : "Save"}</button></div>
</form>
<datalist id="partitions">{#each entry.partitions as item}<option value={item.name}></option>{/each}</datalist>
