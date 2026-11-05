<script>
  import Icon from "./Icon.svelte";
  import { meaningfulHosts } from "./hosts.js";
  let { intake, view, dragging, busy, navigate } = $props();
</script>

{#if view === "intake"}
  <div class="dropzone" class:dragging>
    <button class="drop-target" aria-label="Choose files to import" disabled={busy} onclick={() => intake.chooseSource(false)}><span class="drop-icon"><Icon name="download" size={20} /></span><strong>{dragging ? "Release to scan files" : "Drop secrets or config files"}</strong><span class="muted">.env, JSON or key files</span></button>
    <div class="intake-actions">
      <button disabled={busy} onclick={() => intake.previewImport({}, "clipboard_import")}><Icon name="clipboard" size={14} />Clipboard import</button>
      <button disabled={busy} onclick={() => intake.chooseSource(true)}><Icon name="folder" size={14} />Import project</button>
      <button disabled={busy} onclick={() => navigate("add")}><Icon name="plus" size={14} />Add credential</button>
    </div>
  </div>
{:else if view === "clipboard_name"}
  <form onsubmit={(event) => { event.preventDefault(); if (intake.clipboardName.trim()) void intake.previewImport({ name: intake.clipboardName.trim() }, "clipboard_import"); }}>
    <h1>Clipboard import</h1>
    <label for="clipboard-name">Name</label><input id="clipboard-name" class="mono" bind:value={intake.clipboardName} required />
    <div class="actions"><button type="button" onclick={() => navigate("intake")}>Cancel</button><button type="submit" class="primary" disabled={busy || !intake.clipboardName.trim()}>Import clipboard</button></div>
  </form>
{:else if view === "scanning"}
  <h1>Scanning local sources</h1><progress aria-label="Scanning local sources"></progress>
{:else if view === "review" && intake.plan}
  <form onsubmit={intake.commitImport}>
    <div class="title-row"><h1>Review import</h1><span class="muted">{intake.selectedItems.length} of {intake.importItems.length} selected</span></div>
    <div class="field-row"><div><label for="import-project">Project</label><input id="import-project" list="projects" bind:value={intake.project} oninput={() => (intake.destinationConfirmed = false)} onchange={intake.repreviewDestination} required /></div><div><label for="import-environment">Environment</label><input id="import-environment" list="partitions" bind:value={intake.environment} oninput={() => (intake.destinationConfirmed = false)} onchange={intake.repreviewDestination} required={!intake.mixedEnvironments} placeholder={intake.mixedEnvironments ? "From source files" : ""} /></div></div>
    <ul class="import-list">{#each intake.importItems as item (item.id)}<li class:conflict={item.conflict && item.selected}><div class="import-row"><input type="checkbox" aria-label={`Import ${item.key}`} bind:checked={item.selected} onchange={() => { intake.rewriteHttp = false; intake.destinationConfirmed = false; }} /><span class="mono grow">{item.key}</span><span class="muted source" title={`${item.environment} · ${item.source}`}>{item.environment} · {item.source}</span></div>{#if item.selected}{#if item.needs_hosts && item.conflict_status !== "scope_conflict"}<input id={`hosts-${item.id}`} class="mono" aria-label={`Allowed hosts for ${item.key}`} bind:value={item.hosts} placeholder="Allowed hosts" aria-invalid={(!item.conflict || item.action !== "keep") && !meaningfulHosts(item.hosts)} />{:else if item.hosts}<span class="mono muted">{item.hosts}</span>{/if}{#if item.conflict}<span class="error-text">{item.conflict_status === "scope_conflict" ? "Stored scope differs. Skip this item or change the destination." : "Stored value differs. Choose how to proceed."}</span><div class="segments" aria-label={`Conflict for ${item.key}`}>{#if item.conflict_status !== "scope_conflict"}<button type="button" class:active={item.action === "keep"} onclick={() => { item.action = "keep"; intake.rewriteHttp = false; }}>Keep stored</button><button type="button" class:active={item.action === "replace"} onclick={() => (item.action = "replace")}>Replace</button>{/if}<button type="button" class:active={item.action === "skip"} onclick={() => { item.action = "skip"; item.selected = false; intake.rewriteHttp = false; intake.destinationConfirmed = false; }}>Skip</button></div>{/if}{/if}</li>{/each}</ul>
    {#each intake.plan.warnings || [] as warning}<p class="warning">{warning.source ? `${warning.source}: ` : ""}{warning.message}</p>{/each}
    <span class="field-label">Source files</span><div class="segments"><button type="button" class:active={!intake.rewriteHttp} aria-pressed={!intake.rewriteHttp} onclick={() => (intake.rewriteHttp = false)}>Store only</button><button type="button" class:active={intake.rewriteHttp} aria-pressed={intake.rewriteHttp} disabled={!intake.canRewrite} onclick={() => (intake.rewriteHttp = true)}>Replace HTTP values with tokens</button></div>
    <label class="check destination"><input type="checkbox" bind:checked={intake.destinationConfirmed} />Save to {intake.project || "selected project"} / {intake.environment || (intake.mixedEnvironments ? "source environments" : "selected environment")}</label>
    <div class="actions"><span class="warning-text grow">{intake.unresolved.length ? `Resolve ${intake.unresolved.length} items to import` : ""}</span><button type="button" disabled={busy} onclick={() => navigate("intake")}>Cancel</button><button class="primary" type="submit" disabled={busy || !intake.destinationConfirmed || !intake.selectedItems.length || !!intake.unresolved.length}>Import {intake.selectedItems.length}</button></div>
  </form>
{:else if view === "import_done" && intake.outcome}
  <div class="completion"><span class:warning-icon={intake.outcome.sourceFailed || intake.outcome.files.some((file) => file.status === "failed")} class="completion-icon"><Icon name={intake.outcome.sourceFailed || intake.outcome.files.some((file) => file.status === "failed") ? "alert" : "check"} size={22} /></span><h1>{intake.outcome.imported} {intake.outcome.imported === 1 ? "credential" : "credentials"} stored</h1></div>
  <ul class="result-list">{#each intake.outcome.files as file}<li><span class="mono grow">{file.path}</span><span class:error-text={file.status === "failed"} class="muted">{file.status === "updated" ? "Tokens written" : file.status === "failed" ? "Not changed" : "Unchanged"}</span>{#if file.message}<p class="error-text">{file.message}</p>{/if}</li>{/each}</ul>
  {#if intake.outcome.sourceFailed || intake.outcome.files.some((file) => file.status === "failed")}<p class="warning">Credentials were saved. Review the source files before retrying.</p>{/if}
  <div class="actions"><button onclick={() => navigate("credentials")}>View in Credentials</button><button class="primary" onclick={() => navigate("intake")}>Done</button></div>
{/if}
<datalist id="partitions">{#each intake.partitions as item}<option value={item.name}></option>{/each}</datalist>
