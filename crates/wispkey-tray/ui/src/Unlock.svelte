<script>
  import Icon from "./Icon.svelte";
  let { vault, fields, message, busy, unlockVault } = $props();
</script>

<form class="vault-form" onsubmit={unlockVault}>
  <label for="master-password">Master password</label>
  <div class="password-input" class:invalid={!!message}>
    <input id="master-password" type={fields.revealPassword ? "text" : "password"} bind:value={fields.password} autocomplete={vault.initialized ? "current-password" : "new-password"} required disabled={busy} />
    <button type="button" class="icon-button reveal" aria-label={fields.revealPassword ? "Hide password" : "Show password"} aria-pressed={fields.revealPassword} onclick={() => (fields.revealPassword = !fields.revealPassword)}><Icon name="eye" /></button>
    {#if vault.initialized}<button class="primary inline-unlock" type="submit" disabled={busy}>Unlock</button>{/if}
  </div>
  {#if message}<p class="error-text" role="alert">{message}</p>{/if}
  {#if !vault.initialized}
    <label for="confirm-password">Confirm password</label><input id="confirm-password" type="password" bind:value={fields.confirmation} autocomplete="new-password" required disabled={busy} />
    <p class="muted">A lost master password cannot be reset.</p>
    <button class="primary" type="submit" disabled={busy}>Create vault</button>
  {:else}
    <label class="check remember"><input type="checkbox" bind:checked={fields.remember} disabled={busy} />Remember this device</label>
  {/if}
</form>
