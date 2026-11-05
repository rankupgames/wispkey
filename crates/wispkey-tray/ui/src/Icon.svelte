<script>
  let { name, size = 16 } = $props();
</script>

<svg width={size} height={size} viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
  {#if name === "menu"}<path d="M3 5.5h14M3 10h14M3 14.5h14" />
  {:else if name === "key"}<circle cx="6" cy="9" r="3.5" /><path d="M9.5 9H17M14 9v3" />
  {:else if name === "lock" || name === "unlock"}<rect x="4" y="9" width="12" height="8" rx="2" />{#if name === "lock"}<path d="M7 9V6a3 3 0 016 0v3" />{:else}<path d="M7 9V6a3 3 0 015.5-1.5" />{/if}
  {:else if name === "settings"}<path d="M8 2h4l.5 2 2 .9 2-.6 2 3.4-1.5 1.5v2l1.5 1.5-2 3.4-2-.6-2 .9-.5 2H8l-.5-2-2-.9-2 .6-2-3.4L3 11.2v-2L1.5 7.7l2-3.4 2 .6 2-.9z" /><circle cx="10" cy="10" r="3" />
  {:else if name === "eye"}<path d="M2 10s3-5 8-5 8 5 8 5-3 5-8 5-8-5-8-5z" /><circle cx="10" cy="10" r="2.5" />
  {:else if name === "download"}<path d="M10 3v10M6 9l4 4 4-4M4 16h12" />
  {:else if name === "clipboard"}<rect x="5" y="4" width="10" height="13" rx="2" /><path d="M8 4V2.5h4V4M8 9h4M8 12h3" />
  {:else if name === "folder"}<path d="M2 6a2 2 0 012-2h4l2 2h6a2 2 0 012 2v7a2 2 0 01-2 2H4a2 2 0 01-2-2z" />
  {:else if name === "plus"}<path d="M10 3v14M3 10h14" />
  {:else if name === "back"}<path d="M12 4l-6 6 6 6" />
  {:else if name === "check"}<path d="M4 10l4 4L16 6" />
  {:else if name === "alert"}<path d="M10 2L1.5 17h17zM10 7v4M10 14v.1" />
  {:else if name === "close"}<path d="M5 5l10 10M15 5L5 15" />
  {:else if name === "copy"}<rect x="7" y="7" width="10" height="10" rx="2" /><path d="M13 7V3H3v10h4" />
  {:else if name === "refresh"}<path d="M17 8a7 7 0 10-.5 6M17 3v5h-5" />
  {:else if name === "trash"}<path d="M3 5h14M7 5V2h6v3M5 5l1 13h8l1-13M8 8v7M12 8v7" />
  {/if}
</svg>
