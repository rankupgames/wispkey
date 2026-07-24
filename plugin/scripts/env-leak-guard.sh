#!/bin/bash

# WispKey beforeShellExecution hook: env-leak-guard
# Detects commands that would echo/print/export secrets from env vars.
# Returns JSON only on stdout.

allow() {
  printf '%s\n' '{"permission":"allow"}'
  exit 0
}

deny() {
  local user_message="$1"
  local agent_message="$2"
  printf '%s\n' "{\"permission\":\"deny\",\"user_message\":\"${user_message}\",\"agent_message\":\"${agent_message}\"}"
  exit 0
}

HOOK_INPUT="$(cat)"
if [ -z "$HOOK_INPUT" ]; then
  deny \
    "WispKey blocked: shell hook input was empty." \
    "beforeShellExecution could not inspect an empty hook payload, so it failed closed."
fi

if ! printf '%s' "$HOOK_INPUT" | grep -qE '"command"[[:space:]]*:'; then
  deny \
    "WispKey blocked: shell hook command could not be parsed." \
    "beforeShellExecution did not receive a command field, so it failed closed."
fi

# Scan the full serialized payload. Secret-variable names and values are unchanged
# by JSON string escaping, while slicing raw JSON at quotes truncates normal commands.
COMMAND="${HOOK_INPUT//$'\n'/}"
COMMAND="${COMMAND//$'\r'/}"

# Detect echo/printf/cat of secret env vars.
if printf '%s' "$COMMAND" | grep -qE '(echo|printf)[[:space:]]+.*\$\{?(OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|STRIPE_SECRET_KEY|DATABASE_URL|DISCORD_TOKEN|SLACK_TOKEN)'; then
  deny \
    "WispKey blocked: command would print a secret environment variable." \
    "beforeShellExecution blocked this command because it would print a secret environment variable to stdout, exposing it in the conversation. Use WispKey to manage secrets safely. Run 'wispkey list' to see stored credentials, or use wisp tokens through the proxy instead of raw env vars."
fi

# Detect export of new secret values. Remove only a safe wisp-token assignment
# for the same protected variable before checking whether an unsafe assignment remains.
for secret_name in OPENAI_API_KEY AWS_SECRET_ACCESS_KEY GITHUB_TOKEN STRIPE_SECRET_KEY DATABASE_URL DISCORD_TOKEN SLACK_TOKEN; do
  if printf '%s' "$COMMAND" | grep -qE "export[[:space:]]+${secret_name}="; then
    without_safe_exports="$(printf '%s' "$COMMAND" | sed -E "s/export[[:space:]]+${secret_name}=wk_[a-z0-9_]+//g")"
    if ! printf '%s' "$without_safe_exports" | grep -qE "export[[:space:]]+${secret_name}="; then
      continue
    fi
    deny \
      "WispKey blocked: setting a secret env var directly. Use 'wispkey add' instead." \
      "beforeShellExecution blocked this export because it sets a secret environment variable with a real value. Store it in WispKey instead: run 'wispkey add <name> --type bearer_token --value-file -' and use the wisp token."
  fi
done

allow
