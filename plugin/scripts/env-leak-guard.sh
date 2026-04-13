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
  allow
fi

ONE_LINE="${HOOK_INPUT//$'\n'/}"
ONE_LINE="${ONE_LINE//$'\r'/}"

COMMAND=""
rest="${ONE_LINE#*\"command\"}"
if [ "$rest" != "$ONE_LINE" ]; then
  rest="${rest#*:}"
  rest="${rest#*\"}"
  COMMAND="${rest%%\"*}"
fi

if [ -z "$COMMAND" ]; then
  allow
fi

# Detect echo/printf/cat of secret env vars.
if echo "$COMMAND" | grep -qE '(echo|printf)\s+.*\$\{?(OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|STRIPE_SECRET_KEY|DATABASE_URL|DISCORD_TOKEN|SLACK_TOKEN)'; then
  deny \
    "WispKey blocked: command would print a secret environment variable." \
    "beforeShellExecution blocked this command because it would print a secret environment variable to stdout, exposing it in the conversation. Use WispKey to manage secrets safely. Run 'wispkey list' to see stored credentials, or use wisp tokens through the proxy instead of raw env vars."
fi

# Detect export of new secret values (not wisp tokens).
if echo "$COMMAND" | grep -qE 'export\s+(OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|STRIPE_SECRET_KEY|DATABASE_URL|DISCORD_TOKEN|SLACK_TOKEN)=' ; then
  if echo "$COMMAND" | grep -qE '=wk_[a-z0-9_]+'; then
    allow
  fi
  deny \
    "WispKey blocked: setting a secret env var directly. Use 'wispkey add' instead." \
    "beforeShellExecution blocked this export because it sets a secret environment variable with a real value. Store it in WispKey instead: run 'wispkey add <name> --type bearer_token --value <secret>' and use the wisp token."
fi

allow
