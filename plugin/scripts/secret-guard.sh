#!/bin/bash

# WispKey beforeShellExecution hook: secret-guard
# Detects shell commands containing patterns that look like real secrets
# (API keys, tokens, passwords) and blocks execution, recommending wisp tokens.
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

# Skip if the command already uses wisp tokens (wk_ prefix) -- that's correct usage.
if echo "$COMMAND" | grep -qE 'wk_[a-z0-9_]+'; then
  allow
fi

# Detect real secret patterns in the command text.
LEAKED=""

# OpenAI API keys
if echo "$COMMAND" | grep -qE 'sk-[a-zA-Z0-9]{20,}'; then
  LEAKED="OpenAI API key (sk-...)"
fi

# GitHub PAT
if echo "$COMMAND" | grep -qE 'ghp_[a-zA-Z0-9]{36}'; then
  LEAKED="GitHub personal access token (ghp_...)"
fi

# GitHub App token
if echo "$COMMAND" | grep -qE 'ghs_[a-zA-Z0-9]{36}'; then
  LEAKED="GitHub app token (ghs_...)"
fi

# AWS access key
if echo "$COMMAND" | grep -qE 'AKIA[A-Z0-9]{16}'; then
  LEAKED="AWS access key (AKIA...)"
fi

# Slack tokens
if echo "$COMMAND" | grep -qE 'xox[bp]-[0-9]+-'; then
  LEAKED="Slack token (xox...)"
fi

# Stripe keys
if echo "$COMMAND" | grep -qE 'sk_(test|live)_[a-zA-Z0-9]{24,}'; then
  LEAKED="Stripe secret key (sk_...)"
fi

# Generic Bearer token with long value
if echo "$COMMAND" | grep -qE 'Bearer [a-zA-Z0-9._-]{40,}'; then
  LEAKED="Bearer token (40+ chars)"
fi

# Generic long hex/base64 secret after common flags
if echo "$COMMAND" | grep -qE '(-H|--header|Authorization:|X-API-Key:)\s*['\''"]?[a-zA-Z0-9+/=._-]{40,}'; then
  if [ -z "$LEAKED" ]; then
    LEAKED="possible secret in HTTP header (40+ char value)"
  fi
fi

if [ -n "$LEAKED" ]; then
  deny \
    "WispKey blocked: detected $LEAKED in shell command. Use a wisp token instead." \
    "beforeShellExecution blocked this command because it contains what appears to be a real secret ($LEAKED). Use WispKey wisp tokens instead of real credentials. Run 'wispkey list' to see available tokens, or 'wispkey get <name> --show-token' to get a specific wisp token. Route the request through the proxy (HTTP_PROXY=http://localhost:7700) and the real credential will be injected automatically."
fi

allow
