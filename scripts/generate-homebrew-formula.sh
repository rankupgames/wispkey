#!/usr/bin/env bash
# Fill packaging/homebrew/wispkey.rb.tmpl with a version, base URL, and SHA-256 digests.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: generate-homebrew-formula.sh --version VERSION --base-url URL --out PATH \
  --sha-aarch64-apple-darwin SHA --sha-x86_64-apple-darwin SHA \
  --sha-aarch64-unknown-linux-gnu SHA --sha-x86_64-unknown-linux-gnu SHA
EOF
  exit 2
}

is_sha256() {
  [[ "$1" =~ ^[0-9a-fA-F]{64}$ ]]
}

version=""
base_url=""
out=""
sha_aarch64_apple_darwin=""
sha_x86_64_apple_darwin=""
sha_aarch64_unknown_linux_gnu=""
sha_x86_64_unknown_linux_gnu=""
template=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="${2:-}"; shift 2 ;;
    --base-url) base_url="${2:-}"; shift 2 ;;
    --out) out="${2:-}"; shift 2 ;;
    --template) template="${2:-}"; shift 2 ;;
    --sha-aarch64-apple-darwin) sha_aarch64_apple_darwin="${2:-}"; shift 2 ;;
    --sha-x86_64-apple-darwin) sha_x86_64_apple_darwin="${2:-}"; shift 2 ;;
    --sha-aarch64-unknown-linux-gnu) sha_aarch64_unknown_linux_gnu="${2:-}"; shift 2 ;;
    --sha-x86_64-unknown-linux-gnu) sha_x86_64_unknown_linux_gnu="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      ;;
  esac
done

if [[ -z "$version" || -z "$base_url" || -z "$out" \
  || -z "$sha_aarch64_apple_darwin" || -z "$sha_x86_64_apple_darwin" \
  || -z "$sha_aarch64_unknown_linux_gnu" || -z "$sha_x86_64_unknown_linux_gnu" ]]; then
  echo "missing required argument" >&2
  usage
fi

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-].*)?$ ]]; then
  echo "invalid version: $version" >&2
  exit 1
fi

base_url="${base_url%/}"

for digest in \
  "$sha_aarch64_apple_darwin" \
  "$sha_x86_64_apple_darwin" \
  "$sha_aarch64_unknown_linux_gnu" \
  "$sha_x86_64_unknown_linux_gnu"
do
  if ! is_sha256 "$digest"; then
    echo "invalid SHA-256 digest: $digest" >&2
    exit 1
  fi
done

if [[ -z "$template" ]]; then
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  repo_root="$(cd "$script_dir/.." && pwd)"
  template="$repo_root/packaging/homebrew/wispkey.rb.tmpl"
fi

if [[ ! -f "$template" ]]; then
  echo "template not found: $template" >&2
  exit 1
fi

content="$(cat "$template")"
content="${content//'{{VERSION}}'/$version}"
content="${content//'{{BASE_URL}}'/$base_url}"
content="${content//'{{SHA_AARCH64_APPLE_DARWIN}}'/$sha_aarch64_apple_darwin}"
content="${content//'{{SHA_X86_64_APPLE_DARWIN}}'/$sha_x86_64_apple_darwin}"
content="${content//'{{SHA_AARCH64_UNKNOWN_LINUX_GNU}}'/$sha_aarch64_unknown_linux_gnu}"
content="${content//'{{SHA_X86_64_UNKNOWN_LINUX_GNU}}'/$sha_x86_64_unknown_linux_gnu}"

if [[ "$content" == *'{{'* ]]; then
  echo "unreplaced template placeholders remain" >&2
  exit 1
fi

mkdir -p "$(dirname "$out")"
printf '%s\n' "$content" > "$out"
echo "$out"
